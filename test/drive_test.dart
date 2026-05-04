// Unit tests for drive.dart's mutating + listing operations.
//
// All tests pipe MockClient through the new {http.Client? client}
// param threaded through drive.dart and api.dart functions during
// this commit (mirrors the Phase 9.7.1 + B1 pattern).
//
// Coverage scope:
//   - Mutating ops (moveFile, renameFile, setFileTimestamp,
//     trashItems, deletePermanently, clearTrashAll): pin the
//     HTTP method + URL + body shape, plus the cache invalidation
//     order ("clear parent before mutation" — Phase 3 bug shape).
//   - Listing ops (listFolders, listFolderFiles): pin the cache
//     hit path (no HTTP), the cache miss path (paginated GET), and
//     the detailed=false projection.
//   - resolvePath: pin '/' fast-path and multi-segment resolution.
//   - getTrashContent: pin the dual-call shape + best-effort fault
//     tolerance.
//
// Out of scope: createFolderRecursive, search, findFiles, printTree,
// listFolderWithPaths — these are higher-level orchestrators with
// branching that's better exercised by the live suite.

import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import 'package:internxt_client/cache.dart';
import 'package:internxt_client/drive.dart';

const _api = 'https://drive.test';
const _tok = 'tok';

/// Helper: builds a MockClient that records every request and
/// dispatches based on (method, urlMatcher) → response handler.
MockClient _routingMock(
    List<({String method, bool Function(Uri) match, http.Response Function(http.Request) respond})>
        routes,
    {List<String>? recordedCalls}) {
  return MockClient((req) async {
    recordedCalls?.add('${req.method} ${req.url.path}');
    for (final r in routes) {
      if (r.method == req.method && r.match(req.url)) {
        return r.respond(req);
      }
    }
    throw StateError('unexpected request: ${req.method} ${req.url}');
  });
}

void main() {
  group('moveFile (Phase 6.a drive coverage)', () {
    test('PATCHes /files/{uuid} with destinationFolder; clears parent first', () async {
      final calls = <String>[];
      final folderCache = <String, CacheEntry>{};
      final fileCache = <String, CacheEntry>{};

      // Pre-populate the source parent's cache entry so we can
      // assert it gets invalidated.
      const srcParent = 'src-parent-uuid';
      const dstParent = 'dst-parent-uuid';
      const fileUuid = 'file-1';
      folderCache[srcParent] = CacheEntry(items: [{'name': 'placeholder'}], timestamp: DateTime.now());
      fileCache[srcParent] = CacheEntry(items: [{'name': 'placeholder'}], timestamp: DateTime.now());
      folderCache[dstParent] = CacheEntry(items: [{'name': 'pre-existing'}], timestamp: DateTime.now());

      final mock = _routingMock([
        // _clearParent fetches metadata to find the parent UUID
        (
          method: 'GET',
          match: (u) => u.path == '/files/$fileUuid/meta',
          respond: (_) => http.Response(jsonEncode({
            'folderUuid': srcParent,
          }), 200),
        ),
        // The actual PATCH
        (
          method: 'PATCH',
          match: (u) => u.path == '/files/$fileUuid',
          respond: (req) {
            expect(jsonDecode(req.body)['destinationFolder'], equals(dstParent));
            return http.Response('{"ok":true}', 200);
          },
        ),
      ], recordedCalls: calls);

      await moveFile(_api, _tok, folderCache, fileCache, fileUuid, dstParent,
          client: mock);

      expect(folderCache[srcParent], isNull,
          reason: 'src parent cache should be cleared');
      expect(fileCache[srcParent], isNull,
          reason: 'src parent file cache should be cleared');
      expect(folderCache[dstParent], isNull,
          reason: 'dst parent cache should also be invalidated');
      // Order: GET meta (for clearParent) BEFORE PATCH (the mutation)
      expect(calls.indexWhere((c) => c.contains('/meta')),
          lessThan(calls.indexWhere((c) => c.contains('PATCH'))));
    });
  });

  group('renameFile', () {
    test('PUTs /files/{uuid}/meta with plainName + type', () async {
      final folderCache = <String, CacheEntry>{};
      final fileCache = <String, CacheEntry>{};
      const fileUuid = 'file-2';
      const parentUuid = 'parent-2';

      final mock = _routingMock([
        (
          method: 'GET',
          match: (u) => u.path == '/files/$fileUuid/meta',
          respond: (_) => http.Response(
              jsonEncode({'folderUuid': parentUuid}), 200),
        ),
        (
          method: 'PUT',
          match: (u) => u.path == '/files/$fileUuid/meta',
          respond: (req) {
            final body = jsonDecode(req.body) as Map<String, dynamic>;
            expect(body['plainName'], equals('renamed'));
            expect(body['type'], equals('txt'));
            return http.Response('{"ok":true}', 200);
          },
        ),
      ]);

      await renameFile(
          _api, _tok, folderCache, fileCache, fileUuid, 'renamed', 'txt',
          client: mock);
    });

    test('null type → empty string in payload (matches monolith)', () async {
      final folderCache = <String, CacheEntry>{};
      final fileCache = <String, CacheEntry>{};

      final mock = _routingMock([
        (
          method: 'GET',
          match: (u) => u.path == '/files/x/meta',
          respond: (_) => http.Response('{"folderUuid":"p"}', 200),
        ),
        (
          method: 'PUT',
          match: (u) => u.path == '/files/x/meta',
          respond: (req) {
            expect(jsonDecode(req.body)['type'], equals(''));
            return http.Response('{}', 200);
          },
        ),
      ]);

      await renameFile(_api, _tok, folderCache, fileCache, 'x', 'no-ext', null,
          client: mock);
    });
  });

  group('setFileTimestamp (Phase 9.6 contract)', () {
    test('echoes plainName + type from current meta + sends modificationTime', () async {
      final folderCache = <String, CacheEntry>{};
      final fileCache = <String, CacheEntry>{};
      final ts = DateTime.utc(2024, 6, 1, 12, 30);
      const fileUuid = 'file-ts';

      // setFileTimestamp does GET meta TWICE: once to read current
      // plainName/type, once inside _clearParent to find the parent.
      final mock = _routingMock([
        (
          method: 'GET',
          match: (u) => u.path == '/files/$fileUuid/meta',
          respond: (_) => http.Response(
              jsonEncode({
                'plainName': 'doc',
                'type': 'pdf',
                'folderUuid': 'parent',
              }),
              200),
        ),
        (
          method: 'PUT',
          match: (u) => u.path == '/files/$fileUuid/meta',
          respond: (req) {
            final body = jsonDecode(req.body) as Map<String, dynamic>;
            expect(body['plainName'], equals('doc'),
                reason: 'must echo current plainName');
            expect(body['type'], equals('pdf'),
                reason: 'must echo current type');
            expect(body['modificationTime'], equals(ts.toIso8601String()));
            return http.Response('{}', 200);
          },
        ),
      ]);

      await setFileTimestamp(_api, _tok, folderCache, fileCache, fileUuid, ts,
          client: mock);
    });
  });

  group('trashItems', () {
    test('POSTs /storage/trash/add with items array', () async {
      final folderCache = <String, CacheEntry>{};
      final fileCache = <String, CacheEntry>{};
      const fileUuid = 'trash-file';

      final mock = _routingMock([
        (
          method: 'GET',
          match: (u) => u.path == '/files/$fileUuid/meta',
          respond: (_) => http.Response('{"folderUuid":"p"}', 200),
        ),
        (
          method: 'POST',
          match: (u) => u.path == '/storage/trash/add',
          respond: (req) {
            final body = jsonDecode(req.body) as Map<String, dynamic>;
            final items = body['items'] as List;
            expect(items, hasLength(1));
            final first = items.first as Map<String, dynamic>;
            expect(first['uuid'], equals(fileUuid));
            expect(first['type'], equals('file'));
            return http.Response('{"ok":true}', 200);
          },
        ),
      ]);

      await trashItems(_api, _tok, folderCache, fileCache, fileUuid, 'file',
          client: mock);
    });
  });

  group('deletePermanently', () {
    test('DELETEs /storage/trash with items array', () async {
      final mock = _routingMock([
        (
          method: 'DELETE',
          match: (u) => u.path == '/storage/trash',
          respond: (req) {
            final body = jsonDecode(req.body) as Map<String, dynamic>;
            expect(body['items'], hasLength(1));
            return http.Response('{}', 200);
          },
        ),
      ]);

      await deletePermanently(_api, _tok, 'uuid-d', 'file', client: mock);
    });
  });

  group('clearTrashAll', () {
    test('DELETEs /storage/trash/all', () async {
      var hit = false;
      final mock = _routingMock([
        (
          method: 'DELETE',
          match: (u) => u.path == '/storage/trash/all',
          respond: (_) {
            hit = true;
            return http.Response('{}', 200);
          },
        ),
      ]);
      await clearTrashAll(_api, _tok, client: mock);
      expect(hit, isTrue);
    });
  });

  group('getTrashContent', () {
    test('makes 2 GETs (files + folders) and merges results', () async {
      final mock = _routingMock([
        (
          method: 'GET',
          match: (u) =>
              u.path == '/storage/trash/paginated' &&
              u.queryParameters['type'] == 'files',
          respond: (_) => http.Response(
              jsonEncode({
                'result': [
                  {'plainName': 'a', 'type': 'txt', 'uuid': 'u1', 'size': 10},
                ]
              }),
              200),
        ),
        (
          method: 'GET',
          match: (u) =>
              u.path == '/storage/trash/paginated' &&
              u.queryParameters['type'] == 'folders',
          respond: (_) => http.Response(
              jsonEncode({
                'result': [
                  {'plainName': 'sub', 'uuid': 'f1'},
                ]
              }),
              200),
        ),
      ]);

      final items = await getTrashContent(_api, _tok, client: mock);
      expect(items, hasLength(2));
      expect(items.first['type'], equals('file'));
      expect(items.first['name'], equals('a'));
      expect(items.last['type'], equals('folder'));
      expect(items.last['name'], equals('sub'));
    });

    test('best-effort: files-branch failure returns just folders', () async {
      final mock = _routingMock([
        (
          method: 'GET',
          match: (u) => u.queryParameters['type'] == 'files',
          respond: (_) => http.Response('boom', 500),
        ),
        (
          method: 'GET',
          match: (u) => u.queryParameters['type'] == 'folders',
          respond: (_) => http.Response(
              jsonEncode({'result': [{'plainName': 'F', 'uuid': 'fx'}]}), 200),
        ),
      ]);

      final items = await getTrashContent(_api, _tok, client: mock);
      expect(items, hasLength(1));
      expect(items.first['type'], equals('folder'));
    });
  });

  group('listFolders cache + pagination', () {
    test('cache hit within TTL returns without HTTP', () async {
      final folderCache = <String, CacheEntry>{
        'fid': CacheEntry(
          items: [{'type': 'folder', 'name': 'cached'}],
          timestamp: DateTime.now(),
        ),
      };
      final mock = MockClient((req) async {
        fail('unexpected HTTP call: $req');
      });

      final result =
          await listFolders(_api, _tok, folderCache, 'fid', client: mock);
      expect(result, hasLength(1));
      expect(result.first['name'], equals('cached'));
    });

    test('cache miss: paginates and caches the full list', () async {
      // Two pages: 50 folders then 3 (signals end of pagination).
      var page = 0;
      final mock = MockClient((req) async {
        expect(req.method, equals('GET'));
        expect(req.url.path, equals('/folders/content/fid/folders'));
        page++;
        final folders = page == 1
            ? List.generate(50, (i) => {'plainName': 'f$i', 'uuid': 'u$i'})
            : List.generate(3, (i) => {'plainName': 'tail$i', 'uuid': 'tu$i'});
        return http.Response(jsonEncode({'result': folders}), 200);
      });

      final folderCache = <String, CacheEntry>{};
      final result = await listFolders(_api, _tok, folderCache, 'fid', client: mock);

      expect(result, hasLength(53));
      expect(folderCache['fid'], isNotNull,
          reason: 'should cache the result');
      expect(page, equals(2), reason: 'should stop paginating at < limit');
    });

    test('detailed=false strips down to subset', () async {
      final folderCache = <String, CacheEntry>{};
      final mock = MockClient((req) async => http.Response(
          jsonEncode({
            'result': [
              {
                'plainName': 'f',
                'uuid': 'u',
                'createdAt': '2024-01-01',
                'parentUuid': 'p',
              }
            ]
          }),
          200));

      final result = await listFolders(_api, _tok, folderCache, 'fid',
          client: mock, detailed: false);
      expect(result.first.keys, equals({'type', 'name', 'uuid', 'size'}));
    });
  });

  group('resolvePath', () {
    test('"/" returns root immediately, no HTTP', () async {
      final mock = MockClient((req) async => fail('no HTTP expected: $req'));
      final r = await resolvePath(
          _api, _tok, 'root-uuid', {}, {}, '/', client: mock);
      expect(r['type'], equals('folder'));
      expect(r['uuid'], equals('root-uuid'));
    });

    test('throws when rootFolderId is null', () async {
      await expectLater(
        () => resolvePath(_api, _tok, null, {}, {}, '/Foo'),
        throwsA(predicate((e) => e.toString().contains('Root folder'))),
      );
    });

    test('multi-segment: /Foo/bar.txt resolves via 2 listings', () async {
      final folderCache = <String, CacheEntry>{};
      final fileCache = <String, CacheEntry>{};
      final mock = MockClient((req) async {
        if (req.url.path == '/folders/content/root/folders') {
          return http.Response(
              jsonEncode({
                'result': [
                  {'plainName': 'Foo', 'uuid': 'foo-uuid'}
                ]
              }),
              200);
        }
        // After descending into /Foo:
        if (req.url.path == '/folders/content/foo-uuid/folders') {
          return http.Response(jsonEncode({'result': []}), 200);
        }
        if (req.url.path == '/folders/content/foo-uuid/files') {
          return http.Response(
              jsonEncode({
                'result': [
                  {'plainName': 'bar', 'type': 'txt', 'uuid': 'bar-uuid'}
                ]
              }),
              200);
        }
        fail('unexpected ${req.url.path}');
      });

      final r = await resolvePath(
          _api, _tok, 'root', folderCache, fileCache, '/Foo/bar.txt',
          client: mock);
      expect(r['type'], equals('file'));
      expect(r['uuid'], equals('bar-uuid'));
      expect(r['path'], equals('/Foo/bar.txt'));
    });

    test('throws "Path not found" when segment missing', () async {
      final mock = MockClient((req) async => http.Response(
          jsonEncode({'result': []}), 200));
      await expectLater(
        () => resolvePath(_api, _tok, 'root', {}, {}, '/Missing', client: mock),
        throwsA(predicate((e) => e.toString().contains('not found'))),
      );
    });
  });
}
