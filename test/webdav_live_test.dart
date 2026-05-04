// Live WebDAV reliability test rig (Phase 7.10).
//
// Spins up the actual WebDAV server (shelf_dav over the
// InternxtFileSystem) on a free local port, then drives it with
// raw HTTP requests for the core methods: OPTIONS, PUT, GET,
// DELETE, MOVE. Verifies bytes round-trip end-to-end through the
// WebDAV layer onto the real Internxt backend.
//
// Same opt-in / sentinel safety properties as
// test/live_smoke_test.dart: auto-skipped without IXT_ACCOUNT +
// IXT_PWD; all server-side resources land under
// /__test_inxt_dart_smoke_webdav__/<run-uuid>/ and are trashed on
// teardown.
//
// To run:
//     dart test test/webdav_live_test.dart
//
// To force-skip:
//     DART_TEST_SKIP_LIVE=1 dart test test/webdav_live_test.dart

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_dav/shelf_dav.dart';
import 'package:test/test.dart';

import '../cli.dart';
import '../webdav_filesystem.dart';

// ---------- credential loading (mirror of live_smoke_test.dart) ----------

final Map<String, String> _envOverrides = {};

void _loadDotEnvIfPresent() {
  final candidates = [
    File('${Directory.current.path}/.env'),
    File('.env'),
  ];
  for (final f in candidates) {
    if (f.existsSync()) {
      for (final line in f.readAsLinesSync()) {
        final trimmed = line.trim();
        if (trimmed.isEmpty ||
            trimmed.startsWith('#') ||
            !trimmed.contains('=')) {
          continue;
        }
        final eq = trimmed.indexOf('=');
        final k = trimmed.substring(0, eq).trim();
        final v = trimmed
            .substring(eq + 1)
            .trim()
            .replaceAll('"', '')
            .replaceAll("'", '');
        _envOverrides[k] = v;
      }
      return;
    }
  }
}

String? _env(String key) => _envOverrides[key] ?? Platform.environment[key];

// ---------- helpers ----------

String _uniqueName(String stem) {
  final rng = Random.secure();
  final hex = List.generate(
          6, (_) => rng.nextInt(256).toRadixString(16).padLeft(2, '0'))
      .join();
  return '$stem-$hex';
}

const _webdavUser = 'internxt';
const _webdavPass = 'internxt-webdav';

String _basicAuth() {
  final raw = base64Encode(utf8.encode('$_webdavUser:$_webdavPass'));
  return 'Basic $raw';
}

/// Send a single request through a fresh client + close it, so
/// connection-pool reuse across tests can't leak a half-closed
/// keepalive.
Future<http.Response> _sendOnce(http.BaseRequest request) async {
  final client = http.Client();
  try {
    final streamed = await client.send(request);
    return await http.Response.fromStream(streamed);
  } finally {
    client.close();
  }
}

void main() {
  _loadDotEnvIfPresent();
  final email = _env('IXT_ACCOUNT');
  final password = _env('IXT_PWD');
  final skipLive = _env('DART_TEST_SKIP_LIVE') == '1';

  final skipReason = skipLive
      ? 'DART_TEST_SKIP_LIVE=1 set'
      : (email == null || password == null
          ? 'IXT_ACCOUNT and IXT_PWD not set in env (or .env)'
          : null);

  if (skipReason != null) {
    test('webdav live (skipped: $skipReason)', () {}, skip: skipReason);
    return;
  }

  late ConfigService config;
  late InternxtClient client;
  late HttpServer server;
  late String sentinelPath;
  late String sentinelUuid;
  late String baseUrl;

  setUpAll(() async {
    print('\n🔑 LIVE-WEBDAV: Logging in as $email...');
    final cfgDir =
        Directory.systemTemp.createTempSync('inxt-dart-livewebdavcfg-');
    config = ConfigService(dataDir: cfgDir.path);
    client = InternxtClient(config: config);
    final loginResult = await client.login(email!, password!);
    await config.saveCredentials(loginResult);
    client.setAuth(loginResult);

    // Sentinel folder for this run.
    final runId = _uniqueName('run').substring(4);
    sentinelPath = '/__test_inxt_dart_smoke_webdav__/$runId';
    final folderInfo = await client.createFolderRecursive(sentinelPath);
    sentinelUuid = folderInfo['uuid'] as String;
    print('📁 LIVE-WEBDAV: Sentinel $sentinelPath uuid=$sentinelUuid');

    // Spawn the WebDAV server on a free local port (127.0.0.1 only).
    final fs = InternxtFileSystem(client: client);
    final davConfig = DAVConfig(
      root: fs.directory('/'),
      prefix: '/',
      authenticationProvider: BasicAuthenticationProvider.plaintext(
        realm: 'Internxt WebDAV',
        users: {_webdavUser: _webdavPass},
      ),
      authorizationProvider: RoleBasedAuthorizationProvider(
        readWriteUsers: {_webdavUser},
        allowAnonymousRead: false,
      ),
      enableLocking: true,
    );
    final dav = ShelfDAV.withConfig(davConfig);
    server = await shelf_io.serve(dav.handler, '127.0.0.1', 0);
    baseUrl = 'http://127.0.0.1:${server.port}';
    print('🌐 LIVE-WEBDAV: Server listening on $baseUrl');
  });

  tearDownAll(() async {
    print('\n🧹 LIVE-WEBDAV: Stopping server + cleaning up sentinel');
    try {
      await server.close(force: true);
    } catch (_) {}
    try {
      await client.trashItems(sentinelUuid, 'folder');
      print('✅ LIVE-WEBDAV: Sentinel trashed');
    } catch (e) {
      print('⚠️  LIVE-WEBDAV: Cleanup failed: $e');
    }
  });

  test('OPTIONS / returns DAV class headers + auth required', () async {
    // Without auth: 401 expected.
    final unauthed = await _sendOnce(http.Request('OPTIONS', Uri.parse(baseUrl)));
    expect(unauthed.statusCode, equals(401),
        reason:
            'OPTIONS without auth should be rejected (401), got ${unauthed.statusCode}');

    // With auth: 200 + DAV header advertising class 1 (and ideally 2).
    final authed = await _sendOnce(http.Request('OPTIONS', Uri.parse(baseUrl))
      ..headers['Authorization'] = _basicAuth());
    expect(authed.statusCode, anyOf(equals(200), equals(207)),
        reason: 'OPTIONS with auth should succeed (200 or 207)');
    final davHeader = authed.headers['dav'] ?? authed.headers['DAV'] ?? '';
    expect(davHeader, contains('1'),
        reason: 'DAV header should advertise class 1 compliance');
  });

  test('PUT + GET + DELETE round-trip via WebDAV', () async {
    // Choose a remote path under the sentinel.
    final filename = '${_uniqueName('webdav-rt')}.txt';
    final remotePath = '$sentinelPath/$filename';
    final url = Uri.parse('$baseUrl$remotePath');

    final payload = Uint8List.fromList(
        utf8.encode('webdav round-trip ${_uniqueName('payload').substring(0, 10)}'));

    // PUT
    final putResp = await _sendOnce(http.Request('PUT', url)
      ..headers['Authorization'] = _basicAuth()
      ..bodyBytes = payload);
    if (putResp.statusCode >= 400) {
      print('DEBUG: PUT body: ${putResp.body}');
    }
    expect(putResp.statusCode,
        anyOf(equals(200), equals(201), equals(204)),
        reason: 'PUT should succeed (got ${putResp.statusCode}): ${putResp.body}');

    // GET — bytes should match.
    final getResp = await _sendOnce(http.Request('GET', url)
      ..headers['Authorization'] = _basicAuth());
    expect(getResp.statusCode, equals(200));
    expect(getResp.bodyBytes, equals(payload),
        reason: 'GET bytes should match PUT bytes');

    // DELETE
    final delResp = await _sendOnce(http.Request('DELETE', url)
      ..headers['Authorization'] = _basicAuth());
    expect(delResp.statusCode,
        anyOf(equals(200), equals(204)),
        reason: 'DELETE should succeed (got ${delResp.statusCode})');

    // After DELETE, GET should 404.
    final gone = await _sendOnce(http.Request('GET', url)
      ..headers['Authorization'] = _basicAuth());
    expect(gone.statusCode, equals(404),
        reason: 'GET after DELETE should be 404');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('PUT-on-existing preserves UUID (Phase 8.5: updateFile path)',
      () async {
    final filename = '${_uniqueName('webdav-update')}.txt';
    final remotePath = '$sentinelPath/$filename';
    final url = Uri.parse('$baseUrl$remotePath');

    // First PUT — creates the file.
    final v1 =
        Uint8List.fromList(utf8.encode('first version ${DateTime.now()}'));
    final put1 = await _sendOnce(http.Request('PUT', url)
      ..headers['Authorization'] = _basicAuth()
      ..bodyBytes = v1);
    expect(put1.statusCode, anyOf(equals(200), equals(201), equals(204)),
        reason: 'first PUT should succeed (got ${put1.statusCode})');

    // Capture v1's UUID via the existing client (the WebDAV layer
    // doesn't expose UUIDs directly; resolvePath does).
    final v1Resolved = await client.resolvePath(remotePath);
    final v1Uuid = v1Resolved['uuid'] as String;

    // Second PUT — should hit the updateFile path. Same URL, new
    // bytes.
    final v2 =
        Uint8List.fromList(utf8.encode('second version ${DateTime.now()}'));
    final put2 = await _sendOnce(http.Request('PUT', url)
      ..headers['Authorization'] = _basicAuth()
      ..bodyBytes = v2);
    expect(put2.statusCode, anyOf(equals(200), equals(201), equals(204)),
        reason: 'second PUT should succeed (got ${put2.statusCode})');

    // UUID must be preserved.
    final v2Resolved = await client.resolvePath(remotePath);
    final v2Uuid = v2Resolved['uuid'] as String;
    expect(v2Uuid, equals(v1Uuid),
        reason:
            'PUT-on-existing should preserve UUID via updateFile path');

    // Bytes should be the new content.
    final getResp = await _sendOnce(http.Request('GET', url)
      ..headers['Authorization'] = _basicAuth());
    expect(getResp.statusCode, equals(200));
    expect(getResp.bodyBytes, equals(v2),
        reason: 'GET after replace-PUT should return v2 bytes');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('PROPFIND on sentinel folder returns its children', () async {
    // First PUT a couple of probe files so the listing has known
    // entries.
    final names = <String>[];
    for (var i = 0; i < 2; i++) {
      final f = '${_uniqueName('probe')}.txt';
      names.add(f);
      final url = Uri.parse('$baseUrl$sentinelPath/$f');
      await _sendOnce(http.Request('PUT', url)
        ..headers['Authorization'] = _basicAuth()
        ..bodyBytes = utf8.encode('probe $i'));
    }

    final url = Uri.parse('$baseUrl$sentinelPath');
    final resp = await _sendOnce(http.Request('PROPFIND', url)
      ..headers['Authorization'] = _basicAuth()
      ..headers['Depth'] = '1');
    expect(resp.statusCode, equals(207),
        reason: 'PROPFIND should return 207 Multi-Status');
    // Body is XML; just sanity-check both probe filenames appear.
    for (final n in names) {
      expect(resp.body, contains(n),
          reason: 'PROPFIND body should contain $n');
    }
  }, timeout: const Timeout(Duration(minutes: 2)));
}
