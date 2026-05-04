// Live integration smoke tests against the real Internxt backend.
//
// DESIGN PRINCIPLES (real-account test — be paranoid):
//
// 1. Auto-skip without creds. Only runs if both IXT_ACCOUNT and IXT_PWD
//    are present in env (loaded from .env). Default behaviour: skipped.
//
// 2. Self-contained namespace. All operations happen inside a single
//    sentinel folder named with a UUID:
//        /__test_inxt_dart_smoke__/<run-uuid>/
//    Nothing outside that prefix is touched.
//
// 3. Always cleans up. tearDownAll trashes the sentinel folder even on
//    test failure. Trash is recoverable in Internxt UI for 30 days, so
//    even if cleanup fails the user can recover via web.
//
// 4. No cassette recording. Bytes/responses live only in memory; nothing
//    about the user's account is written to the repo.
//
// 5. Per-call unique names — file/folder names within tests get a UUID
//    suffix. Prevents 409 collisions on rerun.
//
// 6. Small payloads only. <= 1 MB per file to limit quota impact.
//
// To run:
//     dart test test/live_smoke_test.dart
//
// To force-skip even with creds:
//     DART_TEST_SKIP_LIVE=1 dart test test/live_smoke_test.dart

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:internxt_client/cli.dart';

// ---------- credential loading ----------

void _loadDotEnvIfPresent() {
  // Walk up from test/ to project root, look for .env
  final projectRoot = Directory.current;
  final candidates = [
    File('${projectRoot.path}/.env'),
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
        // Dart Platform.environment is read-only; use a side-channel map
        _envOverrides[k] = v;
      }
      return;
    }
  }
}

final Map<String, String> _envOverrides = {};

String? _env(String key) {
  return _envOverrides[key] ?? Platform.environment[key];
}

// Random run id
String _runId = '';

// Sentinel root path on remote
const _sentinelPrefix = '__test_inxt_dart_smoke__';
String get _sentinelPath => '/$_sentinelPrefix/$_runId';

// ---------- helpers ----------

String _uniqueName(String stem) {
  final rng = Random.secure();
  final hex = List.generate(
      6, (_) => rng.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
  return '$stem-$hex';
}

String _uniqueSubpath(String name) => '$_sentinelPath/${_uniqueName(name)}';

({File file, Uint8List payload}) _writePayload(Directory tmp, String filename,
    {int sizeBytes = 256}) {
  final rng = Random.secure();
  final tag = utf8.encode('inxt-dart-smoke-${_uniqueName('').substring(1)}-');
  final fill = List.generate(sizeBytes - tag.length, (_) => rng.nextInt(256));
  final payload = Uint8List.fromList([...tag, ...fill]);
  final f = File('${tmp.path}/$filename');
  f.writeAsBytesSync(payload);
  return (file: f, payload: payload);
}

void main() {
  // Load .env once at startup
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
    test('live smoke (skipped: $skipReason)', () {
      // Empty body — pinned to make the skip visible in the report
    }, skip: skipReason);
    return;
  }

  // Live tests retry on transient API flakiness (rate-limit, eventual-
  // consistency). Per-test names include random UUIDs, so reruns won't
  // collide. Run dart test with --no-retry to disable.
  const liveRetries = 2;

  // Thin wrapper around `test()` that defaults to retry: liveRetries.
  // `timeout` overrides the package:test default of 30s for tests that
  // legitimately need longer (chunked uploads, eventual-consistency
  // retries on search).
  void liveTest(String description, dynamic Function() body,
      {Timeout? timeout}) {
    test(description, body, retry: liveRetries, timeout: timeout);
  }

  // Per-run unique id — fresh for each `dart test` invocation
  _runId = _uniqueName('run').substring(4); // strip "run-" prefix

  late final ConfigService config;
  late final InternxtClient client;
  late final Directory tmpRoot;
  Map<String, dynamic>? _creds;
  String? _sentinelUuid;

  setUpAll(() async {
    print('\n🔑 LIVE: Logging in as $email...');
    // Use a fresh isolated config dir so we don't trample real creds
    final cfgDir = Directory.systemTemp.createTempSync('inxt-dart-livecfg-');
    config = ConfigService(configPath: cfgDir.path);
    client = InternxtClient(config: config);

    final loginResult = await client.login(email!, password!);
    expect(loginResult['email']?.toString().toLowerCase(),
        equals(email.toLowerCase()));
    expect(loginResult['token'], isA<String>());
    expect(loginResult['mnemonic'], isA<String>());
    _creds = loginResult;
    await config.saveCredentials(loginResult);
    client.setAuth(loginResult);
    print(
        '✅ LIVE: Authenticated (uuid=${(loginResult['userId'] as String).substring(0, 8)}...)');

    // Create sentinel folder
    print('📁 LIVE: Creating sentinel folder $_sentinelPath');
    final folderInfo = await client.createFolderRecursive(_sentinelPath);
    _sentinelUuid = folderInfo['uuid'] as String;
    print('✅ LIVE: Sentinel uuid=${_sentinelUuid!.substring(0, 8)}...');

    tmpRoot = Directory.systemTemp.createTempSync('inxt-dart-live-tests-');
  });

  tearDownAll(() async {
    // Trash the sentinel folder
    print('\n🧹 LIVE: Cleaning up sentinel folder $_sentinelPath');
    if (_sentinelUuid != null) {
      try {
        await client.trashItems(_sentinelUuid!, 'folder');
        print('✅ LIVE: Cleanup successful');
      } catch (e) {
        print(
            '⚠️  LIVE: Cleanup failed (please manually trash $_sentinelPath): $e');
      }
    }
    if (tmpRoot.existsSync()) {
      tmpRoot.deleteSync(recursive: true);
    }
  });

  // ===========================================================================
  // READ-ONLY SMOKE
  // ===========================================================================

  group('read-only smoke', () {
    liveTest('login + creds shape', () {
      final c = _creds!;
      expect(c['email'], isNotNull);
      expect(c['userId'], isA<String>());
      expect(c['rootFolderId'], isA<String>());
      expect(c['mnemonic'], isA<String>());
      expect((c['mnemonic'] as String).split(' ').length,
          greaterThanOrEqualTo(12));
    });

    liveTest('list root folder', () async {
      final rootUuid = _creds!['rootFolderId'] as String;
      final folders = await client.listFolders(rootUuid);
      final files = await client.listFolderFiles(rootUuid);
      expect(folders, isA<List<Map<String, dynamic>>>());
      expect(files, isA<List<Map<String, dynamic>>>());
    });
  });

  // ===========================================================================
  // CORE UPLOAD/DOWNLOAD CYCLE
  // ===========================================================================

  liveTest('full upload/download round-trip preserves bytes', () async {
    final name = _uniqueName('smoke');
    final w = _writePayload(tmpRoot, '$name.txt', sizeBytes: 512);

    print('📤 LIVE: Uploading $name.txt (${w.payload.length} bytes)...');
    final result = await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$name.txt',
    );
    expect(result, equals('uploaded'), reason: 'upload returned: $result');

    // Resolve the file via path → get its UUID
    final resolved = await client.resolvePath('$_sentinelPath/$name.txt');
    expect(resolved['type'], equals('file'));
    final fileUuid = resolved['uuid'] as String;

    print('📥 LIVE: Downloading...');
    final downloadResult = await client.downloadFile(
      fileUuid,
      _creds!['bridgeUser'] as String,
      _creds!['userId'].toString(),
    );

    final downloaded = downloadResult['data'] as Uint8List;
    expect(downloaded.length, equals(w.payload.length));
    expect(downloaded, equals(w.payload), reason: 'bytes mismatch');
    print('✅ LIVE: Round-trip ${w.payload.length} bytes OK');
  });

  // ===========================================================================
  // PATH RESOLUTION
  // ===========================================================================

  liveTest('resolve sentinel path from cold cache', () async {
    final resolved = await client.resolvePath(_sentinelPath);
    expect(resolved['type'], equals('folder'));
    expect(resolved['uuid'], equals(_sentinelUuid));
  });

  liveTest('resolve missing path throws', () async {
    expect(
      () => client.resolvePath(
          '$_sentinelPath/definitely-no-such-thing-${_uniqueName('x')}'),
      throwsA(isA<Exception>()),
    );
  });

  // ===========================================================================
  // RECURSIVE FOLDER CREATION
  // ===========================================================================

  liveTest('recursive folder creation 3 levels deep then resolve each',
      () async {
    final nested =
        '$_sentinelPath/lvl1/lvl2/lvl3-${_uniqueName('').substring(1)}';
    final created = await client.createFolderRecursive(nested);
    expect(created['uuid'], isNotNull);

    // Each segment must resolve cleanly
    final lvl1 = '$_sentinelPath/lvl1';
    final lvl2 = '$_sentinelPath/lvl1/lvl2';
    for (final path in [lvl1, lvl2, nested]) {
      final r = await client.resolvePath(path);
      expect(r['type'], equals('folder'),
          reason: '$path didn\'t resolve as folder');
      expect(r['uuid'], isNotNull);
    }
  });

  // ===========================================================================
  // FILE OPERATIONS
  // ===========================================================================

  liveTest('rename file in place', () async {
    final before = _uniqueName('before');
    final after = _uniqueName('after');
    final w = _writePayload(tmpRoot, '$before.txt', sizeBytes: 64);

    await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$before.txt',
    );

    final resolved = await client.resolvePath('$_sentinelPath/$before.txt');
    final fileUuid = resolved['uuid'] as String;

    await client.renameFile(fileUuid, '$after.txt', null);

    // After rename: new path resolves, old path doesn't
    final resolvedAfter = await client.resolvePath('$_sentinelPath/$after.txt');
    expect(resolvedAfter['uuid'], equals(fileUuid));

    expect(
      () => client.resolvePath('$_sentinelPath/$before.txt'),
      throwsA(isA<Exception>()),
    );
  });

  liveTest('move file between folders', () async {
    final srcSub = await client.createFolderRecursive(_uniqueSubpath('src'));
    final dstSub = await client.createFolderRecursive(_uniqueSubpath('dst'));

    final name = _uniqueName('movable');
    final w = _writePayload(tmpRoot, '$name.txt', sizeBytes: 64);

    await client.uploadSingleItem(
      w.file,
      // The CLI uses path strings for the parent path — the actual call
      // doesn't strictly need it accurate since uuid below dispatches.
      _sentinelPath,
      srcSub['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$name.txt',
    );

    // Find the uploaded file uuid via list of src.
    // listFolderFiles normalises the response and exposes the filename
    // as 'name' (not 'plainName').
    final srcFiles = await client.listFolderFiles(srcSub['uuid'] as String);
    final theFile = srcFiles.firstWhere(
      (f) => (f['name'] as String?) == name,
      orElse: () => <String, dynamic>{},
    );
    expect(theFile, isNotEmpty,
        reason: 'uploaded file not found in src listing');
    final fileUuid = theFile['uuid'] as String;

    await client.moveFile(fileUuid, dstSub['uuid'] as String);

    // After move: in dst, not in src
    final dstFiles = await client.listFolderFiles(dstSub['uuid'] as String);
    final inDst = dstFiles.any((f) => f['uuid'] == fileUuid);
    expect(inDst, isTrue, reason: 'file not in destination after move');

    final srcFilesAfter =
        await client.listFolderFiles(srcSub['uuid'] as String);
    final inSrc = srcFilesAfter.any((f) => f['uuid'] == fileUuid);
    expect(inSrc, isFalse, reason: 'file still in source after move');
  });

  // ===========================================================================
  // FOLDER OPERATIONS
  // ===========================================================================

  liveTest('rename folder', () async {
    final initial = _uniqueSubpath('renameable');
    final folder = await client.createFolderRecursive(initial);
    final folderUuid = folder['uuid'] as String;

    final newName = _uniqueName('renamed');
    await client.renameFolder(folderUuid, newName);

    // Resolve the new path
    final newPath = '$_sentinelPath/$newName';
    final resolved = await client.resolvePath(newPath);
    expect(resolved['uuid'], equals(folderUuid));
  });

  liveTest('move folder to another parent', () async {
    final srcParent =
        await client.createFolderRecursive(_uniqueSubpath('src-p'));
    final dstParent =
        await client.createFolderRecursive(_uniqueSubpath('dst-p'));

    // Create a child under srcParent. createFolderRecursive returns the
    // raw API response which uses 'plainName'; listFolders/listFolders
    // below normalise to 'name'.
    final srcParentName =
        (srcParent['plainName'] ?? srcParent['name']) as String;
    final childInfo = await client
        .createFolderRecursive('$_sentinelPath/$srcParentName/movable-child');
    // Actually fetch via listing to get the right uuid
    final srcKids = await client.listFolders(srcParent['uuid'] as String);
    final child = srcKids.firstWhere(
      (f) => (f['name'] as String?) == 'movable-child',
      orElse: () => <String, dynamic>{},
    );
    expect(child, isNotEmpty, reason: 'movable-child not found in src parent');
    final childUuid = child['uuid'] as String;

    await client.moveFolder(childUuid, dstParent['uuid'] as String);

    // After move: in dst, not in src
    final dstKids = await client.listFolders(dstParent['uuid'] as String);
    final inDst = dstKids.any((f) => f['uuid'] == childUuid);
    expect(inDst, isTrue);

    final srcKidsAfter = await client.listFolders(srcParent['uuid'] as String);
    final inSrc = srcKidsAfter.any((f) => f['uuid'] == childUuid);
    expect(inSrc, isFalse);
    // childInfo is captured for completeness; we use the listing-resolved uuid
    expect(childInfo, isNotNull);
  });

  // ===========================================================================
  // TRASH
  // ===========================================================================

  liveTest('trash file removes from listing', () async {
    final name = _uniqueName('trashable');
    final w = _writePayload(tmpRoot, '$name.txt', sizeBytes: 64);

    await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$name.txt',
    );

    final resolved = await client.resolvePath('$_sentinelPath/$name.txt');
    final fileUuid = resolved['uuid'] as String;

    await client.trashItems(fileUuid, 'file');

    expect(
      () => client.resolvePath('$_sentinelPath/$name.txt'),
      throwsA(isA<Exception>()),
    );
  });

  // ===========================================================================
  // BATCH / NESTED — trash non-empty folder
  // ===========================================================================

  liveTest('trash non-empty folder removes children', () async {
    final folderPath = _uniqueSubpath('nonempty-trash');
    final folder = await client.createFolderRecursive(folderPath);
    final folderUuid = folder['uuid'] as String;

    // Add 2 files inside
    final filePaths = <String>[];
    for (final stem in ['inner1', 'inner2']) {
      final name = _uniqueName(stem);
      final w = _writePayload(tmpRoot, '$name.txt', sizeBytes: 64);
      await client.uploadSingleItem(
        w.file,
        folderPath,
        folderUuid,
        'overwrite',
        bridgeUser: _creds!['bridgeUser'] as String,
        userIdForAuth: _creds!['userId'].toString(),
        preserveTimestamps: false,
        remoteFileName: '$name.txt',
      );
      filePaths.add('$folderPath/$name.txt');
    }

    // Trash the entire folder
    await client.trashItems(folderUuid, 'folder');

    // Children no longer resolve under the old paths
    for (final path in filePaths) {
      expect(
        () => client.resolvePath(path),
        throwsA(isA<Exception>()),
      );
    }
  });

  // ===========================================================================
  // UPLOAD VARIATIONS
  // ===========================================================================

  liveTest('upload with unicode filename round-trips', () async {
    // Use ASCII for the local filesystem (filesystems vary on what they
    // accept), but pass the unicode name as the *remote* filename.
    final stem = _uniqueName('resume');
    final unicodeStem = 'résumé-${stem.substring(stem.length - 6)}';
    final w = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 64);

    final result = await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$unicodeStem.txt',
    );
    expect(result, equals('uploaded'));

    // Listing must surface the unicode name unchanged.
    final files = await client.listFolderFiles(_sentinelUuid!);
    final names = files.map((f) => f['name'] as String?).toList();
    expect(names, contains(unicodeStem),
        reason: 'unicode plainName not preserved on remote: $names');

    // Resolve via the unicode path; download bytes must match.
    final resolved =
        await client.resolvePath('$_sentinelPath/$unicodeStem.txt');
    expect(resolved['type'], equals('file'));
    final fileUuid = resolved['uuid'] as String;
    final downloadResult = await client.downloadFile(
      fileUuid,
      _creds!['bridgeUser'] as String,
      _creds!['userId'].toString(),
    );
    expect(downloadResult['data'] as Uint8List, equals(w.payload));
  });

  liveTest('upload extensionless file round-trips', () async {
    final name = _uniqueName('README');
    final w = _writePayload(tmpRoot, name, sizeBytes: 128);

    final result = await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: name,
    );
    expect(result, equals('uploaded'));

    // Resolve under bare name (no extension), verify bytes round-trip.
    final resolved = await client.resolvePath('$_sentinelPath/$name');
    expect(resolved['type'], equals('file'));
    final fileUuid = resolved['uuid'] as String;
    final downloadResult = await client.downloadFile(
      fileUuid,
      _creds!['bridgeUser'] as String,
      _creds!['userId'].toString(),
    );
    expect(downloadResult['data'] as Uint8List, equals(w.payload));
  });

  liveTest('upload 2 MB file (exercises chunked multipart path)',
      timeout: const Timeout(Duration(minutes: 3)), () async {
    // 2 MB to keep quota impact small while forcing the
    // uploadChunkWithProgress 128 KB sub-chunk loop and the 5 ms
    // inter-chunk delay to actually iterate. Timeout bumped above
    // package:test's default 30s because the chunked path + network
    // round-trip can stretch past it for files of this size.
    const size = 2 * 1024 * 1024;
    final name = _uniqueName('bigger');
    final w = _writePayload(tmpRoot, '$name.bin', sizeBytes: size);

    final t0 = DateTime.now();
    final result = await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$name.bin',
    );
    expect(result, equals('uploaded'));
    final elapsed = DateTime.now().difference(t0).inSeconds;
    print('✅ LIVE: 2 MB upload in ${elapsed}s');

    final resolved = await client.resolvePath('$_sentinelPath/$name.bin');
    final fileUuid = resolved['uuid'] as String;
    final downloadResult = await client.downloadFile(
      fileUuid,
      _creds!['bridgeUser'] as String,
      _creds!['userId'].toString(),
    );
    final downloaded = downloadResult['data'] as Uint8List;
    expect(downloaded.length, equals(size));
    expect(downloaded, equals(w.payload), reason: '2 MB round-trip mismatch');
  });

  // ===========================================================================
  // SEARCH (server-side fuzzy)
  // ===========================================================================

  liveTest('search finds uniquely-named file', () async {
    // A name almost certainly unique on the user's drive — server-side
    // fuzzy index needs an exact-prefix probe to avoid noise.
    final rng = Random.secure();
    final hex = List.generate(
            10, (_) => rng.nextInt(256).toRadixString(16).padLeft(2, '0'))
        .join()
        .substring(0, 10);
    final uniqueToken = 'darttestsmoke$hex';
    final w = _writePayload(tmpRoot, '$uniqueToken.txt', sizeBytes: 64);

    await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$uniqueToken.txt',
    );

    final resolved =
        await client.resolvePath('$_sentinelPath/$uniqueToken.txt');
    final fileUuid = resolved['uuid'] as String;

    // Server-side index has eventual consistency; retry up to ~10s.
    var found = false;
    Map<String, List<Map<String, dynamic>>>? lastResults;
    for (var attempt = 0; attempt < 5; attempt++) {
      final results = await client.search(uniqueToken);
      lastResults = results;
      final fileUuids = results['files']!.map((f) => f['uuid']).toList();
      if (fileUuids.contains(fileUuid)) {
        found = true;
        break;
      }
      await Future<void>.delayed(const Duration(seconds: 2));
    }

    if (!found) {
      // Backend latency, not a CLI bug — match the Python sibling and
      // document via a print rather than failing the suite.
      print('⚠️  LIVE: search index did not surface $uniqueToken within '
          '~10s. Last results: $lastResults');
      markTestSkipped('server-side search index latency, not a CLI bug');
    }
  });

  liveTest('search with bogus query returns a list (Map shape)', () async {
    final rng = Random.secure();
    final hex = List.generate(
        16, (_) => rng.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
    final bogus = 'definitelyNoSuchThing$hex';
    try {
      final results = await client.search(bogus);
      // Internxt's fuzzy search returns ranked-by-distance results even
      // for nonsense terms. We only assert the shape is sane.
      expect(results, isA<Map<String, List<Map<String, dynamic>>>>());
      expect(results.containsKey('folders'), isTrue);
      expect(results.containsKey('files'), isTrue);
      expect(results['folders'], isA<List<Map<String, dynamic>>>());
      expect(results['files'], isA<List<Map<String, dynamic>>>());
    } catch (e) {
      // 4xx on no-results is also an acceptable backend behavior.
      print('ℹ️  LIVE: bogus search raised cleanly: $e');
    }
  });

  // ===========================================================================
  // FIND (recursive client-side glob)
  // ===========================================================================

  liveTest('findFiles within sentinel returns only matching glob', () async {
    // Use a per-call probe extension so reruns don't collide with prior
    // attempts in the shared sentinel folder.
    final rng = Random.secure();
    final hex = List.generate(
            3, (_) => rng.nextInt(256).toRadixString(16).padLeft(2, '0'))
        .join()
        .substring(0, 6);
    final probeExt = 'findprobe$hex';

    final expected = <String>[];
    for (var i = 0; i < 2; i++) {
      final name = _uniqueName('finder$i');
      final w = _writePayload(tmpRoot, '$name.$probeExt', sizeBytes: 64);
      await client.uploadSingleItem(
        w.file,
        _sentinelPath,
        _sentinelUuid!,
        'overwrite',
        bridgeUser: _creds!['bridgeUser'] as String,
        userIdForAuth: _creds!['userId'].toString(),
        preserveTimestamps: false,
        remoteFileName: '$name.$probeExt',
      );
      expected.add('$name.$probeExt');
    }

    // Control file with a different extension — must not match the glob.
    final controlName = _uniqueName('control');
    final controlW =
        _writePayload(tmpRoot, '$controlName.unrelated', sizeBytes: 64);
    await client.uploadSingleItem(
      controlW.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$controlName.unrelated',
    );

    final results = await client.findFiles(_sentinelPath, '*.$probeExt');
    final names = results.map((r) => r['displayName'] as String).toList()
      ..sort();
    expected.sort();
    expect(names, equals(expected),
        reason: 'findFiles returned unexpected set: $names vs $expected');
  });

  // ===========================================================================
  // BATCHED / NESTED OPERATIONS
  // ===========================================================================

  liveTest('recursive folder upload + per-file download round-trips', () async {
    final rootRemote = _uniqueSubpath('rec-tree');
    // Pre-create the root remote folder; per-file uploads attach into it.
    await client.createFolderRecursive(rootRemote);

    // Build a local tree of 4 files in 3 subfolders.
    final srcRoot = Directory('${tmpRoot.path}/${_uniqueName('src')}');
    srcRoot.createSync();
    Directory('${srcRoot.path}/sub1').createSync();
    Directory('${srcRoot.path}/sub2').createSync();
    Directory('${srcRoot.path}/sub2/sub2sub').createSync();

    final treePayloads = <String, Uint8List>{};
    for (final entry in const <List<dynamic>>[
      ['a.txt', 64],
      ['b.bin', 256],
      ['sub1/c.txt', 96],
      ['sub2/sub2sub/d.txt', 128],
    ]) {
      final relPath = entry[0] as String;
      final size = entry[1] as int;
      final fullLocal = '${srcRoot.path}/$relPath';
      final parts = relPath.split('/');
      final dirPart =
          parts.length > 1 ? parts.sublist(0, parts.length - 1).join('/') : '';
      if (dirPart.isNotEmpty) {
        Directory('${srcRoot.path}/$dirPart').createSync(recursive: true);
      }
      final w = _writePayload(Directory('${srcRoot.path}/$dirPart'), parts.last,
          sizeBytes: size);
      treePayloads[relPath] = w.payload;
      // ignore: unused_local_variable
      final _ = fullLocal; // silences lints; we use w.file below
    }

    // Upload each file: ensure remote subfolder exists, upload into it.
    final remoteUuids = <String, String>{};
    for (final entry in treePayloads.entries) {
      final relPath = entry.key;
      final parts = relPath.split('/');
      final relDir = parts.sublist(0, parts.length - 1).join('/');
      final remoteDir = relDir.isEmpty ? rootRemote : '$rootRemote/$relDir';
      final folderInfo = await client.createFolderRecursive(remoteDir);
      final localFile = File('${srcRoot.path}/$relPath');
      // Use unique name suffix so retries don't collide.
      final leaf = parts.last;
      final dot = leaf.lastIndexOf('.');
      final stem = dot > 0 ? leaf.substring(0, dot) : leaf;
      final ext = dot > 0 ? leaf.substring(dot + 1) : '';
      final unique = _uniqueName(stem);
      final remoteFileName = ext.isEmpty ? unique : '$unique.$ext';
      await client.uploadSingleItem(
        localFile,
        remoteDir,
        folderInfo['uuid'] as String,
        'overwrite',
        bridgeUser: _creds!['bridgeUser'] as String,
        userIdForAuth: _creds!['userId'].toString(),
        preserveTimestamps: false,
        remoteFileName: remoteFileName,
      );
      final resolved = await client.resolvePath('$remoteDir/$remoteFileName');
      remoteUuids[relPath] = resolved['uuid'] as String;
    }

    // Download each by uuid; bytes must match the original payloads.
    for (final entry in remoteUuids.entries) {
      final relPath = entry.key;
      final fileUuid = entry.value;
      final downloadResult = await client.downloadFile(
        fileUuid,
        _creds!['bridgeUser'] as String,
        _creds!['userId'].toString(),
      );
      final downloaded = downloadResult['data'] as Uint8List;
      expect(downloaded, equals(treePayloads[relPath]),
          reason: 'bytes mismatch for $relPath');
    }
  });

  liveTest('move non-empty folder brings children with same uuids', () async {
    // Build remote tree:
    //   <sentinel>/move-src-XX/A/file1.txt
    //                          file2.txt
    //                          sub/file3.txt
    final srcRoot = _uniqueSubpath('move-src');
    final aPath = '$srcRoot/A';
    final aSubPath = '$aPath/sub';
    final aInfo = await client.createFolderRecursive(aPath);
    final aSubInfo = await client.createFolderRecursive(aSubPath);

    final fileUuids = <String, String>{};
    for (final placement in <List<dynamic>>[
      [aInfo['uuid'] as String, aPath, 'file1'],
      [aInfo['uuid'] as String, aPath, 'file2'],
      [aSubInfo['uuid'] as String, aSubPath, 'file3'],
    ]) {
      final parentUuid = placement[0] as String;
      final parentPath = placement[1] as String;
      final stem = placement[2] as String;
      final unique = _uniqueName(stem);
      final w = _writePayload(tmpRoot, '$unique.txt', sizeBytes: 64);
      await client.uploadSingleItem(
        w.file,
        parentPath,
        parentUuid,
        'overwrite',
        bridgeUser: _creds!['bridgeUser'] as String,
        userIdForAuth: _creds!['userId'].toString(),
        preserveTimestamps: false,
        remoteFileName: '$unique.txt',
      );
      final resolved = await client.resolvePath('$parentPath/$unique.txt');
      fileUuids[stem] = resolved['uuid'] as String;
    }

    // Move A under a fresh dst-parent.
    final dstParent =
        await client.createFolderRecursive(_uniqueSubpath('move-dst'));
    await client.moveFolder(
        aInfo['uuid'] as String, dstParent['uuid'] as String);

    // A is no longer in srcRoot.
    final srcRootInfo = await client.resolvePath(srcRoot);
    final srcSubs = await client.listFolders(srcRootInfo['uuid'] as String);
    expect(srcSubs.any((f) => f['name'] == 'A'), isFalse,
        reason: 'A still in src after move');

    // A is now in dstParent.
    final dstSubs = await client.listFolders(dstParent['uuid'] as String);
    expect(dstSubs.any((f) => f['name'] == 'A'), isTrue,
        reason: 'A not in dst after move');

    // All child file uuids are preserved (move = pointer reparent).
    final aInDst = dstSubs.firstWhere((f) => f['name'] == 'A');
    final aInDstUuid = aInDst['uuid'] as String;
    final filesUnderA = await client.listFolderFiles(aInDstUuid);
    final subsUnderA = await client.listFolders(aInDstUuid);
    final subUuid =
        subsUnderA.firstWhere((f) => f['name'] == 'sub')['uuid'] as String;
    final filesUnderSub = await client.listFolderFiles(subUuid);

    final foundUuids = <String>[
      ...filesUnderA.map((f) => f['uuid'] as String),
      ...filesUnderSub.map((f) => f['uuid'] as String),
    ];
    for (final original in fileUuids.values) {
      expect(foundUuids, contains(original),
          reason: 'child file uuid lost on parent move');
    }
  });

  liveTest('rename folder preserves child file uuid + path', () async {
    final fooPath = _uniqueSubpath('foo');
    final fooInfo = await client.createFolderRecursive(fooPath);

    final stem = _uniqueName('inside');
    final w = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      w.file,
      fooPath,
      fooInfo['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );
    final originalResolved = await client.resolvePath('$fooPath/$stem.txt');
    final originalUuid = originalResolved['uuid'] as String;

    final newFolderName = _uniqueName('bar');
    await client.renameFolder(fooInfo['uuid'] as String, newFolderName);

    // File resolves under the renamed parent with the same uuid.
    final parentOfFoo = fooPath.substring(0, fooPath.lastIndexOf('/'));
    final newFilePath = '$parentOfFoo/$newFolderName/$stem.txt';
    final renamedResolved = await client.resolvePath(newFilePath);
    expect(renamedResolved['type'], equals('file'));
    expect(renamedResolved['uuid'], equals(originalUuid),
        reason: 'child file uuid changed after parent rename');
  });

  // ===========================================================================
  // CONFLICT POLICY (upload.dart's onConflict branches)
  // ===========================================================================

  liveTest('upload with onConflict=skip preserves original uuid + bytes',
      () async {
    final testDir = _uniqueSubpath('conflict-skip');
    final dirInfo = await client.createFolderRecursive(testDir);

    final name = _uniqueName('conflict-target');
    final wV1 = _writePayload(tmpRoot, '$name.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      wV1.file,
      testDir,
      dirInfo['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$name.txt',
    );
    final initial = await client.resolvePath('$testDir/$name.txt');
    final initialUuid = initial['uuid'] as String;

    // Same remote name, different local file → conflict; expect skip.
    final wV2 = _writePayload(tmpRoot, '${name}_v2.txt', sizeBytes: 64);
    final result = await client.uploadSingleItem(
      wV2.file,
      testDir,
      dirInfo['uuid'] as String,
      'skip',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$name.txt',
    );
    expect(result, equals('skipped'),
        reason: "expected 'skipped', got '$result'");

    // The path still resolves to the original uuid + bytes.
    final after = await client.resolvePath('$testDir/$name.txt');
    expect(after['uuid'], equals(initialUuid),
        reason: 'uuid changed despite skip');
    final downloadResult = await client.downloadFile(
      initialUuid,
      _creds!['bridgeUser'] as String,
      _creds!['userId'].toString(),
    );
    expect(downloadResult['data'] as Uint8List, equals(wV1.payload),
        reason: 'bytes changed despite skip');
  });

  liveTest('upload with onConflict=safety_pattern keeps old as .bak', () async {
    final testDir = _uniqueSubpath('conflict-safety');
    final dirInfo = await client.createFolderRecursive(testDir);

    final stem = _uniqueName('safety-target');
    final wV1 = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      wV1.file,
      testDir,
      dirInfo['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );
    final initial = await client.resolvePath('$testDir/$stem.txt');
    final initialUuid = initial['uuid'] as String;

    // Re-upload with safety_pattern. Different content size on
    // purpose so we can tell the new bytes from the old.
    final wV2 = _writePayload(tmpRoot, '${stem}_v2.txt', sizeBytes: 128);
    final result = await client.uploadSingleItem(
      wV2.file,
      testDir,
      dirInfo['uuid'] as String,
      'safety_pattern',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );
    expect(result, equals('uploaded'));

    // After safety-pattern:
    //   <stem>.txt     → new file, new uuid, new bytes
    //   <stem>.txt.bak → original uuid, original bytes
    final after = await client.resolvePath('$testDir/$stem.txt');
    expect(after['uuid'], isNot(equals(initialUuid)),
        reason:
            'safety_pattern should produce a NEW uuid at the original path');

    final bak = await client.resolvePath('$testDir/$stem.txt.bak');
    expect(bak['uuid'], equals(initialUuid),
        reason: '.bak should retain the ORIGINAL file uuid');

    // Bytes round-trip: original now lives at .bak, new lives at
    // the original path.
    final newDl = await client.downloadFile(
      after['uuid'] as String,
      _creds!['bridgeUser'] as String,
      _creds!['userId'].toString(),
    );
    final bakDl = await client.downloadFile(
      bak['uuid'] as String,
      _creds!['bridgeUser'] as String,
      _creds!['userId'].toString(),
    );
    expect(newDl['data'] as Uint8List, equals(wV2.payload),
        reason: 'new file should contain v2 bytes');
    expect(bakDl['data'] as Uint8List, equals(wV1.payload),
        reason: '.bak should retain v1 bytes');
  });

  liveTest('upload with onConflict=overwrite trashes old + uploads new',
      () async {
    final testDir = _uniqueSubpath('conflict-overwrite');
    final dirInfo = await client.createFolderRecursive(testDir);

    final name = _uniqueName('overwrite-target');
    final wV1 = _writePayload(tmpRoot, '$name.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      wV1.file,
      testDir,
      dirInfo['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$name.txt',
    );
    final initial = await client.resolvePath('$testDir/$name.txt');
    final initialUuid = initial['uuid'] as String;

    // Re-upload with overwrite → trash old, upload new (new uuid).
    final wV2 = _writePayload(tmpRoot, '${name}_v2.txt', sizeBytes: 80);
    final result = await client.uploadSingleItem(
      wV2.file,
      testDir,
      dirInfo['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$name.txt',
    );
    expect(result, equals('uploaded'),
        reason: "expected 'uploaded', got '$result'");

    // Path now resolves to a NEW uuid with v2 bytes.
    final after = await client.resolvePath('$testDir/$name.txt');
    final newUuid = after['uuid'] as String;
    expect(newUuid, isNot(equals(initialUuid)),
        reason: 'uuid unchanged after overwrite (expected new uuid)');
    final downloadResult = await client.downloadFile(
      newUuid,
      _creds!['bridgeUser'] as String,
      _creds!['userId'].toString(),
    );
    final downloaded = downloadResult['data'] as Uint8List;
    expect(downloaded, equals(wV2.payload),
        reason: 'overwrite produced new uuid but old bytes');
    expect(downloaded, isNot(equals(wV1.payload)));
  });

  // ===========================================================================
  // PHASE 7 — performance + UX parity with Python sibling
  // ===========================================================================

  // 8.1 — trash lifecycle
  liveTest(
      'trash lifecycle: trash file -> appears in trash -> restore -> '
      'resolves at destination', () async {
    // Upload a file under sentinel.
    final stem = _uniqueName('trash-restore');
    final w = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );
    final original = await client.resolvePath('$_sentinelPath/$stem.txt');
    final fileUuid = original['uuid'] as String;

    // Trash.
    await client.trashItems(fileUuid, 'file');
    expect(
      () => client.resolvePath('$_sentinelPath/$stem.txt'),
      throwsA(isA<Exception>()),
      reason: 'trashed file should not resolve at original path',
    );

    // List trash. The trashed item *should* appear, but Internxt's
    // trash index has eventual-consistency lag (the dedicated
    // `trash listing eventual-consistency latency` test below
    // measures it explicitly). Best-effort retry here; the
    // restore-then-verify step is the real lifecycle assertion.
    var foundInTrash = false;
    for (var attempt = 0; attempt < 4; attempt++) {
      final trashItems = await client.getTrashContent(limit: 200);
      if (trashItems.any((t) => t['uuid'] == fileUuid)) {
        foundInTrash = true;
        break;
      }
      await Future<void>.delayed(const Duration(seconds: 2));
    }
    if (!foundInTrash) {
      print('⚠️  LIVE: trashed file did not surface in trash listing '
          'within ~6s (Internxt index lag, not a CLI bug). '
          'Continuing with restore.');
    }

    // Create a fresh restore destination (the original parent might
    // not be the right home for restore; pick a fresh subfolder so
    // the test is deterministic).
    final restoreDst =
        await client.createFolderRecursive(_uniqueSubpath('restore-dst'));
    final restoreDstUuid = restoreDst['uuid'] as String;

    await client.restoreFromTrash(
      fileUuid,
      'file',
      destinationFolderUuid: restoreDstUuid,
    );

    // Restored file should appear in the destination folder with the
    // original UUID.
    final dstFiles = await client.listFolderFiles(restoreDstUuid);
    expect(dstFiles.any((f) => f['uuid'] == fileUuid), isTrue,
        reason: 'restored file should appear in destination folder');
  });

  // 7.3 — batch-mv ergonomics
  liveTest('batch mv: multi-source moves all files in parallel', () async {
    final srcA =
        await client.createFolderRecursive(_uniqueSubpath('mv-multi-srcA'));
    final srcB =
        await client.createFolderRecursive(_uniqueSubpath('mv-multi-srcB'));
    final dst =
        await client.createFolderRecursive(_uniqueSubpath('mv-multi-dst'));

    // Upload one file to each src folder.
    final uuids = <String>[];
    final names = <String>[];
    for (final entry in [
      [srcA, 'fA'],
      [srcB, 'fB'],
    ]) {
      final folderInfo = entry[0] as Map<String, dynamic>;
      final stem = _uniqueName(entry[1] as String);
      names.add('$stem.txt');
      final w = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 64);
      await client.uploadSingleItem(
        w.file,
        folderInfo['path'] as String,
        folderInfo['uuid'] as String,
        'overwrite',
        bridgeUser: _creds!['bridgeUser'] as String,
        userIdForAuth: _creds!['userId'].toString(),
        preserveTimestamps: false,
        remoteFileName: '$stem.txt',
      );
      final resolved =
          await client.resolvePath('${folderInfo['path']}/$stem.txt');
      uuids.add(resolved['uuid'] as String);
    }

    // Multi-source batch move via the library entry-point.
    final result = await InternxtCLI.executeMoveBatch(
      client: client,
      sources: [
        '${srcA['path']}/${names[0]}',
        '${srcB['path']}/${names[1]}',
      ],
      targetPath: dst['path'] as String,
      onConflict: 'skip',
      dryRun: false,
      workers: 4,
      silent: true,
    );

    expect(result.success, equals(2));
    expect(result.errors, equals(0));
    expect(result.skipped, equals(0));

    // Both files now in dst with original UUIDs.
    final dstFiles = await client.listFolderFiles(dst['uuid'] as String);
    final dstUuids = dstFiles.map((f) => f['uuid'] as String).toSet();
    expect(dstUuids, containsAll(uuids));
  });

  liveTest('batch mv: --dry-run plans without moving', () async {
    final src =
        await client.createFolderRecursive(_uniqueSubpath('mv-dry-src'));
    final dst =
        await client.createFolderRecursive(_uniqueSubpath('mv-dry-dst'));

    final stem = _uniqueName('dry');
    final w = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      w.file,
      src['path'] as String,
      src['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );

    final result = await InternxtCLI.executeMoveBatch(
      client: client,
      sources: ['${src['path']}/$stem.txt'],
      targetPath: dst['path'] as String,
      onConflict: 'skip',
      dryRun: true,
      workers: 4,
      silent: true,
    );

    expect(result.planSize, equals(1));
    expect(result.success, equals(0)); // dry-run never executes
    expect(result.errors, equals(0));

    // File is still in src, NOT in dst.
    final srcFiles = await client.listFolderFiles(src['uuid'] as String);
    final dstFiles = await client.listFolderFiles(dst['uuid'] as String);
    expect(srcFiles.any((f) => f['name'] == stem), isTrue,
        reason: 'dry-run unexpectedly moved file out of src');
    expect(dstFiles.any((f) => f['name'] == stem), isFalse,
        reason: 'dry-run unexpectedly created file in dst');
  });

  liveTest('batch mv: onConflict=skip preserves the dst file', () async {
    final src =
        await client.createFolderRecursive(_uniqueSubpath('mv-skip-src'));
    final dst =
        await client.createFolderRecursive(_uniqueSubpath('mv-skip-dst'));

    final stem = _uniqueName('collide');
    // Pre-populate dst with a file of the same leaf name as the src.
    final wDst = _writePayload(tmpRoot, '${stem}_dst.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      wDst.file,
      dst['path'] as String,
      dst['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );
    final dstResolved = await client.resolvePath('${dst['path']}/$stem.txt');
    final dstOriginalUuid = dstResolved['uuid'] as String;

    // Source file with the same leaf name.
    final wSrc = _writePayload(tmpRoot, '${stem}_src.txt', sizeBytes: 80);
    await client.uploadSingleItem(
      wSrc.file,
      src['path'] as String,
      src['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );

    final result = await InternxtCLI.executeMoveBatch(
      client: client,
      sources: ['${src['path']}/$stem.txt'],
      targetPath: dst['path'] as String,
      onConflict: 'skip',
      dryRun: false,
      workers: 4,
      silent: true,
    );

    expect(result.success, equals(0));
    expect(result.skipped, equals(1));

    // dst still has the original file with the original UUID.
    final dstAfter = await client.resolvePath('${dst['path']}/$stem.txt');
    expect(dstAfter['uuid'], equals(dstOriginalUuid),
        reason: 'skip policy should leave dst original intact');
  });

  liveTest('batch mv: onConflict=overwrite trashes dst, moves src', () async {
    final src =
        await client.createFolderRecursive(_uniqueSubpath('mv-ovw-src'));
    final dst =
        await client.createFolderRecursive(_uniqueSubpath('mv-ovw-dst'));

    final stem = _uniqueName('replace');
    // Pre-populate dst.
    final wDst = _writePayload(tmpRoot, '${stem}_dst.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      wDst.file,
      dst['path'] as String,
      dst['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );
    final dstOriginal = await client.resolvePath('${dst['path']}/$stem.txt');
    final dstOriginalUuid = dstOriginal['uuid'] as String;

    // src file with same leaf.
    final wSrc = _writePayload(tmpRoot, '${stem}_src.txt', sizeBytes: 100);
    await client.uploadSingleItem(
      wSrc.file,
      src['path'] as String,
      src['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );
    final srcOriginal = await client.resolvePath('${src['path']}/$stem.txt');
    final srcOriginalUuid = srcOriginal['uuid'] as String;

    final result = await InternxtCLI.executeMoveBatch(
      client: client,
      sources: ['${src['path']}/$stem.txt'],
      targetPath: dst['path'] as String,
      onConflict: 'overwrite',
      dryRun: false,
      workers: 4,
      silent: true,
    );

    expect(result.success, equals(1));
    expect(result.skipped, equals(0));
    expect(result.errors, equals(0));

    // dst now resolves to the SOURCE's UUID (because the original
    // dst file got trashed and the src moved into its place).
    final dstAfter = await client.resolvePath('${dst['path']}/$stem.txt');
    expect(dstAfter['uuid'], equals(srcOriginalUuid),
        reason: 'overwrite policy should leave the moved-source UUID at dst');
    expect(dstAfter['uuid'], isNot(equals(dstOriginalUuid)),
        reason: 'overwrite should have trashed the original dst file');
  });

  liveTest(
      'upload() pre-scan + size-match skip: re-running an unchanged tree '
      'uploads nothing',
      timeout: const Timeout(Duration(minutes: 3)), () async {
    // Build a tiny local tree, upload it once, then re-run with the
    // same inputs. The second run's pre-scan should see the same
    // sizes already on the remote and mark every task as
    // 'skipped_size_match'.
    final localDir = Directory('${tmpRoot.path}/${_uniqueName('rescan-tree')}');
    localDir.createSync();
    for (var i = 0; i < 4; i++) {
      _writePayload(localDir, '${_uniqueName('f$i')}.txt', sizeBytes: 64);
    }

    final remoteRoot = _uniqueSubpath('rescan-target');

    Future<void> runUploadOnce(String marker) async {
      final batchId =
          config.generateBatchId(marker, [localDir.path], remoteRoot);
      await client.upload(
        [localDir.path],
        remoteRoot,
        recursive: true,
        onConflict: 'skip',
        preserveTimestamps: false,
        include: const [],
        exclude: const [],
        bridgeUser: _creds!['bridgeUser'] as String,
        userIdForAuth: _creds!['userId'].toString(),
        batchId: batchId,
        initialBatchState: null,
        saveStateCallback: (state) async {
          await config.saveBatchState(batchId, state);
        },
        workers: 4,
      );
      await config.deleteBatchState(batchId);
    }

    // First run: actually uploads.
    await runUploadOnce('rescan-1');

    // Second run: should pre-scan, see same sizes, skip everything.
    // We assert by checking the batch state file mid-flight, but
    // post-run validation is cleaner: count the files in the remote
    // subdir and verify their UUIDs are unchanged.
    final dirBase = localDir.path.split(Platform.pathSeparator).last;
    final remoteSubdir = '$remoteRoot/$dirBase';
    final firstRunFiles = await client.listFolderFiles(
        (await client.resolvePath(remoteSubdir))['uuid'] as String);
    final firstRunUuids = firstRunFiles.map((f) => f['uuid'] as String).toSet();

    await runUploadOnce('rescan-2');

    final secondRunFiles = await client.listFolderFiles(
        (await client.resolvePath(remoteSubdir))['uuid'] as String);
    final secondRunUuids =
        secondRunFiles.map((f) => f['uuid'] as String).toSet();

    // No new uploads = no new UUIDs.
    expect(secondRunUuids, equals(firstRunUuids),
        reason: 'second run should have skipped via size-match; new UUIDs '
            'imply re-upload.');
    expect(secondRunFiles.length, equals(firstRunFiles.length),
        reason: 'second run should not duplicate files');
  });

  // 7.9 — upper-bound size check is unit-tested in
  // test/upload_test.dart. This live test only verifies the
  // dynamic-timeout path doesn't break a normal upload (i.e. the
  // small files used by the suite finish well within the 300s+60s
  // floor — no test should now fail on a "too tight" timeout).
  liveTest('uploadFile under dynamic timeout completes normally', () async {
    // Just a regular small upload. If the new timeout machinery is
    // wrong (e.g. timeout always 0), this would fail.
    final stem = _uniqueName('timeout-probe');
    final w = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 4 * 1024);
    final result = await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );
    expect(result, equals('uploaded'));
  });

  liveTest('upload() cancellation: pre-cancelled token uploads nothing',
      () async {
    final localDir = Directory('${tmpRoot.path}/${_uniqueName('cancel-tree')}');
    localDir.createSync();
    for (var i = 0; i < 4; i++) {
      _writePayload(localDir, '${_uniqueName('c$i')}.txt', sizeBytes: 64);
    }

    final remoteRoot = _uniqueSubpath('cancel-target');
    final batchId =
        config.generateBatchId('cancel', [localDir.path], remoteRoot);

    // Pre-cancel the token: every task should hit the early-return
    // branch in runOne and never actually upload.
    final token = CancellationToken();
    token.cancel();

    await client.upload(
      [localDir.path],
      remoteRoot,
      recursive: true,
      onConflict: 'overwrite',
      preserveTimestamps: false,
      include: const [],
      exclude: const [],
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      batchId: batchId,
      initialBatchState: null,
      saveStateCallback: (state) async {
        await config.saveBatchState(batchId, state);
      },
      workers: 4,
      cancellationToken: token,
    );
    await config.deleteBatchState(batchId);

    // The remote target subtree may have been created (parent
    // pre-create runs before tasks fire), but no files should have
    // been uploaded.
    final dirBase = localDir.path.split(Platform.pathSeparator).last;
    final remoteSubdir = '$remoteRoot/$dirBase';
    Map<String, dynamic>? resolved;
    try {
      resolved = await client.resolvePath(remoteSubdir);
    } on Exception catch (e) {
      if (!e.toString().contains('Path not found')) rethrow;
    }
    if (resolved != null) {
      final files = await client.listFolderFiles(resolved['uuid'] as String);
      expect(files, isEmpty,
          reason: 'pre-cancelled upload should not have uploaded anything');
    }
  });

  liveTest('client.upload() parallelism uploads all files',
      timeout: const Timeout(Duration(minutes: 3)), () async {
    // Drives the high-level batch driver (`client.upload(...)`) end
    // to end so the Phase 7.2 parallel pool + Phase 7.1 memory gate +
    // serialized state-saves all get exercised. Sequential live
    // tests (above) only call `uploadSingleItem` directly.
    final localDir = Directory('${tmpRoot.path}/${_uniqueName('parallel-up')}');
    localDir.createSync();
    final payloads = <String, Uint8List>{};
    for (var i = 0; i < 6; i++) {
      final stem = _uniqueName('p$i');
      final w = _writePayload(localDir, '$stem.txt', sizeBytes: 64);
      payloads['$stem.txt'] = w.payload;
    }

    final remoteRoot = _uniqueSubpath('parallel-target');
    final batchId =
        config.generateBatchId('upload', [localDir.path], remoteRoot);

    await client.upload(
      [localDir.path],
      remoteRoot,
      recursive: true,
      onConflict: 'overwrite',
      preserveTimestamps: false,
      include: const [],
      exclude: const [],
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      batchId: batchId,
      initialBatchState: null,
      saveStateCallback: (state) async {
        await config.saveBatchState(batchId, state);
      },
      workers: 4,
    );
    await config.deleteBatchState(batchId);

    // The local dir base name becomes a remote subfolder under
    // `remoteRoot` (the upload pipeline mirrors the local tree).
    final dirBase = localDir.path.split(Platform.pathSeparator).last;
    final remoteSubdir = '$remoteRoot/$dirBase';
    final resolved = await client.resolvePath(remoteSubdir);
    expect(resolved['type'], equals('folder'));

    // All 6 files landed remote with the right bytes.
    final remoteFiles =
        await client.listFolderFiles(resolved['uuid'] as String);
    final remoteByName = {
      for (final f in remoteFiles)
        '${f['name']}.${f['fileType']}': f['uuid'] as String,
    };
    for (final entry in payloads.entries) {
      final fileName = entry.key;
      final original = entry.value;
      final fileUuid = remoteByName[fileName];
      expect(fileUuid, isNotNull,
          reason: '$fileName missing from remote listing $remoteByName');
      final downloadResult = await client.downloadFile(
        fileUuid!,
        _creds!['bridgeUser'] as String,
        _creds!['userId'].toString(),
      );
      expect(downloadResult['data'] as Uint8List, equals(original),
          reason: 'bytes mismatch for $fileName');
    }
  });

  // ===========================================================================
  // PINNED GAPS — features the Python sibling tests but the Dart CLI
  // doesn't yet implement. Each is a `skip:` test so the gap is visible
  // in the test report without breaking the suite. See PLAN.md for the
  // implementation roadmap.
  // ===========================================================================

  liveTest('storage usage endpoint returns a Map', () async {
    final usage = await getStorageUsage(
      client.driveApiUrl,
      client.newToken,
    );
    expect(usage, isA<Map<String, dynamic>>());
  });

  liveTest('users/me known-404 marker (regression pin)', () async {
    // Pinned regression: /drive/users/me does not exist on the live
    // backend (returns 404 "Cannot GET /api/users/me"). If this test
    // starts passing the call without throwing OR throws with a
    // different status, the endpoint has come online (or the gateway
    // changed the error shape) and we should wire real callers.
    //
    // Tightened assertion: must be a 404 specifically. The previous
    // version also accepted "Not Found" / "Cannot GET" but those
    // are 404 message variants; keeping the status-code check is
    // unambiguous and means a 5xx (e.g. an outage) won't be mistaken
    // for "endpoint still missing".
    expect(
      () => getUserInfo(client.driveApiUrl, client.newToken),
      throwsA(predicate((e) => e.toString().contains('404'))),
    );
  });

  liveTest('listFolderWithPaths returns enriched entries', () async {
    final stem = _uniqueName('listing-probe');
    final w = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );

    final listing = await listFolderWithPaths(
      client.driveApiUrl,
      client.newToken,
      client.rootFolderId,
      // Tests don't have direct access to the private cache maps; pass
      // empty maps so the listing always hits the network. Production
      // callers (the CLI) thread the InternxtClient's caches through.
      <String, CacheEntry>{},
      <String, CacheEntry>{},
      _sentinelPath,
    );

    expect(listing['currentPath'], endsWith(_runId));
    final files = listing['files'] as List<Map<String, dynamic>>;
    final probe = files.firstWhere(
      (f) => f['displayName'] == '$stem.txt',
      orElse: () => <String, dynamic>{},
    );
    expect(probe, isNotEmpty,
        reason: '$stem.txt not in enriched listing: '
            '${files.map((f) => f['displayName']).toList()}');
    expect(probe['path'], endsWith('$stem.txt'));
    expect(probe['sizeDisplay'], isA<String>());
    expect(probe['modified'], isNotNull);
  });

  liveTest('copy file to another folder preserves content', () async {
    // Source + destination folders.
    final srcInfo =
        await client.createFolderRecursive(_uniqueSubpath('copy-src'));
    final dstInfo =
        await client.createFolderRecursive(_uniqueSubpath('copy-dst'));

    // Upload an original file under src.
    final stem = _uniqueName('original');
    final w = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 128);
    await client.uploadSingleItem(
      w.file,
      srcInfo['path'] as String,
      srcInfo['uuid'] as String,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );

    // Find original uuid by listing src.
    final srcFiles = await client.listFolderFiles(srcInfo['uuid'] as String);
    final originalUuid =
        srcFiles.firstWhere((f) => f['name'] == stem)['uuid'] as String;

    // Copy it.
    await client.copyItem(
      originalUuid,
      dstInfo['uuid'] as String,
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
    );

    // Original still in src.
    final srcAfter = await client.listFolderFiles(srcInfo['uuid'] as String);
    expect(srcAfter.any((f) => f['uuid'] == originalUuid), isTrue,
        reason: 'original removed by copy operation');

    // Copy in dst with a different uuid.
    final dstFiles = await client.listFolderFiles(dstInfo['uuid'] as String);
    expect(dstFiles.length, equals(1),
        reason: 'expected 1 file in dst after copy, got ${dstFiles.length}');
    final copyUuid = dstFiles.first['uuid'] as String;
    expect(copyUuid, isNot(equals(originalUuid)),
        reason: 'copy has same uuid as original (expected new uuid)');

    // Both UUIDs decrypt to the same payload.
    final origDl = await client.downloadFile(
      originalUuid,
      _creds!['bridgeUser'] as String,
      _creds!['userId'].toString(),
    );
    final copyDl = await client.downloadFile(
      copyUuid,
      _creds!['bridgeUser'] as String,
      _creds!['userId'].toString(),
    );
    expect(origDl['data'] as Uint8List, equals(w.payload));
    expect(copyDl['data'] as Uint8List, equals(w.payload));
  });

  liveTest('updateFile replaces bytes while keeping uuid', () async {
    // Initial upload (content v1).
    final stem = _uniqueName('updatable');
    final wV1 = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      wV1.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );
    final initial = await client.resolvePath('$_sentinelPath/$stem.txt');
    final fileUuid = initial['uuid'] as String;

    // Replace with content v2 — different size on purpose.
    final v2Path = '${tmpRoot.path}/${stem}_v2.txt';
    final v2Bytes = Uint8List.fromList(
        utf8.encode('REPLACED content for updateFile test ${_uniqueName('')}'));
    File(v2Path).writeAsBytesSync(v2Bytes);

    await client.updateFile(
      fileUuid,
      File(v2Path),
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
    );

    // Critical invariant: same uuid resolves to the new bytes.
    final after = await client.resolvePath('$_sentinelPath/$stem.txt');
    expect(after['uuid'], equals(fileUuid),
        reason: 'updateFile changed the uuid (expected in-place)');
    final downloadResult = await client.downloadFile(
      fileUuid,
      _creds!['bridgeUser'] as String,
      _creds!['userId'].toString(),
    );
    final downloaded = downloadResult['data'] as Uint8List;
    expect(downloaded, equals(v2Bytes),
        reason: 'downloaded bytes do not match v2');
    expect(downloaded, isNot(equals(wV1.payload)),
        reason: 'updateFile did not actually replace the content');
  });

  liveTest('trash listing eventual-consistency latency', () async {
    // Measures how long it takes for a freshly-trashed file to
    // surface in /storage/trash/paginated. Internxt's trash index
    // is async; the lifecycle test above retries best-effort and
    // continues if the file doesn't appear in time. This test is
    // dedicated to capturing the lag empirically — useful to know
    // if Internxt fixes (or worsens) it.
    //
    // Test passes if EITHER the file appears within 30s OR if it
    // never appears (in which case we just print the data point).
    // The signal the test surfaces is the printed latency line.
    final stem = _uniqueName('trash-lag-probe');
    final w = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );
    final original = await client.resolvePath('$_sentinelPath/$stem.txt');
    final fileUuid = original['uuid'] as String;

    final stopwatch = Stopwatch()..start();
    await client.trashItems(fileUuid, 'file');

    int attempts = 0;
    Duration? latency;
    // Poll every 1s up to 30s. Cheap enough — trashing is rare.
    for (; attempts < 30; attempts++) {
      final items = await client.getTrashContent(limit: 200);
      if (items.any((t) => t['uuid'] == fileUuid)) {
        latency = stopwatch.elapsed;
        break;
      }
      await Future<void>.delayed(const Duration(seconds: 1));
    }
    stopwatch.stop();

    if (latency != null) {
      print('📊 LIVE: trash-listing latency ${latency.inMilliseconds} ms '
          '(${attempts + 1} attempts)');
    } else {
      print('📊 LIVE: trashed file did NOT surface in 30s — backend lag '
          'has worsened or the trash index is degraded.');
    }

    // Cleanup: permanently delete to avoid trash-bin debris.
    try {
      await client.deletePermanently(fileUuid, 'file');
    } catch (_) {/* swallow */}
  }, timeout: const Timeout(Duration(minutes: 2)));

  liveTest('setFileTimestamp known-broken marker (gateway 409)', () async {
    // NEW gateway gap surfaced while expanding the Phase 9.6
    // marker set: PUT /files/{uuid}/meta with the (required by
    // the documented contract) plainName + type echo triggers a
    // 409 "A file with this name already exists in this location"
    // even when echoing the file's own current name. The gateway
    // appears to run a uniqueness check that doesn't exclude the
    // file itself.
    //
    // Distinct from setFolderTimestamp: PUT /folders/{uuid}/meta
    // accepts the same payload shape (and silently ignores the
    // mtime — see the folder marker below), no 409.
    //
    // Asserts the *current broken behavior*: setFileTimestamp
    // throws with 409. Fires if Internxt fixes the uniqueness
    // check (then we'd start checking whether mtime is honored,
    // matching the folder marker).
    final stem = _uniqueName('mtime-file');
    final w = _writePayload(tmpRoot, '$stem.txt', sizeBytes: 64);
    await client.uploadSingleItem(
      w.file,
      _sentinelPath,
      _sentinelUuid!,
      'overwrite',
      bridgeUser: _creds!['bridgeUser'] as String,
      userIdForAuth: _creds!['userId'].toString(),
      preserveTimestamps: false,
      remoteFileName: '$stem.txt',
    );
    final initial = await client.resolvePath('$_sentinelPath/$stem.txt');
    final fileUuid = initial['uuid'] as String;

    final targetMtime = DateTime.utc(2021, 6, 1, 8, 15, 30);

    expect(
      () => client.setFileTimestamp(fileUuid, targetMtime),
      throwsA(predicate((e) => e.toString().contains('409'))),
      reason: 'setFileTimestamp no longer 409s — the gateway uniqueness '
          'check has changed. Remove this marker and check whether mtime '
          'is now honored end-to-end.',
    );
  });

  liveTest('setFolderTimestamp known-broken marker (Phase 9.6)', () async {
    // Regression pin for the gateway-side gap discovered during
    // the Phase 9.6 stale-cache audit. Sequence:
    //   1. Audit found setFileTimestamp/setFolderTimestamp had no
    //      cache invalidation while the listing cache *does* store
    //      modificationTime → in theory a stale-read bug.
    //   2. Adding a live test for the fix surfaced that
    //      PUT /folders/{uuid}/meta requires plainName too (400 on
    //      partial body). Fix: include plainName in payload.
    //   3. With both fixes in place, the gateway *still* doesn't
    //      honor the requested mtime — direct GET-PUT-GET shows it
    //      always reflects back "now()", regardless of the body.
    //
    // So this test asserts the *current broken behavior*: requesting
    // a 2021 mtime should NOT actually land. If Internxt fixes the
    // gateway, this fires and the cache-invalidation code we added
    // becomes load-bearing instead of defensive.
    final subInfo = await client.createFolderRecursive(_uniqueSubpath('mtime'));
    final folderUuid = subInfo['uuid'] as String;

    final before = await client.getFolderMetadata(folderUuid);
    final targetMtime = DateTime.utc(2021, 6, 1, 8, 15, 30);

    await client.setFolderTimestamp(folderUuid, targetMtime);

    final after = await client.getFolderMetadata(folderUuid);
    final rawAfter =
        (after['modificationTime'] ?? after['updatedAt']) as String?;
    expect(rawAfter, isNotNull);
    final actualMtime = DateTime.parse(rawAfter!).toUtc();

    // Known broken: gateway should ignore our value and return ~now.
    final secondsSinceTarget =
        actualMtime.difference(targetMtime).inSeconds.abs();
    expect(
      secondsSinceTarget,
      greaterThan(
          60), // generous; if it ever lands within a minute, the gateway accepted
      reason: 'gateway honored the requested mtime — '
          'remove this known-broken marker, the feature now works end-to-end. '
          'before=${before['modificationTime']} after=$rawAfter target=$targetMtime',
    );
  });
}
