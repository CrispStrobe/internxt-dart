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

import '../cli.dart';

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
        if (trimmed.isEmpty || trimmed.startsWith('#') || !trimmed.contains('=')) {
          continue;
        }
        final eq = trimmed.indexOf('=');
        final k = trimmed.substring(0, eq).trim();
        final v = trimmed.substring(eq + 1).trim().replaceAll('"', '').replaceAll("'", '');
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
  final hex = List.generate(6, (_) => rng.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
  return '$stem-$hex';
}

String _uniqueSubpath(String name) => '$_sentinelPath/${_uniqueName(name)}';

({File file, Uint8List payload}) _writePayload(Directory tmp, String filename, {int sizeBytes = 256}) {
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
  void liveTest(String description, dynamic Function() body) {
    test(description, body, retry: liveRetries);
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
    config = ConfigService(dataDir: cfgDir.path);
    client = InternxtClient(config: config);

    final loginResult = await client.login(email!, password!);
    expect(loginResult['email']?.toString().toLowerCase(), equals(email.toLowerCase()));
    expect(loginResult['token'], isA<String>());
    expect(loginResult['mnemonic'], isA<String>());
    _creds = loginResult;
    await config.saveCredentials(loginResult);
    client.setAuth(loginResult);
    print('✅ LIVE: Authenticated (uuid=${(loginResult['userId'] as String).substring(0, 8)}...)');

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
        print('⚠️  LIVE: Cleanup failed (please manually trash $_sentinelPath): $e');
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
      expect((c['mnemonic'] as String).split(' ').length, greaterThanOrEqualTo(12));
    });

    liveTest('list root folder', () async {
      final rootUuid = _creds!['rootFolderId'] as String;
      final folders = await client.listFolders(rootUuid);
      final files = await client.listFolderFiles(rootUuid);
      expect(folders, isA<List>());
      expect(files, isA<List>());
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
      () => client.resolvePath('$_sentinelPath/definitely-no-such-thing-${_uniqueName('x')}'),
      throwsA(isA<Exception>()),
    );
  });

  // ===========================================================================
  // RECURSIVE FOLDER CREATION
  // ===========================================================================

  liveTest('recursive folder creation 3 levels deep then resolve each', () async {
    final nested = '$_sentinelPath/lvl1/lvl2/lvl3-${_uniqueName('').substring(1)}';
    final created = await client.createFolderRecursive(nested);
    expect(created['uuid'], isNotNull);

    // Each segment must resolve cleanly
    final lvl1 = '$_sentinelPath/lvl1';
    final lvl2 = '$_sentinelPath/lvl1/lvl2';
    for (final path in [lvl1, lvl2, nested]) {
      final r = await client.resolvePath(path);
      expect(r['type'], equals('folder'), reason: '$path didn\'t resolve as folder');
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
    expect(theFile, isNotEmpty, reason: 'uploaded file not found in src listing');
    final fileUuid = theFile['uuid'] as String;

    await client.moveFile(fileUuid, dstSub['uuid'] as String);

    // After move: in dst, not in src
    final dstFiles = await client.listFolderFiles(dstSub['uuid'] as String);
    final inDst = dstFiles.any((f) => f['uuid'] == fileUuid);
    expect(inDst, isTrue, reason: 'file not in destination after move');

    final srcFilesAfter = await client.listFolderFiles(srcSub['uuid'] as String);
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
    final srcParent = await client.createFolderRecursive(_uniqueSubpath('src-p'));
    final dstParent = await client.createFolderRecursive(_uniqueSubpath('dst-p'));

    // Create a child under srcParent. createFolderRecursive returns the
    // raw API response which uses 'plainName'; listFolders/listFolders
    // below normalise to 'name'.
    final srcParentName = (srcParent['plainName'] ?? srcParent['name']) as String;
    final childInfo = await client.createFolderRecursive(
        '$_sentinelPath/$srcParentName/movable-child');
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
}
