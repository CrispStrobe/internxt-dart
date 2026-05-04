// ConfigService persistence tests.
//
// These exercise credential save/read/clear, batch state persistence,
// WebDAV PID file lifecycle, and batch ID determinism. All operations
// happen inside a per-test temporary directory; nothing touches the
// real ~/.internxt-cli/.
//
// SECURITY NOTE (logged also in LEARNINGS.md): the Dart codebase stores
// credentials as PLAIN JSON. The Python codebase encrypts the file with
// AES-256-CBC + a fixed APP_CRYPTO_SECRET. The encryption isn't strong
// security — anyone who can read the file can also read the secret from
// the binary — but it's a defence-in-depth layer. Worth aligning with
// Python in a future pass.

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import 'package:internxt_client/cli.dart';

ConfigService _newConfig(Directory tmp) => ConfigService(configPath: tmp.path);

void main() {
  late Directory tmp;

  setUp(() {
    tmp = Directory.systemTemp.createTempSync('inxt-dart-config-test-');
  });

  tearDown(() {
    if (tmp.existsSync()) {
      tmp.deleteSync(recursive: true);
    }
  });

  group('ConfigService construction', () {
    test('creates the data dir + subdirs on construction', () {
      final cfg = _newConfig(tmp);
      expect(Directory(cfg.internxtCliDataDir).existsSync(), isTrue);
      expect(Directory(cfg.internxtCliLogsDir).existsSync(), isTrue);
      expect(Directory(cfg.batchStateDir).existsSync(), isTrue);
    });

    test('configDir getter equals the constructor data dir', () {
      final cfg = _newConfig(tmp);
      expect(cfg.configDir, equals(tmp.path));
    });
  });

  group('Credentials persistence', () {
    test('save then read round-trips the credential map', () async {
      final cfg = _newConfig(tmp);
      final creds = {
        'email': 'test@example.com',
        'token': 'abc.def.ghi',
        'newToken': 'jkl.mno.pqr',
        'userId': 'user-uuid',
        'rootFolderId': 'root-uuid',
        'mnemonic': 'abandon abandon abandon abandon abandon abandon '
            'abandon abandon abandon abandon abandon about',
        'bridgeUser': 'test@example.com',
        'bridgePass': 'sha256-of-userid',
        'bucketId': 'bucket-id',
      };
      await cfg.saveCredentials(creds);
      final out = await cfg.readCredentials();
      expect(out, isNotNull);
      expect(out!['email'], equals('test@example.com'));
      expect(out['token'], equals('abc.def.ghi'));
      expect(out['mnemonic'], startsWith('abandon '));
      expect(out['bucketId'], equals('bucket-id'));
    });

    test('read returns null when no credentials file exists', () async {
      final cfg = _newConfig(tmp);
      expect(await cfg.readCredentials(), isNull);
    });

    test('read returns null when credentials file is corrupted', () async {
      final cfg = _newConfig(tmp);
      // Write garbage to the credentials file
      await File(cfg.credentialsFile).writeAsString('not-valid-json{{');
      expect(await cfg.readCredentials(), isNull);
    });

    test('clearCredentials removes the file', () async {
      final cfg = _newConfig(tmp);
      await cfg.saveCredentials({'email': 'x'});
      expect(File(cfg.credentialsFile).existsSync(), isTrue);
      await cfg.clearCredentials();
      expect(File(cfg.credentialsFile).existsSync(), isFalse);
    });

    test('clearCredentials when no file exists is a no-op', () async {
      final cfg = _newConfig(tmp);
      // Should not throw
      await cfg.clearCredentials();
    });

    test('REGRESSION MARKER: credentials are stored as plain JSON', () async {
      // The Dart impl currently stores credentials unencrypted on disk.
      // The Python impl encrypts with AES-256-CBC + a fixed app secret.
      // This test pins the current Dart behaviour so a future encryption
      // upgrade is intentional.
      final cfg = _newConfig(tmp);
      const sentinelToken = 'sentinel-token-abcdef-12345';
      await cfg.saveCredentials({'token': sentinelToken});
      final raw = await File(cfg.credentialsFile).readAsString();
      // The token MUST be plainly readable in the file today.
      expect(raw.contains(sentinelToken), isTrue,
          reason: 'credentials file is currently plaintext JSON');
      // Sanity: it's valid JSON
      expect(jsonDecode(raw), isA<Map>());
    });
  });

  group('WebDAV PID file lifecycle', () {
    test('save -> read -> clear cycle', () async {
      final cfg = _newConfig(tmp);
      expect(await cfg.readWebdavPid(), isNull);

      await cfg.saveWebdavPid(12345);
      expect(await cfg.readWebdavPid(), equals(12345));

      await cfg.clearWebdavPid();
      expect(await cfg.readWebdavPid(), isNull);
    });

    test('readWebdavPid returns null on garbage content', () async {
      final cfg = _newConfig(tmp);
      await File(cfg.webdavPidFile).writeAsString('not-a-number');
      expect(await cfg.readWebdavPid(), isNull);
    });

    test('clearWebdavPid is a no-op when no file exists', () async {
      final cfg = _newConfig(tmp);
      await cfg.clearWebdavPid(); // must not throw
    });
  });

  group('Batch ID generation', () {
    test('deterministic for same inputs', () {
      final cfg = _newConfig(tmp);
      final id1 = cfg.generateBatchId('upload', ['/src/a', '/src/b'], '/dst');
      final id2 = cfg.generateBatchId('upload', ['/src/a', '/src/b'], '/dst');
      expect(id1, equals(id2));
      expect(id1.length, equals(16)); // SHA1[:16]
    });

    test('different sources -> different id', () {
      final cfg = _newConfig(tmp);
      final id1 = cfg.generateBatchId('upload', ['/src/a'], '/dst');
      final id2 = cfg.generateBatchId('upload', ['/src/b'], '/dst');
      expect(id1, isNot(equals(id2)));
    });

    test('different operation -> different id', () {
      final cfg = _newConfig(tmp);
      final upload = cfg.generateBatchId('upload', ['/x'], '/dst');
      final download = cfg.generateBatchId('download', ['/x'], '/dst');
      expect(upload, isNot(equals(download)));
    });

    test('different target -> different id', () {
      final cfg = _newConfig(tmp);
      final id1 = cfg.generateBatchId('upload', ['/x'], '/dst1');
      final id2 = cfg.generateBatchId('upload', ['/x'], '/dst2');
      expect(id1, isNot(equals(id2)));
    });

    test('source order matters (different id for reordered sources)', () {
      final cfg = _newConfig(tmp);
      final ab = cfg.generateBatchId('upload', ['/a', '/b'], '/dst');
      final ba = cfg.generateBatchId('upload', ['/b', '/a'], '/dst');
      // Current implementation joins with '|' so order matters.
      // Documented behaviour — pin it.
      expect(ab, isNot(equals(ba)));
    });
  });

  group('Batch state persistence', () {
    test('save then load round-trips the state map', () async {
      final cfg = _newConfig(tmp);
      const batchId = 'test-batch-1';
      final state = {
        'completed': ['file1.txt', 'file2.txt'],
        'failed': ['file3.txt'],
        'progress': 0.66,
      };
      await cfg.saveBatchState(batchId, state);

      final loaded = await cfg.loadBatchState(batchId);
      expect(loaded, isNotNull);
      expect(loaded!['completed'], equals(['file1.txt', 'file2.txt']));
      expect(loaded['failed'], equals(['file3.txt']));
      expect(loaded['progress'], equals(0.66));
    });

    test('loadBatchState returns null when no file exists', () async {
      final cfg = _newConfig(tmp);
      expect(await cfg.loadBatchState('no-such-batch'), isNull);
    });

    test('loadBatchState deletes corrupted files and returns null', () async {
      final cfg = _newConfig(tmp);
      const batchId = 'corrupted-batch';
      // Write garbage to the state file
      final filePath = cfg.getBatchStateFilePath(batchId);
      await File(filePath).writeAsString('not-valid-json{{');

      final loaded = await cfg.loadBatchState(batchId);
      expect(loaded, isNull);
      // Self-healing: corrupted file is deleted
      expect(File(filePath).existsSync(), isFalse);
    });

    test('deleteBatchState removes the file', () async {
      final cfg = _newConfig(tmp);
      const batchId = 'deletable';
      await cfg.saveBatchState(batchId, {'k': 'v'});
      expect(File(cfg.getBatchStateFilePath(batchId)).existsSync(), isTrue);
      await cfg.deleteBatchState(batchId);
      expect(File(cfg.getBatchStateFilePath(batchId)).existsSync(), isFalse);
    });

    test('deleteBatchState is a no-op when file does not exist', () async {
      final cfg = _newConfig(tmp);
      await cfg.deleteBatchState('nonexistent'); // must not throw
    });

    test('multiple batches do not interfere', () async {
      final cfg = _newConfig(tmp);
      await cfg.saveBatchState('a', {'name': 'alpha'});
      await cfg.saveBatchState('b', {'name': 'beta'});

      final a = await cfg.loadBatchState('a');
      final b = await cfg.loadBatchState('b');
      expect(a!['name'], equals('alpha'));
      expect(b!['name'], equals('beta'));
    });
  });
}
