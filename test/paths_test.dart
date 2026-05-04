// Unit tests for lib/paths.dart — the path-based facade methods.
//
// The methods themselves go through resolvePath + downstream HTTP
// calls and are exercised end-to-end by the live suite. This file
// pins the testable surface:
//   - splitFileNameForRename's rules (extension vs no extension)
//   - _requireSession's gate (the path facade refuses pre-auth
//     calls with a clear StateError instead of NPEing on bridgeUser)

import 'dart:io';

import 'package:test/test.dart';

import 'package:internxt_client/cli.dart';

void main() {
  group('splitFileNameForRename (Phase 6.a B2)', () {
    test('plain name with extension: split on last dot', () {
      expect(splitFileNameForRename('report.pdf'), equals(('report', 'pdf')));
      expect(splitFileNameForRename('archive.tar.gz'),
          equals(('archive.tar', 'gz')));
    });

    test('no extension: name unchanged, extension null', () {
      expect(splitFileNameForRename('README'), equals(('README', null)));
    });

    test('leading dot (dotfile, no extension): null extension', () {
      expect(splitFileNameForRename('.bashrc'), equals(('.bashrc', null)));
    });

    test('trailing dot: null extension (no real ext char)', () {
      expect(splitFileNameForRename('weird.'), equals(('weird.', null)));
    });

    test('empty string: empty + null', () {
      expect(splitFileNameForRename(''), equals(('', null)));
    });
  });

  group('InternxtClientPaths session gate (Phase 6.a B2)', () {
    late Directory tmp;

    setUp(() {
      tmp = Directory.systemTemp.createTempSync('inxt-paths-test-');
    });

    tearDown(() {
      if (tmp.existsSync()) tmp.deleteSync(recursive: true);
    });

    test('uploadFileBytes pre-auth → StateError', () async {
      final client = InternxtClient(config: ConfigService(configPath: tmp.path));
      await expectLater(
        () => client.uploadFileBytes([0, 1, 2], 'x.bin', '/'),
        throwsA(isA<StateError>().having(
          (e) => e.message,
          'message',
          contains('not authenticated'),
        )),
      );
    });

    test('downloadFileByPath pre-auth → StateError', () async {
      final client = InternxtClient(config: ConfigService(configPath: tmp.path));
      await expectLater(
        () => client.downloadFileByPath('/foo.txt', '${tmp.path}/foo.txt'),
        throwsA(isA<StateError>()),
      );
    });

    test('downloadFileBytesByPath pre-auth → StateError', () async {
      final client = InternxtClient(config: ConfigService(configPath: tmp.path));
      await expectLater(
        () => client.downloadFileBytesByPath('/foo.txt'),
        throwsA(isA<StateError>()),
      );
    });

    test('setAuth populates bridgeUser + userIdForAuth (Phase 7.10 fallback)',
        () async {
      final client = InternxtClient(config: ConfigService(configPath: tmp.path));

      // Fresh-login style creds (no userIdForAuth) — fallback to userId.
      client.setAuth({
        'token': 't',
        'newToken': 'nt',
        'mnemonic': 'm',
        'email': 'e@x',
        'userId': 'u-fresh',
        'rootFolderId': 'root',
        'bucketId': 'bkt',
        'bridgeUser': 'bridge@x',
      });
      expect(client.bridgeUser, equals('bridge@x'));
      expect(client.userIdForAuth, equals('u-fresh'));

      // Refresh-style creds (explicit userIdForAuth) — used as-is.
      client.setAuth({
        'token': 't2',
        'newToken': 'nt2',
        'mnemonic': 'm2',
        'email': 'e@x',
        'userId': 'u-after-refresh',
        'userIdForAuth': 'u-bridge-id',
        'rootFolderId': 'root',
        'bucketId': 'bkt',
        'bridgeUser': 'bridge@x',
      });
      expect(client.userIdForAuth, equals('u-bridge-id'));
    });
  });
}
