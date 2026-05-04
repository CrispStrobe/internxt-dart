// Unit tests for download.dart's `downloadFileBytes`.
//
// Mirrors the api_test.dart pattern: MockClient piped through
// `httpClient` intercepts the metadata GET, the download-links GET,
// and the actual encrypted-payload GET. The crypto path is real —
// we encrypt a known plaintext, hand the bytes back through the
// mock, and verify the function decrypts it correctly.
//
// Note: getFileMetadata + getDownloadLinks gained the optional
// `client:` param as part of this Phase 6.a extension. Production
// callers (CLI) pass null and the top-level http helpers run as
// before; tests pipe the mock through.

import 'dart:convert';
import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import 'package:internxt_client/crypto.dart';
import 'package:internxt_client/download.dart';

void main() {
  group('downloadFileBytes (Phase 6.a B1)', () {
    test('streams + decrypts + reports progress', () async {
      // Real crypto: encrypt a known plaintext, hand the ciphertext
      // back through the mock, expect the function to return the
      // plaintext after decrypt.
      final mnemonic = bip39.generateMnemonic();
      // Bucket IDs are HEX-decoded by generateFileBucketKey, so the
      // test value must be valid hex (real Internxt uses 24-char hex).
      const bucketId = '0123456789abcdef01234567';
      final plaintext = Uint8List.fromList(List.generate(2048, (i) => i % 256));
      final enc = encryptStream(plaintext, mnemonic, bucketId);
      final ciphertext = enc['data'] as Uint8List;
      final indexHex = enc['index'] as String;

      final calls = <String>[];
      final mock = MockClient.streaming((req, body) async {
        calls.add('${req.method} ${req.url.path}');
        if (req.url.path.endsWith('/files/test-uuid/meta')) {
          final json = jsonEncode({
            'size': plaintext.length,
            'bucket': bucketId,
            'fileId': 'test-network-file-id',
            'plainName': 'test',
            'type': 'bin',
          });
          return http.StreamedResponse(
            Stream.value(utf8.encode(json)),
            200,
          );
        }
        if (req.url.path.contains('/buckets/$bucketId/files/') &&
            req.url.path.endsWith('/info')) {
          final json = jsonEncode({
            'shards': [
              {'url': 'https://shards.test/payload'}
            ],
            'index': indexHex,
          });
          return http.StreamedResponse(
            Stream.value(utf8.encode(json)),
            200,
          );
        }
        if (req.url.toString() == 'https://shards.test/payload') {
          return http.StreamedResponse(
            Stream.value(ciphertext),
            200,
            contentLength: ciphertext.length,
          );
        }
        throw StateError('unexpected request: ${req.url}');
      });

      final progress = <(int, int)>[];
      final result = await downloadFileBytes(
        'https://drive.test',
        'https://network.test',
        'token',
        mnemonic,
        'test-uuid',
        'bridge-user',
        'user-id-for-auth',
        onProgress: (d, t) => progress.add((d, t)),
        httpClient: mock,
      );

      expect(result, equals(plaintext));
      // All three endpoints hit in order
      expect(calls, hasLength(3));
      expect(calls[0], contains('/files/test-uuid/meta'));
      expect(calls[1], contains('/buckets/$bucketId/files/'));
      expect(calls[2], equals('GET /payload'));
      // Progress fired at least once with a positive bytes count
      expect(progress, isNotEmpty);
      expect(progress.last.$1, equals(ciphertext.length));
    });

    test('non-200 download URL throws with status code', () async {
      final mnemonic = bip39.generateMnemonic();
      const bucketId = '0123456789abcdef01234567';
      final mock = MockClient.streaming((req, body) async {
        if (req.url.path.endsWith('/meta')) {
          return http.StreamedResponse(
            Stream.value(utf8.encode(jsonEncode({
              'size': 100,
              'bucket': bucketId,
              'fileId': 'fid',
              'plainName': 'x',
              'type': '',
            }))),
            200,
          );
        }
        if (req.url.path.endsWith('/info')) {
          return http.StreamedResponse(
            Stream.value(utf8.encode(jsonEncode({
              'shards': [
                {'url': 'https://shards.test/payload'}
              ],
              'index': '00' * 32,
            }))),
            200,
          );
        }
        return http.StreamedResponse(Stream.value(<int>[]), 503);
      });

      expect(
        () => downloadFileBytes(
          'https://drive.test',
          'https://network.test',
          'tok',
          mnemonic,
          'uuid',
          'bridge',
          'uid',
          httpClient: mock,
        ),
        throwsA(predicate((e) => e.toString().contains('503'))),
      );
    });
  });
}
