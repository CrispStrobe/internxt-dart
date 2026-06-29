// Tests for Step B — parallel ranged downloads (download.dart).
//
// downloadRangedToMemory splits a presigned GET into N 16-byte-aligned ranges
// fetched concurrently and CTR-decrypts each at its offset (crypto's seekable
// decryptStreamAt is covered in crypto_test.dart). These hermetic tests install
// a MockClient via runWithClient (which http.get honours) and assert:
//
//   - a ranged fetch reassembles to the exact plaintext
//   - peak ranges in flight <= the worker pool size
//   - ranges completing out of order still reassemble byte-identically
//   - a 200 (Range-ignored) probe returns null so the caller falls back
//   - a mid-flight 200 surfaces as an exception (triggers the fallback)

import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import 'package:internxt_client/crypto.dart' as inxt_crypto;
import 'package:internxt_client/download.dart' as inxt_download;
import 'package:internxt_client/upload.dart';

const _mnemonic = 'abandon abandon abandon abandon abandon abandon '
    'abandon abandon abandon abandon abandon about';
const _bucket = '000000000000000000000000';

class _Obs {
  int inFlight = 0;
  int peak = 0;
  int rangeGets = 0;
}

MockClient _mock(
  Uint8List ciphertext, {
  int probeStatus = 206,
  int rangeStatus = 206,
  int delayMs = 0,
  bool reverseDelay = false,
  int partSize = 0,
  _Obs? obs,
}) {
  return MockClient((req) async {
    final range = req.headers['range'] ?? req.headers['Range'] ?? '';
    final m = RegExp(r'bytes=(\d+)-(\d+)').firstMatch(range);
    final start = int.parse(m!.group(1)!);
    final end = int.parse(m.group(2)!);
    if (start == 0 && end == 0) {
      return http.Response.bytes(ciphertext.sublist(0, 1), probeStatus);
    }
    obs?.inFlight++;
    if (obs != null && obs.inFlight > obs.peak) obs.peak = obs.inFlight;
    try {
      if (rangeStatus != 206) {
        return http.Response.bytes(ciphertext, rangeStatus); // whole object
      }
      if (delayMs > 0) {
        final n = partSize > 0 ? (start ~/ partSize) : 0;
        final factor = reverseDelay ? (n + 1) : 1;
        await Future<void>.delayed(Duration(milliseconds: delayMs * factor));
      }
      obs?.rangeGets++;
      return http.Response.bytes(ciphertext.sublist(start, end + 1), 206);
    } finally {
      obs?.inFlight--;
    }
  });
}

(Uint8List, String) _encrypt(Uint8List plaintext) {
  final enc = inxt_crypto.encryptStream(plaintext, _mnemonic, _bucket);
  return (enc['data'] as Uint8List, enc['index'] as String);
}

Uint8List _randomish(int n) =>
    Uint8List.fromList(List<int>.generate(n, (i) => (i * 31 + 7) & 0xff));

void main() {
  setUp(() {
    MemoryGate.resetForTesting();
    // Make the gate instant (its macOS probe shells out synchronously and would
    // serialise the ranges, masking the network concurrency under test).
    memoryGateOverride = 64 * 1024 * 1024 * 1024;
  });
  tearDown(() {
    MemoryGate.resetForTesting();
    memoryGateOverride = null;
  });

  test('ranged fetch reassembles to the exact plaintext', () async {
    final plaintext = _randomish(80000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    final obs = _Obs();
    final out = await http.runWithClient(
      () => inxt_download.downloadRangedToMemory(
          'https://s3/get', plaintext.length, _mnemonic, _bucket, indexHex,
          chunkWorkers: 3, partSize: 10000),
      () => _mock(ciphertext, delayMs: 5, partSize: 10000, obs: obs),
    );
    expect(out, isNotNull);
    expect(out, equals(plaintext));
    expect(obs.rangeGets, equals(8)); // 80k / 10k
  });

  test('peak ranges in flight <= worker pool', () async {
    final plaintext = _randomish(80000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    final obs = _Obs();
    await http.runWithClient(
      () => inxt_download.downloadRangedToMemory(
          'https://s3/get', plaintext.length, _mnemonic, _bucket, indexHex,
          chunkWorkers: 3, partSize: 10000),
      () => _mock(ciphertext, delayMs: 10, partSize: 10000, obs: obs),
    );
    expect(obs.peak, lessThanOrEqualTo(3));
    expect(obs.peak, greaterThanOrEqualTo(2)); // genuinely parallel
  });

  test('out-of-order range completion still reassembles byte-identically',
      () async {
    final plaintext = _randomish(80000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    final out = await http.runWithClient(
      () => inxt_download.downloadRangedToMemory(
          'https://s3/get', plaintext.length, _mnemonic, _bucket, indexHex,
          chunkWorkers: 4, partSize: 10000),
      () => _mock(ciphertext, delayMs: 4, partSize: 10000, reverseDelay: true),
    );
    expect(out, equals(plaintext));
  });

  test('200 probe returns null (caller falls back to single GET)', () async {
    final plaintext = _randomish(50000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    final out = await http.runWithClient(
      () => inxt_download.downloadRangedToMemory(
          'https://s3/get', plaintext.length, _mnemonic, _bucket, indexHex,
          chunkWorkers: 2, partSize: 10000),
      () => _mock(ciphertext, probeStatus: 200),
    );
    expect(out, isNull);
  });

  test('mid-flight 200 surfaces as an exception (triggers fallback)', () async {
    final plaintext = _randomish(50000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    await expectLater(
      http.runWithClient(
        () => inxt_download.downloadRangedToMemory(
            'https://s3/get', plaintext.length, _mnemonic, _bucket, indexHex,
            chunkWorkers: 2, partSize: 10000),
        () => _mock(ciphertext, probeStatus: 206, rangeStatus: 200),
      ),
      throwsA(isA<Exception>()),
    );
  });
}
