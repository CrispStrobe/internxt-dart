// Tests for the bounded-memory DISK download path (download.dart):
// downloadRangedToFile + the incremental streaming decryptor.
//
// Unlike downloadRangedToMemory (which allocates the whole file in RAM),
// downloadRangedToFile writes each decrypted range positionally into a
// RandomAccessFile, so peak RAM is bounded by the in-flight ranges, matching
// the Python CLI's disk-streaming ranged download. These hermetic tests install
// a MockClient via runWithClient and use a real temp file (cross-platform via
// Directory.systemTemp). They assert:
//
//   - a ranged disk fetch writes the exact plaintext byte-for-byte
//   - peak ranges in flight <= the worker pool size (bounded)
//   - ranges completing out of order still land at the right offsets
//   - a 200 (Range-ignored) probe returns false so the caller falls back
//   - a mid-flight 200 returns false (no throw) so the caller falls back
//   - the incremental streaming decryptor matches a one-shot decrypt

import 'dart:convert';
import 'dart:io';
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

/// Run [body] with a fresh temp file, always cleaning it up afterwards.
Future<T> _withTempFile<T>(Future<T> Function(File file) body) async {
  final dir = Directory.systemTemp.createTempSync('inxt_rdtd_');
  try {
    return await body(File('${dir.path}/out.bin'));
  } finally {
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  }
}

void main() {
  setUp(() {
    MemoryGate.resetForTesting();
    memoryGateOverride = 64 * 1024 * 1024 * 1024;
  });
  tearDown(() {
    MemoryGate.resetForTesting();
    memoryGateOverride = null;
  });

  test('ranged disk fetch writes the exact plaintext', () async {
    final plaintext = _randomish(80000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    final obs = _Obs();
    await _withTempFile((file) async {
      final raf = await file.open(mode: FileMode.write);
      final ok = await http.runWithClient(
        () => inxt_download.downloadRangedToFile('https://s3/get',
            plaintext.length, _mnemonic, _bucket, indexHex, raf,
            chunkWorkers: 3, partSize: 10000),
        () => _mock(ciphertext, delayMs: 5, partSize: 10000, obs: obs),
      );
      await raf.close();
      expect(ok, isTrue);
      expect(obs.rangeGets, equals(8)); // 80k / 10k
      expect(file.readAsBytesSync(), equals(plaintext));
    });
  });

  test('peak ranges in flight <= worker pool (bounded RAM)', () async {
    final plaintext = _randomish(80000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    final obs = _Obs();
    await _withTempFile((file) async {
      final raf = await file.open(mode: FileMode.write);
      await http.runWithClient(
        () => inxt_download.downloadRangedToFile('https://s3/get',
            plaintext.length, _mnemonic, _bucket, indexHex, raf,
            chunkWorkers: 3, partSize: 10000),
        () => _mock(ciphertext, delayMs: 10, partSize: 10000, obs: obs),
      );
      await raf.close();
      expect(obs.peak, lessThanOrEqualTo(3));
      expect(obs.peak, greaterThanOrEqualTo(2)); // genuinely parallel
    });
  });

  test('out-of-order range completion lands at the right offsets', () async {
    final plaintext = _randomish(80000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    await _withTempFile((file) async {
      final raf = await file.open(mode: FileMode.write);
      final ok = await http.runWithClient(
        () => inxt_download.downloadRangedToFile('https://s3/get',
            plaintext.length, _mnemonic, _bucket, indexHex, raf,
            chunkWorkers: 4, partSize: 10000),
        () =>
            _mock(ciphertext, delayMs: 4, partSize: 10000, reverseDelay: true),
      );
      await raf.close();
      expect(ok, isTrue);
      expect(file.readAsBytesSync(), equals(plaintext));
    });
  });

  test('200 probe returns false (caller falls back)', () async {
    final plaintext = _randomish(50000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    await _withTempFile((file) async {
      final raf = await file.open(mode: FileMode.write);
      final ok = await http.runWithClient(
        () => inxt_download.downloadRangedToFile('https://s3/get',
            plaintext.length, _mnemonic, _bucket, indexHex, raf,
            chunkWorkers: 2, partSize: 10000),
        () => _mock(ciphertext, probeStatus: 200),
      );
      await raf.close();
      expect(ok, isFalse);
    });
  });

  test('mid-flight 200 returns false without throwing (caller falls back)',
      () async {
    final plaintext = _randomish(50000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    await _withTempFile((file) async {
      final raf = await file.open(mode: FileMode.write);
      final ok = await http.runWithClient(
        () => inxt_download.downloadRangedToFile('https://s3/get',
            plaintext.length, _mnemonic, _bucket, indexHex, raf,
            chunkWorkers: 2, partSize: 10000),
        () => _mock(ciphertext, probeStatus: 206, rangeStatus: 200),
      );
      await raf.close();
      expect(ok, isFalse);
    });
  });

  // End-to-end orchestrator: metadata GET + links GET + payload GET, all
  // intercepted via runWithClient, exercising the sequential streaming-to-disk
  // path (the default + the Range-unsupported fallback target).
  MockClient orchestratorMock(Uint8List ciphertext, String indexHex, int size) {
    return MockClient((req) async {
      final path = req.url.path;
      if (path.endsWith('/meta')) {
        return http.Response(
            jsonEncode({
              'size': size,
              'bucket': _bucket,
              'fileId': 'netfid',
              'plainName': 'doc',
              'type': 'bin',
            }),
            200);
      }
      if (path.endsWith('/info')) {
        return http.Response(
            jsonEncode({
              'shards': [
                {'url': 'https://shards.test/payload'}
              ],
              'index': indexHex,
            }),
            200);
      }
      if (req.url.toString() == 'https://shards.test/payload') {
        return http.Response.bytes(ciphertext, 200); // whole object (no Range)
      }
      throw StateError('unexpected ${req.url}');
    });
  }

  test('downloadFileToDisk (sequential) writes byte-exact to a file path',
      () async {
    inxt_download.rangedDownload = false;
    final plaintext = _randomish(5000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    await _withTempFile((file) async {
      final result = await http.runWithClient(
        () => inxt_download.downloadFileToDisk(
            'https://drive.test',
            'https://network.test',
            'token',
            _mnemonic,
            'file-uuid',
            file.path,
            'bridge',
            'uid'),
        () => orchestratorMock(ciphertext, indexHex, plaintext.length),
      );
      expect(file.readAsBytesSync(), equals(plaintext));
      expect(result['filename'], equals('doc.bin'));
      expect(result['size'], equals(plaintext.length));
    });
  });

  test('downloadFileToDisk into a directory appends the remote filename',
      () async {
    inxt_download.rangedDownload = false;
    final plaintext = _randomish(3000);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    final dir = Directory.systemTemp.createTempSync('inxt_rdtd_dir_');
    try {
      await http.runWithClient(
        () => inxt_download.downloadFileToDisk(
            'https://drive.test',
            'https://network.test',
            'token',
            _mnemonic,
            'file-uuid',
            dir.path,
            'bridge',
            'uid'),
        () => orchestratorMock(ciphertext, indexHex, plaintext.length),
      );
      final written = File('${dir.path}/doc.bin');
      expect(written.existsSync(), isTrue);
      expect(written.readAsBytesSync(), equals(plaintext));
    } finally {
      if (dir.existsSync()) dir.deleteSync(recursive: true);
    }
  });

  test('incremental streaming decryptor matches one-shot decrypt', () {
    final plaintext = _randomish(7003); // not a block multiple
    final (ciphertext, indexHex) = _encrypt(plaintext);
    final cipher = inxt_crypto.downloadDecryptor(_mnemonic, _bucket, indexHex);
    // Feed the ciphertext in uneven chunks; concatenated output must equal the
    // one-shot decrypt (keystream state persists across process() calls).
    final out = <int>[];
    var i = 0;
    for (final size in [1, 16, 100, 333, 17, 999]) {
      final end = (i + size < ciphertext.length) ? i + size : ciphertext.length;
      out.addAll(cipher.process(ciphertext.sublist(i, end)));
      i = end;
    }
    if (i < ciphertext.length)
      out.addAll(cipher.process(ciphertext.sublist(i)));
    expect(Uint8List.fromList(out), equals(plaintext));
  });

  test('downloadDecryptor at a non-zero aligned offset matches one-shot', () {
    final plaintext = _randomish(4096);
    final (ciphertext, indexHex) = _encrypt(plaintext);
    const off = 1024; // 16-byte aligned
    final cipher = inxt_crypto.downloadDecryptor(_mnemonic, _bucket, indexHex,
        offset: off);
    final streamed = cipher.process(ciphertext.sublist(off));
    expect(streamed, equals(plaintext.sublist(off)));
  });

  test('downloadDecryptor rejects a misaligned offset', () {
    expect(
      () => inxt_crypto.downloadDecryptor(_mnemonic, _bucket, '00' * 32,
          offset: 5),
      throwsArgumentError,
    );
  });
}
