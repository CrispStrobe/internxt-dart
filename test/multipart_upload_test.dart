// Tests for within-file multipart chunk concurrency (Step A).
//
// A single large file (ciphertext >= multipartMinSize) is uploaded with
// true S3 multipart: the continuous AES-CTR ciphertext is sliced into
// parts whose PUTs run in parallel through runBoundedPool + MemoryGate,
// while the crypto + content hash stay sequential. These hermetic tests
// drive `pushEncryptedShard` with a MockClient (installed via
// runWithClient, which both `makeRequest` and `http.Request.send` honor)
// and assert the four non-negotiable constraints:
//
//   1. SEQUENTIAL CRYPTO — the shard hash is sha256 over the WHOLE
//      ciphertext regardless of how the PUTs are split/ordered.
//   2. ORDER BY INDEX — the finish payload's `parts` is ordered by
//      PartNumber even when parts complete out of order.
//   3. BOUNDED IN FLIGHT — peak concurrent part PUTs <= chunkWorkers.
//   4. FAILURE — a failing part surfaces out of pushEncryptedShard.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import 'package:internxt_client/upload.dart';

/// Records what the mocked network observed during one run.
class _Capture {
  int? partsRequested;
  int inFlight = 0;
  int peakInFlight = 0;
  int chunkPuts = 0; // single-PUT (non-multipart) transfers
  Map<String, dynamic>? finishPayload;
  final List<String> partUrls = [];
}

/// Build a MockClient simulating the Internxt network + S3 for an upload.
///
/// [partDelayMs] makes each part PUT take time so concurrency is
/// observable; [reverseDelay] makes later parts finish first (out of
/// order); [failPart] (1-based PartNumber) makes that part PUT 500.
MockClient _mockNetwork(
  _Capture cap, {
  int partDelayMs = 0,
  bool reverseDelay = false,
  int? failPart,
}) {
  return MockClient((request) async {
    final url = request.url.toString();
    if (url.contains('/files/start')) {
      final parts = int.parse(request.url.queryParameters['multiparts'] ?? '1');
      cap.partsRequested = parts;
      if (parts > 1) {
        return http.Response(
          json.encode({
            'uploads': [
              {
                'uuid': 'net-uuid',
                'urls': [
                  for (var i = 0; i < parts; i++) 'https://s3.test/part/$i'
                ],
                'UploadId': 'UPID',
              }
            ]
          }),
          200,
        );
      }
      return http.Response(
        json.encode({
          'uploads': [
            {'uuid': 'net-uuid', 'url': 'https://s3.test/single'}
          ]
        }),
        200,
      );
    }
    if (url.contains('/files/finish')) {
      cap.finishPayload = json.decode(request.body) as Map<String, dynamic>;
      return http.Response(json.encode({'id': 'NETFILE'}), 200);
    }
    if (url.contains('/part/')) {
      final idx = int.parse(url.split('/').last);
      cap.partUrls.add(url);
      cap.inFlight++;
      if (cap.inFlight > cap.peakInFlight) cap.peakInFlight = cap.inFlight;
      try {
        if (failPart != null && idx + 1 == failPart) {
          return http.Response('boom', 500);
        }
        if (partDelayMs > 0) {
          final factor = reverseDelay ? (cap.partsRequested! - idx) : 1;
          await Future<void>.delayed(
              Duration(milliseconds: partDelayMs * factor));
        }
        return http.Response('', 200, headers: {'etag': '"etag-$idx"'});
      } finally {
        cap.inFlight--;
      }
    }
    if (url.contains('/single')) {
      cap.chunkPuts++;
      return http.Response('', 200);
    }
    return http.Response('unexpected: $url', 404);
  });
}

Future<_Capture> _run(
  Uint8List data, {
  required int partSize,
  required int multipartMin,
  int chunkWorkers = 4,
  int partDelayMs = 0,
  bool reverseDelay = false,
  int? failPart,
}) async {
  final cap = _Capture();
  final client = _mockNetwork(cap,
      partDelayMs: partDelayMs, reverseDelay: reverseDelay, failPart: failPart);
  await http.runWithClient(() async {
    await pushEncryptedShard(
      'https://network.test',
      '00' * 12,
      data,
      'aa' * 32, // fileIndexHex (unused by the mock)
      'bridge-user',
      'bridge-pass',
      'test-file',
      chunkWorkers: chunkWorkers,
      partSize: partSize,
      multipartMin: multipartMin,
    );
  }, () => client);
  return cap;
}

void main() {
  setUp(() {
    MemoryGate.resetForTesting();
    // Make the gate pass through instantly: the real probe shells out to
    // `vm_stat`/`sysctl` synchronously on macOS, which would serialize the
    // parts (the blocking probe is slower than the simulated PUT delay) and
    // mask the network concurrency we're trying to observe.
    memoryGateOverride = 64 * 1024 * 1024 * 1024; // 64 GB
  });
  tearDown(() {
    MemoryGate.resetForTesting();
    memoryGateOverride = null;
  });

  group('multipart branch + finish payload', () {
    test('large ciphertext requests multipart and builds the parts shard',
        () async {
      // 250 B, 100 B parts, 50 B floor -> 3 parts.
      final data = Uint8List.fromList(List.generate(250, (i) => i % 256));
      final cap = await _run(data, partSize: 100, multipartMin: 50);
      expect(cap.partsRequested, equals(3));
      expect(cap.chunkPuts, equals(0)); // multipart never uses the single PUT
      final shard = (cap.finishPayload!['shards'] as List)[0] as Map;
      expect(shard['uuid'], equals('net-uuid'));
      expect(shard['UploadId'], equals('UPID'));
      expect(
        shard['hash'],
        equals(crypto.sha256.convert(data).toString()),
      );
    });

    test('small ciphertext stays on the single-PUT path', () async {
      final data = Uint8List.fromList(List.generate(40, (i) => i % 256));
      final cap = await _run(data, partSize: 100, multipartMin: 50);
      expect(cap.partsRequested, equals(1));
      expect(cap.chunkPuts, equals(1));
      expect(cap.partUrls, isEmpty);
      final shard = (cap.finishPayload!['shards'] as List)[0] as Map;
      expect(shard.containsKey('UploadId'), isFalse);
      expect(shard.containsKey('parts'), isFalse);
    });
  });

  group('ORDER BY INDEX — manifest ordered regardless of completion', () {
    test('parts finishing out of order still yield PartNumber 1..N', () async {
      final data = Uint8List.fromList(List.generate(800, (i) => i % 256));
      final cap = await _run(data,
          partSize: 100,
          multipartMin: 50,
          chunkWorkers: 4,
          partDelayMs: 5,
          reverseDelay: true);
      final shard =
          (cap.finishPayload!['shards'] as List)[0] as Map<String, dynamic>;
      final parts = (shard['parts'] as List).cast<Map<String, dynamic>>();
      expect(parts.length, equals(8));
      for (var i = 0; i < parts.length; i++) {
        expect(parts[i]['PartNumber'], equals(i + 1));
        expect(parts[i]['ETag'], equals('etag-$i'));
      }
    });
  });

  group('BOUNDED IN FLIGHT — peak part PUTs <= chunkWorkers', () {
    test('peak concurrency respects the pool size', () async {
      final data = Uint8List.fromList(List.generate(800, (i) => i % 256));
      final cap = await _run(data,
          partSize: 100, multipartMin: 50, chunkWorkers: 3, partDelayMs: 10);
      expect(cap.partsRequested, equals(8));
      expect(cap.peakInFlight, lessThanOrEqualTo(3));
      expect(cap.peakInFlight, greaterThanOrEqualTo(2)); // genuinely parallel
    });

    test('chunkWorkers=1 is effectively serial', () async {
      final data = Uint8List.fromList(List.generate(500, (i) => i % 256));
      final cap = await _run(data,
          partSize: 100, multipartMin: 50, chunkWorkers: 1, partDelayMs: 4);
      expect(cap.peakInFlight, equals(1));
    });
  });

  group('FAILURE — failing part surfaces and gate drains', () {
    test('a 500 on one part throws out of pushEncryptedShard', () async {
      final data = Uint8List.fromList(List.generate(800, (i) => i % 256));
      await expectLater(
        _run(data,
            partSize: 100,
            multipartMin: 50,
            chunkWorkers: 4,
            partDelayMs: 2,
            failPart: 5),
        throwsA(isA<Exception>()),
      );
      // pushEncryptedShard does not gate per-part (the caller holds the
      // whole-file reservation), so nothing should ever be reserved here.
      expect(MemoryGate.currentReserved, equals(0));
    });
  });
}
