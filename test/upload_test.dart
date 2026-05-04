// Unit tests for upload.dart's testable primitives:
//   - MemoryGate (Phase 7.1)
//   - runBoundedPool (Phase 7.2)
//
// These cover the load-bearing concurrency machinery of the upload
// pipeline. They don't touch the network — the upload pipeline as a
// whole is exercised by test/live_smoke_test.dart.

import 'dart:async';

import 'package:test/test.dart';

import 'package:internxt_client/upload.dart';

void main() {
  group('MemoryGate (Phase 7.1)', () {
    setUp(() {
      MemoryGate.resetForTesting();
      memoryGateOverride = null;
    });

    tearDown(() {
      MemoryGate.resetForTesting();
      memoryGateOverride = null;
    });

    test('acquire passes through when budget is plentiful', () async {
      // 8 GB available, 1 GB safety margin → 7 GB headroom.
      memoryGateOverride = 8 * 1024 * 1024 * 1024;
      await MemoryGate.acquire(1 * 1024 * 1024 * 1024);
      expect(MemoryGate.currentReserved, equals(1 * 1024 * 1024 * 1024));
      MemoryGate.release(1 * 1024 * 1024 * 1024);
      expect(MemoryGate.currentReserved, equals(0));
    });

    test('release accumulates correctly across multiple acquires', () async {
      memoryGateOverride = 8 * 1024 * 1024 * 1024;
      await MemoryGate.acquire(100);
      await MemoryGate.acquire(200);
      await MemoryGate.acquire(300);
      expect(MemoryGate.currentReserved, equals(600));
      MemoryGate.release(100);
      expect(MemoryGate.currentReserved, equals(500));
      MemoryGate.release(500);
      expect(MemoryGate.currentReserved, equals(0));
    });

    test('release clamps at zero on under-flow', () {
      MemoryGate.release(10000);
      expect(MemoryGate.currentReserved, equals(0));
    });

    test('deadlock-avoidance: lets one through even with no headroom',
        () async {
      // Simulate a tiny machine: 1 GB available, safety margin 1 GB,
      // so headroom is 0. Even though `need` exceeds headroom, we
      // let one upload through because no other reservation is active.
      memoryGateOverride = 1 * 1024 * 1024 * 1024;
      await MemoryGate.acquire(2 * 1024 * 1024 * 1024)
          .timeout(const Duration(seconds: 2));
      expect(MemoryGate.currentReserved, equals(2 * 1024 * 1024 * 1024));
      MemoryGate.release(2 * 1024 * 1024 * 1024);
    });

    test('second acquirer waits when budget is consumed', () async {
      // 4 GB available - 1 GB safety = 3 GB headroom. First acquire
      // takes 2 GB (leaving 1 GB). Second wants 2 GB but can't fit:
      // 2 > 3 - 2 = 1. AND _reserved > 0 (deadlock-avoidance branch
      // doesn't apply). So second blocks.
      memoryGateOverride = 4 * 1024 * 1024 * 1024;
      await MemoryGate.acquire(2 * 1024 * 1024 * 1024);
      expect(MemoryGate.currentReserved, equals(2 * 1024 * 1024 * 1024));

      // Kick off the second acquire; it should park.
      var secondCompleted = false;
      final secondFuture = MemoryGate.acquire(2 * 1024 * 1024 * 1024).then((_) {
        secondCompleted = true;
      });

      // Yield a few times to let `acquire` install its waiter.
      for (var i = 0; i < 5; i++) {
        await Future<void>.delayed(Duration.zero);
      }

      expect(secondCompleted, isFalse,
          reason: 'second acquire should be parked behind the first');
      expect(MemoryGate.waiterCount, equals(1));

      // Release the first; the second should now succeed.
      MemoryGate.release(2 * 1024 * 1024 * 1024);
      await secondFuture.timeout(const Duration(seconds: 2));
      expect(secondCompleted, isTrue);

      MemoryGate.release(2 * 1024 * 1024 * 1024);
    });

    test('release wakes parked waiters', () async {
      memoryGateOverride = 4 * 1024 * 1024 * 1024;
      await MemoryGate.acquire(2 * 1024 * 1024 * 1024); // first

      // Two waiters parked behind the first; both want 2 GB but only
      // one can fit at a time after release.
      final waiter1Done = Completer<void>();
      final waiter2Done = Completer<void>();
      // ignore: unawaited_futures
      MemoryGate.acquire(2 * 1024 * 1024 * 1024).then((_) {
        waiter1Done.complete();
      });
      // ignore: unawaited_futures
      MemoryGate.acquire(2 * 1024 * 1024 * 1024).then((_) {
        waiter2Done.complete();
      });

      // Let waiters install themselves.
      for (var i = 0; i < 5; i++) {
        await Future<void>.delayed(Duration.zero);
      }
      expect(MemoryGate.waiterCount, greaterThanOrEqualTo(1));

      // Release first — wakes both waiters; only one will succeed
      // and the other re-parks. We only check that *at least one*
      // wakes up.
      MemoryGate.release(2 * 1024 * 1024 * 1024);
      await waiter1Done.future.timeout(const Duration(seconds: 2));

      // Drain the rest of the chain.
      MemoryGate.release(2 * 1024 * 1024 * 1024);
      await waiter2Done.future.timeout(const Duration(seconds: 2));
    });
  });

  group('Size limit + dynamic timeout (Phase 7.9)', () {
    test('maxFileSizeBytes is exactly 20 GB', () {
      expect(maxFileSizeBytes, equals(20 * 1024 * 1024 * 1024));
    });

    test('uploadTimeoutForSize: floor of 5 min for tiny files', () {
      // 1 KB at 100 KB/s → 0s, plus 60s headroom = 60s. But the
      // floor is 300s + 60s = 360s.
      expect(uploadTimeoutForSize(1024).inSeconds, equals(360));
    });

    test('uploadTimeoutForSize: scales linearly past the floor', () {
      // 100 MB at 100 KB/s → 1024 sec, plus 60s = 1084s.
      expect(uploadTimeoutForSize(100 * 1024 * 1024).inSeconds, equals(1084));
    });

    test('uploadTimeoutForSize: 1 GB → ~3 hours', () {
      // 1 GB at 100 KB/s → ~10240 sec, plus 60s. The point is the
      // timeout is generous — slow uploads don't trip it
      // prematurely.
      expect(uploadTimeoutForSize(1 * 1024 * 1024 * 1024).inSeconds,
          greaterThan(10000));
    });

    test('uploadTimeoutForSize: 20 GB still produces a finite duration', () {
      expect(uploadTimeoutForSize(maxFileSizeBytes).inSeconds, greaterThan(0));
    });
  });

  group('CancellationToken (Phase 7.7)', () {
    test('starts uncancelled', () {
      final t = CancellationToken();
      expect(t.isCancelled, isFalse);
    });

    test('cancel() flips the flag', () {
      final t = CancellationToken();
      t.cancel();
      expect(t.isCancelled, isTrue);
    });

    test('cancel() is idempotent', () {
      final t = CancellationToken();
      t.cancel();
      t.cancel();
      t.cancel();
      expect(t.isCancelled, isTrue);
    });

    test('integrates with runBoundedPool: cancelled work returns early',
        () async {
      // Pattern that mirrors how upload()'s runOne uses the token:
      // each task checks the flag at the top and returns early if
      // cancelled.
      final t = CancellationToken();
      final completed = <int>[];
      final cancelled = <int>[];

      // Cancel after the first task completes. Subsequent tasks see
      // the flag and return early.
      await runBoundedPool<int>(
        List.generate(10, (i) => i),
        2, // small concurrency so cancellation is observable
        (i) async {
          if (t.isCancelled) {
            cancelled.add(i);
            return;
          }
          await Future<void>.delayed(const Duration(milliseconds: 10));
          completed.add(i);
          if (completed.length == 2) t.cancel();
        },
      );

      expect(completed.length, lessThan(10));
      expect(cancelled.length, greaterThan(0));
      expect(completed.length + cancelled.length, equals(10));
    });
  });

  group('ProgressLine (Phase 7.6)', () {
    test('first call always writes', () {
      final writes = <String>[];
      final pl = ProgressLine(writer: writes.add);
      pl.update('hello');
      expect(writes, equals(['\rhello']));
    });

    test('throttles subsequent calls within the interval', () {
      final writes = <String>[];
      final pl = ProgressLine(writer: writes.add);
      pl.update('one');
      // Synchronous follow-up: well within 200 ms — should be dropped.
      pl.update('two');
      pl.update('three');
      expect(writes, equals(['\rone']));
    });

    test('force=true bypasses the throttle', () {
      final writes = <String>[];
      final pl = ProgressLine(writer: writes.add);
      pl.update('one');
      pl.update('two', force: true);
      expect(writes, equals(['\rone', '\rtwo']));
    });

    test('finish writes the final line + newline', () {
      final writes = <String>[];
      final pl = ProgressLine(writer: writes.add);
      pl.update('mid');
      pl.finish('done');
      expect(writes, equals(['\rmid', '\rdone', '\n']));
    });

    test('finish with no final line just writes newline', () {
      final writes = <String>[];
      final pl = ProgressLine(writer: writes.add);
      pl.update('mid');
      pl.finish();
      expect(writes, equals(['\rmid', '\n']));
    });

    test('writes again after the interval elapses', () async {
      final writes = <String>[];
      final pl = ProgressLine(writer: writes.add);
      pl.update('one');
      // Wait past the 200 ms interval.
      await Future<void>.delayed(const Duration(milliseconds: 250));
      pl.update('two');
      expect(writes, equals(['\rone', '\rtwo']));
    });
  });

  group('shouldSkipForSizeMatch (Phase 7.4)', () {
    test('returns true: matching size, onConflict=skip', () {
      final r = shouldSkipForSizeMatch(
        remoteFilesInParent: {'a.txt': 1024},
        filename: 'a.txt',
        localSize: 1024,
        onConflict: 'skip',
      );
      expect(r, isTrue);
    });

    test('returns false: size mismatch (re-upload needed)', () {
      final r = shouldSkipForSizeMatch(
        remoteFilesInParent: {'a.txt': 1024},
        filename: 'a.txt',
        localSize: 2048,
        onConflict: 'skip',
      );
      expect(r, isFalse);
    });

    test('returns false: file not in remote (new upload)', () {
      final r = shouldSkipForSizeMatch(
        remoteFilesInParent: {'other.txt': 1024},
        filename: 'a.txt',
        localSize: 1024,
        onConflict: 'skip',
      );
      expect(r, isFalse);
    });

    test('returns false: onConflict != skip (overwrite forces re-upload)', () {
      final r = shouldSkipForSizeMatch(
        remoteFilesInParent: {'a.txt': 1024},
        filename: 'a.txt',
        localSize: 1024,
        onConflict: 'overwrite',
      );
      expect(r, isFalse);
    });

    test('returns false: parent not in pre-scan (no remote map)', () {
      final r = shouldSkipForSizeMatch(
        remoteFilesInParent: null,
        filename: 'a.txt',
        localSize: 1024,
        onConflict: 'skip',
      );
      expect(r, isFalse);
    });

    test('returns false: remote size 0 is never a confident match', () {
      final r = shouldSkipForSizeMatch(
        remoteFilesInParent: {'a.txt': 0},
        filename: 'a.txt',
        localSize: 0,
        onConflict: 'skip',
      );
      expect(r, isFalse);
    });
  });

  group('runBoundedPool (Phase 7.2)', () {
    test('runs all tasks exactly once', () async {
      final ran = <int>[];
      await runBoundedPool<int>(
        List.generate(20, (i) => i),
        4,
        (i) async {
          ran.add(i);
        },
      );
      ran.sort();
      expect(ran, equals(List.generate(20, (i) => i)));
    });

    test('respects the concurrency cap (peak in-flight ≤ N)', () async {
      var inFlight = 0;
      var peak = 0;
      final completer = Completer<void>();
      final tasks = List.generate(10, (i) => i);

      // Each task increments in-flight, awaits a brief delay, then
      // decrements. Peak should never exceed the configured cap.
      const cap = 3;
      await runBoundedPool<int>(
        tasks,
        cap,
        (i) async {
          inFlight++;
          if (inFlight > peak) peak = inFlight;
          await Future<void>.delayed(const Duration(milliseconds: 5));
          inFlight--;
        },
      );

      expect(peak, lessThanOrEqualTo(cap),
          reason: 'peak in-flight $peak exceeded cap $cap');
      expect(peak, greaterThan(1),
          reason: 'concurrency=$cap should produce >1 in-flight at some point');
      completer.complete();
    });

    test('clamps concurrency < 1 up to 1', () async {
      // Behaves as sequential.
      final order = <int>[];
      await runBoundedPool<int>(
        [1, 2, 3, 4],
        0,
        (i) async {
          order.add(i);
          await Future<void>.delayed(Duration.zero);
        },
      );
      // With concurrency=1, completion order matches submission order
      // because tasks run sequentially.
      expect(order, equals([1, 2, 3, 4]));
    });

    test('completes immediately on empty input', () async {
      var ran = false;
      await runBoundedPool<int>(<int>[], 4, (_) async {
        ran = true;
      });
      expect(ran, isFalse);
    });

    test('a task throwing does not stop other in-flight tasks', () async {
      // The pool surfaces the error, but the in-flight tasks at the
      // moment of the throw still complete (Dart Futures aren't
      // cancellable). Tasks scheduled AFTER the throw don't run.
      final completed = <int>[];
      try {
        await runBoundedPool<int>(
          [1, 2, 3],
          2,
          (i) async {
            await Future<void>.delayed(const Duration(milliseconds: 5));
            if (i == 2) throw StateError('boom');
            completed.add(i);
          },
        );
        fail('expected runBoundedPool to surface the worker exception');
      } on StateError catch (e) {
        expect(e.message, equals('boom'));
      }
      // Task 1 (started concurrently with 2) should have completed.
      expect(completed, contains(1));
    });
  });
}
