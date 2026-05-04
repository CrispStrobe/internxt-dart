// Unit tests for the pure-function helpers on InternxtCLI.
//
// These don't touch the network — the CLI handlers as a whole are
// exercised by test/live_smoke_test.dart. This file pins the
// algorithmic primitives that decide *what* to do, separately from
// *executing* the work.

import 'package:test/test.dart';

import 'package:internxt_client/cli.dart';

void main() {
  group('InternxtCLI.formatMtime (Phase 7.8)', () {
    test('formats a full ISO timestamp to YYYY-MM-DD HH:MM', () {
      expect(InternxtCLI.formatMtime('2026-05-04T12:34:56.789Z'),
          equals('2026-05-04 12:34'));
    });

    test('handles ISO without milliseconds', () {
      expect(InternxtCLI.formatMtime('2026-05-04T12:34:56'),
          equals('2026-05-04 12:34'));
    });

    test('null gives a 16-wide blank', () {
      expect(InternxtCLI.formatMtime(null), equals(' ' * 16));
    });

    test('short / unparseable input is right-padded to 16 chars', () {
      expect(InternxtCLI.formatMtime('???').length, equals(16));
    });

    test('output width is exactly 16 (column alignment guarantee)', () {
      for (final input in <dynamic>[
        '2026-05-04T12:34:56.789Z',
        '2026-05-04T12:34:56',
        null,
        '???',
        '',
      ]) {
        expect(InternxtCLI.formatMtime(input).length, equals(16),
            reason: 'input=$input');
      }
    });
  });

  group('InternxtCLI.buildMovePlan (Phase 7.3)', () {
    Map<String, dynamic> _src(
        String srcPath, String type, String uuid, String leaf) {
      return {'srcPath': srcPath, 'type': type, 'uuid': uuid, 'leaf': leaf};
    }

    test('plain move: no conflicts, no already-in-target, all queued', () {
      final r = InternxtCLI.buildMovePlan(
        expanded: [
          _src('/Docs/a.txt', 'file', 'u1', 'a.txt'),
          _src('/Docs/b.txt', 'file', 'u2', 'b.txt'),
        ],
        targetExisting: const {},
        onConflict: 'skip',
        targetResolvedPath: '/Archive',
      );
      expect(r.plan, hasLength(2));
      expect(r.plan.every((e) => e['action'] == 'move'), isTrue);
      expect(r.skips, isEmpty);
    });

    test('skips items whose parent is already the target folder', () {
      final r = InternxtCLI.buildMovePlan(
        expanded: [
          _src('/Archive/already.txt', 'file', 'u1', 'already.txt'),
          _src('/Docs/move-me.txt', 'file', 'u2', 'move-me.txt'),
        ],
        targetExisting: const {},
        onConflict: 'skip',
        targetResolvedPath: '/Archive',
      );
      expect(r.plan, hasLength(1));
      expect(r.plan.first['leaf'], equals('move-me.txt'));
      expect(r.skips, hasLength(1));
      expect(r.skips.first['srcPath'], equals('/Archive/already.txt'));
      expect(r.skips.first['reason'], contains('already in target'));
    });

    test('onConflict=skip: target collisions become skips', () {
      final r = InternxtCLI.buildMovePlan(
        expanded: [
          _src('/Docs/a.txt', 'file', 'u1', 'a.txt'),
          _src('/Docs/b.txt', 'file', 'u2', 'b.txt'),
        ],
        targetExisting: {
          'a.txt': {'type': 'file', 'uuid': 'existing-a'},
        },
        onConflict: 'skip',
        targetResolvedPath: '/Archive',
      );
      expect(r.plan, hasLength(1));
      expect(r.plan.first['leaf'], equals('b.txt'));
      expect(r.skips, hasLength(1));
      expect(r.skips.first['reason'], contains('a.txt'));
    });

    test(
        'onConflict=overwrite: file collision -> overwrite plan with '
        'existingUuid', () {
      final r = InternxtCLI.buildMovePlan(
        expanded: [
          _src('/Docs/a.txt', 'file', 'u1', 'a.txt'),
        ],
        targetExisting: {
          'a.txt': {'type': 'file', 'uuid': 'existing-a'},
        },
        onConflict: 'overwrite',
        targetResolvedPath: '/Archive',
      );
      expect(r.plan, hasLength(1));
      expect(r.plan.first['action'], equals('overwrite'));
      expect(r.plan.first['existingUuid'], equals('existing-a'));
      expect(r.skips, isEmpty);
    });

    test('onConflict=overwrite: refuses to overwrite a folder at target', () {
      final r = InternxtCLI.buildMovePlan(
        expanded: [
          _src('/Docs/a.txt', 'file', 'u1', 'a.txt'),
        ],
        targetExisting: {
          'a.txt': {'type': 'folder', 'uuid': 'existing-folder'},
        },
        onConflict: 'overwrite',
        targetResolvedPath: '/Archive',
      );
      expect(r.plan, isEmpty);
      expect(r.skips, hasLength(1));
      expect(r.skips.first['reason'],
          contains('refusing to overwrite folder at target'));
    });

    test(
        'mixed: some plain, some skip-already, some skip-conflict, some '
        'overwrite', () {
      final r = InternxtCLI.buildMovePlan(
        expanded: [
          _src('/Archive/in-target.txt', 'file', 'u0', 'in-target.txt'),
          _src('/Docs/plain.txt', 'file', 'u1', 'plain.txt'),
          _src('/Docs/conflict.txt', 'file', 'u2', 'conflict.txt'),
          _src('/Docs/replace.txt', 'file', 'u3', 'replace.txt'),
        ],
        targetExisting: {
          'conflict.txt': {'type': 'file', 'uuid': 'old-conflict'},
          'replace.txt': {'type': 'file', 'uuid': 'old-replace'},
        },
        // skip handles `conflict.txt`; replace.txt is overwritten only
        // when policy=overwrite. With policy=skip both collide & skip.
        onConflict: 'skip',
        targetResolvedPath: '/Archive',
      );
      expect(r.plan, hasLength(1));
      expect(r.plan.first['leaf'], equals('plain.txt'));
      // 1 already-in-target + 2 conflict skips
      expect(r.skips, hasLength(3));
    });

    test('source path at root: srcParent normalized to /', () {
      // When srcPath = "/foo.txt", lastIndexOf('/') == 0; we want
      // srcParent to be "/" (not ""), so a target_resolved_path of
      // "/" causes the no-op skip.
      final r = InternxtCLI.buildMovePlan(
        expanded: [
          _src('/foo.txt', 'file', 'u1', 'foo.txt'),
        ],
        targetExisting: const {},
        onConflict: 'skip',
        targetResolvedPath: '/',
      );
      expect(r.plan, isEmpty);
      expect(r.skips, hasLength(1));
      expect(r.skips.first['reason'], contains('already in target'));
    });
  });
}
