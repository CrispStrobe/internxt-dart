// Pure-function utility tests: formatSize and shouldIncludeFile.
//
// These have no I/O, no network, no auth state — just sanity checks
// on inputs and outputs. They run in milliseconds and catch off-by-one
// errors at the unit-boundary thresholds.

import 'package:test/test.dart';
import 'package:internxt_client/cli.dart';

InternxtClient _newClient() => InternxtClient(config: ConfigService());

void main() {
  group('formatSize', () {
    test('null -> N/A', () {
      expect(formatSize(null), equals('N/A'));
    });

    test('non-numeric, non-string -> N/A', () {
      expect(formatSize([1, 2, 3]), equals('N/A'));
      expect(formatSize({'a': 1}), equals('N/A'));
    });

    test('non-numeric string -> 0 B', () {
      // String "abc" parses to null, falls through to 0
      expect(formatSize('abc'), equals('0 B'));
    });

    test('numeric string -> formatted', () {
      expect(formatSize('1024'), equals('1.0 KB'));
    });

    test('exact 0 -> 0 B', () {
      expect(formatSize(0), equals('0 B'));
    });

    test('< 1 KB -> bytes', () {
      expect(formatSize(1), equals('1 B'));
      expect(formatSize(512), equals('512 B'));
      expect(formatSize(1023), equals('1023 B'));
    });

    test('1 KB threshold', () {
      expect(formatSize(1024), equals('1.0 KB'));
      expect(formatSize(2048), equals('2.0 KB'));
    });

    test('1 MB threshold', () {
      expect(formatSize(1024 * 1024), equals('1.0 MB'));
      expect(formatSize(5 * 1024 * 1024), equals('5.0 MB'));
    });

    test('1 GB threshold', () {
      expect(formatSize(1024 * 1024 * 1024), equals('1.0 GB'));
      expect(formatSize(3 * 1024 * 1024 * 1024), equals('3.0 GB'));
    });

    test('precision is one decimal', () {
      // 1.5 KB
      expect(formatSize(1024 + 512), equals('1.5 KB'));
      // 1.5 MB
      expect(formatSize(1024 * 1024 + 512 * 1024), equals('1.5 MB'));
    });
  });

  group('shouldIncludeFile (glob filtering)', () {
    test('no patterns includes everything', () {
      final c = _newClient();
      expect(c.shouldIncludeFile('any.xyz', [], []), isTrue);
    });

    test('include pattern matches', () {
      final c = _newClient();
      expect(c.shouldIncludeFile('photo.jpg', ['*.jpg'], []), isTrue);
      expect(c.shouldIncludeFile('photo.png', ['*.jpg'], []), isFalse);
    });

    test('exclude pattern excludes', () {
      final c = _newClient();
      expect(c.shouldIncludeFile('temp.tmp', [], ['*.tmp']), isFalse);
      expect(c.shouldIncludeFile('keep.txt', [], ['*.tmp']), isTrue);
    });

    test('exclude takes priority when both match', () {
      final c = _newClient();
      // README.md matches *.md (include) but also matches readme.* (exclude)
      expect(
        c.shouldIncludeFile('README.md', ['*.md'], ['readme.*']),
        // Glob matching is case-sensitive: README.md does NOT match readme.*
        // so this should be included
        isTrue,
      );
      // Test the case-sensitive case where both genuinely match
      expect(
        c.shouldIncludeFile('temp.log', ['*.log'], ['temp.*']),
        isFalse,
      );
    });

    test('multiple include patterns: any-of semantics', () {
      final c = _newClient();
      expect(c.shouldIncludeFile('x.jpg', ['*.jpg', '*.png'], []), isTrue);
      expect(c.shouldIncludeFile('x.png', ['*.jpg', '*.png'], []), isTrue);
      expect(c.shouldIncludeFile('x.gif', ['*.jpg', '*.png'], []), isFalse);
    });

    test('multiple exclude patterns: any-of semantics', () {
      final c = _newClient();
      expect(c.shouldIncludeFile('x.tmp', [], ['*.tmp', '*.bak']), isFalse);
      expect(c.shouldIncludeFile('x.bak', [], ['*.tmp', '*.bak']), isFalse);
      expect(c.shouldIncludeFile('x.txt', [], ['*.tmp', '*.bak']), isTrue);
    });

    test('empty include list does not block (only exclude does)', () {
      // include=[] means "no include filter", not "exclude all"
      final c = _newClient();
      expect(c.shouldIncludeFile('whatever.xyz', [], []), isTrue);
    });
  });
}
