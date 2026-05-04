// Unit tests for cache.dart's primitives + the TTL constant.
//
// Cache mutators (invalidateCache, clearParentCache) are exercised
// indirectly by every live test. This file pins the TTL value as a
// regression marker (Phase 7.5 bumped it 10m -> 1h) and the basic
// invalidate/clear behavior.

import 'package:test/test.dart';

import '../cache.dart';

void main() {
  group('cacheDuration (Phase 7.5 regression marker)', () {
    test('cacheDuration is 1 hour', () {
      // Pinned: Phase 7.5 bumped this from 10 minutes -> 1 hour to
      // match the Python sibling. If anyone changes it back, this
      // test will fire and remind them to also revert the
      // associated PLAN.md / HISTORY.md entries.
      expect(cacheDuration, equals(const Duration(hours: 1)));
    });
  });

  group('invalidateCache', () {
    test('removes entry from both folder + file caches', () {
      final folderCache = <String, CacheEntry>{
        'a': CacheEntry(items: ['x'], timestamp: DateTime.now()),
        'b': CacheEntry(items: ['y'], timestamp: DateTime.now()),
      };
      final fileCache = <String, CacheEntry>{
        'a': CacheEntry(items: ['z'], timestamp: DateTime.now()),
      };
      invalidateCache(folderCache, fileCache, 'a');
      expect(folderCache.containsKey('a'), isFalse);
      expect(folderCache.containsKey('b'), isTrue);
      expect(fileCache.containsKey('a'), isFalse);
    });

    test('no-op for missing key', () {
      final folderCache = <String, CacheEntry>{};
      final fileCache = <String, CacheEntry>{};
      // Should not throw.
      invalidateCache(folderCache, fileCache, 'no-such-uuid');
      expect(folderCache, isEmpty);
      expect(fileCache, isEmpty);
    });
  });
}
