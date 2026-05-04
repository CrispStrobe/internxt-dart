// Unit tests for cache.dart's primitives + the TTL constant.
//
// Cache mutators (invalidateCache, clearParentCache) are exercised
// indirectly by every live test. This file pins the TTL value as a
// regression marker (Phase 7.5 bumped it 10m -> 1h) and the basic
// invalidate/clear behavior.

import 'package:test/test.dart';

import 'package:internxt_client/cache.dart';

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

  group('clearParentCache (Phase 3 regression marker)', () {
    // The Phase 3 bug: clearParentCache used `folderId` (legacy
    // integer) when the cache is keyed by `folderUuid` (string).
    // Mutating ops therefore failed to invalidate, and the next
    // `ls` returned a stale listing. These tests pin the
    // string-UUID keying so a future edit can't quietly regress.
    test('file: prefers folderUuid over folderId, drops parent', () async {
      final folderCache = <String, CacheEntry>{
        'parent-uuid':
            CacheEntry(items: const ['stale'], timestamp: DateTime.now()),
      };
      final fileCache = <String, CacheEntry>{
        'parent-uuid':
            CacheEntry(items: const ['stale'], timestamp: DateTime.now()),
      };
      await clearParentCache(
        folderCache,
        fileCache,
        'item-uuid',
        'file',
        (uuid) async => {
          'folderUuid': 'parent-uuid',
          // folderId is the legacy integer field. Must be ignored.
          'folderId': 12345,
        },
        (_) async =>
            throw StateError('folder fetcher must not be called for files'),
      );
      expect(folderCache.containsKey('parent-uuid'), isFalse,
          reason: 'parent listing should be dropped');
      expect(fileCache.containsKey('parent-uuid'), isFalse,
          reason: 'parent file listing should be dropped');
    });

    test('file: falls back to folderId when folderUuid is absent', () async {
      // Defensive — older API responses might omit folderUuid. The
      // toString() coercion is what saves us; without it we'd hit
      // the type cast and silently no-op.
      final folderCache = <String, CacheEntry>{
        '99': CacheEntry(items: const ['x'], timestamp: DateTime.now()),
      };
      final fileCache = <String, CacheEntry>{};
      await clearParentCache(
        folderCache,
        fileCache,
        'item-uuid',
        'file',
        (_) async => {'folderId': 99},
        (_) async => throw StateError('unused'),
      );
      expect(folderCache.containsKey('99'), isFalse);
    });

    test('folder: prefers parentUuid over parentId', () async {
      final folderCache = <String, CacheEntry>{
        'gp-uuid':
            CacheEntry(items: const ['stale'], timestamp: DateTime.now()),
      };
      final fileCache = <String, CacheEntry>{};
      await clearParentCache(
        folderCache,
        fileCache,
        'folder-uuid',
        'folder',
        (_) async =>
            throw StateError('file fetcher must not be called for folders'),
        (_) async => {
          'parentUuid': 'gp-uuid',
          'parentId': 42,
        },
      );
      expect(folderCache.containsKey('gp-uuid'), isFalse);
    });

    test('swallows fetcher errors (best-effort invalidation)', () async {
      // The contract: a transient metadata-fetch failure shouldn't
      // crash the user-facing op; cache will expire on its own.
      final folderCache = <String, CacheEntry>{
        'parent-uuid':
            CacheEntry(items: const ['x'], timestamp: DateTime.now()),
      };
      final fileCache = <String, CacheEntry>{};
      await clearParentCache(
        folderCache,
        fileCache,
        'item-uuid',
        'file',
        (_) async => throw Exception('network down'),
        (_) async => throw StateError('unused'),
      );
      // Cache untouched, but no rethrow.
      expect(folderCache.containsKey('parent-uuid'), isTrue);
    });
  });
}
