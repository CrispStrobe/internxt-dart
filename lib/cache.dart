// Folder/file listing cache primitives.
//
// Extracted from cli.dart in Phase 4. The cache *storage* (the two
// `Map<String, CacheEntry>` instances) still lives on `InternxtClient`
// because its lifetime is tied to a logged-in session; only the entry
// shape, the TTL constant, and the pure mutator functions live here.
//
// This is the module the cache-coherency bug from Phase 3 lived in
// (folderId-vs-folderUuid keying — see HISTORY.md). The
// `clearParentCache` doc comment pins the lesson so a future edit
// can't quietly reintroduce it.
//
// Coverage is currently end-to-end via test/live_smoke_test.dart;
// targeted unit tests for the cache layer are tracked in PLAN.md.

/// A single cached folder-listing or file-listing result.
///
/// `items` is intentionally `dynamic` to mirror the JSON shape returned
/// by the listing endpoints; callers cast it back to
/// `List<Map<String, dynamic>>` at the boundary.
class CacheEntry {
  final dynamic items;
  final DateTime timestamp;
  CacheEntry({required this.items, required this.timestamp});
}

/// How long a [CacheEntry] is considered fresh before it must be
/// refetched from the backend.
///
/// Phase 7.5 bumped this from 10 minutes to 1 hour to match the
/// Python sibling. The trade-off: longer batch operations don't
/// hit cache misses mid-run, at the cost of a stale read window if
/// the user (or another client) mutates the same folder externally.
/// Mutating ops within this client invalidate the cache eagerly via
/// `clearParentCache` / `invalidateCache`, so the staleness only
/// affects external mutations.
const Duration cacheDuration = Duration(hours: 1);

/// Drops both the folder-listing and the file-listing entry for
/// [folderUuid]. Cheap and idempotent — calling it on a UUID that
/// was never cached is a no-op.
void invalidateCache(
  Map<String, CacheEntry> folderCache,
  Map<String, CacheEntry> fileCache,
  String folderUuid,
) {
  folderCache.remove(folderUuid);
  fileCache.remove(folderUuid);
}

/// Resolves the parent folder of an item and invalidates that
/// parent's listings so the next `list` call hits the network.
///
/// Used after every mutating operation (trash / move / rename / copy
/// / replace) so subsequent path resolutions see the new state.
///
/// IMPORTANT: prefers `folderUuid` (string UUID) over `folderId`
/// (legacy integer). The cache is keyed by string UUID; using the
/// integer silently fails to invalidate. Same for `parentUuid`
/// vs. `parentId`. This was the Phase 3 cache-coherency bug — only
/// catchable with live integration tests against the real backend.
///
/// Errors are swallowed by design: the cache will expire on its own
/// after [cacheDuration], so a transient metadata-fetch failure
/// degrades to a 10-minute window of staleness rather than crashing
/// the user-visible operation that triggered the invalidation.
Future<void> clearParentCache(
  Map<String, CacheEntry> folderCache,
  Map<String, CacheEntry> fileCache,
  String itemUuid,
  String itemType,
  Future<Map<String, dynamic>> Function(String) getFileMetadata,
  Future<Map<String, dynamic>> Function(String) getFolderMetadata,
) async {
  try {
    String? parentUuid;
    if (itemType == 'file') {
      final metadata = await getFileMetadata(itemUuid);
      parentUuid = (metadata['folderUuid'] as String?) ??
          metadata['folderId']?.toString();
    } else {
      final metadata = await getFolderMetadata(itemUuid);
      parentUuid = (metadata['parentUuid'] as String?) ??
          metadata['parentId']?.toString();
    }
    if (parentUuid != null) {
      invalidateCache(folderCache, fileCache, parentUuid);
    }
  } catch (_) {
    // best-effort: cache expires on its own after `cacheDuration`
  }
}
