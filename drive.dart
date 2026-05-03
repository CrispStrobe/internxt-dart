// Drive domain operations — mutate, list, resolve.
//
// Extracted from cli.dart in Phase 4. This module owns the *user-
// facing* drive operations that combine an HTTP call with the right
// cache invalidation. The transport itself lives in api.dart; the
// cache primitives in cache.dart; this module is the layer that
// glues them.
//
// Stage 4.h.1 lifts the simple mutating ops (mv / rename / set
// timestamp / trash / delete / list-trash). Stage 4.h.2 will add
// the more complex domain operations (resolvePath, the listing-
// with-cache path through listFolders / listFolderFiles, recursive
// folder creation, search / find / tree).
//
// State convention: nothing here holds instance state. Callers pass
// `driveApiUrl`, a bearer-token snapshot, and (where the operation
// touches the cache) the two cache maps. Cache invalidation is
// performed inline by calling `inxt_cache.invalidateCache` /
// `inxt_cache.clearParentCache` rather than via callbacks — drive
// is layered above cache so the direct dependency is fine.

import 'dart:convert';

import 'api.dart' as inxt_api;
import 'cache.dart' as inxt_cache;

/// Bind cache.clearParentCache's metadata-fetcher callbacks to the
/// supplied (driveApiUrl, bearerToken) snapshot. Used by every
/// mutating op in this module that needs to invalidate a parent
/// listing.
Future<void> _clearParent(
  String driveApiUrl,
  String? bearerToken,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String itemUuid,
  String itemType,
) =>
    inxt_cache.clearParentCache(
      folderCache,
      fileCache,
      itemUuid,
      itemType,
      (uuid) => inxt_api.getFileMetadata(driveApiUrl, bearerToken, uuid),
      (uuid) => inxt_api.getFolderMetadata(driveApiUrl, bearerToken, uuid),
    );

/// PATCH /files/{uuid}  body: `{destinationFolder: ...}`.
/// Invalidates both the source parent (via `clearParentCache`) and
/// the destination listing.
Future<void> moveFile(
  String driveApiUrl,
  String? bearerToken,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String fileUuid,
  String destinationFolderUuid,
) async {
  await _clearParent(
      driveApiUrl, bearerToken, folderCache, fileCache, fileUuid, 'file');
  await inxt_api.makeRequest(
    'PATCH',
    Uri.parse('$driveApiUrl/files/$fileUuid'),
    bearerToken: bearerToken,
    body: json.encode({'destinationFolder': destinationFolderUuid}),
  );
  inxt_cache.invalidateCache(folderCache, fileCache, destinationFolderUuid);
}

/// PATCH /folders/{uuid}  body: `{destinationFolder: ...}`.
/// Same invalidation pattern as [moveFile].
Future<void> moveFolder(
  String driveApiUrl,
  String? bearerToken,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String folderUuid,
  String destinationFolderUuid,
) async {
  await _clearParent(
      driveApiUrl, bearerToken, folderCache, fileCache, folderUuid, 'folder');
  await inxt_api.makeRequest(
    'PATCH',
    Uri.parse('$driveApiUrl/folders/$folderUuid'),
    bearerToken: bearerToken,
    body: json.encode({'destinationFolder': destinationFolderUuid}),
  );
  inxt_cache.invalidateCache(folderCache, fileCache, destinationFolderUuid);
}

/// PUT /files/{uuid}/meta  body: `{plainName, type}`.
/// `newType` is sent as `''` when null (matches monolith behavior —
/// the gateway treats absent and empty as equivalent for retype).
Future<void> renameFile(
  String driveApiUrl,
  String? bearerToken,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String fileUuid,
  String newPlainName,
  String? newType,
) async {
  await _clearParent(
      driveApiUrl, bearerToken, folderCache, fileCache, fileUuid, 'file');
  await inxt_api.updateFileMetadata(driveApiUrl, bearerToken, fileUuid, {
    'plainName': newPlainName,
    'type': newType ?? '',
  });
}

/// PUT /folders/{uuid}/meta  body: `{plainName}`.
Future<void> renameFolder(
  String driveApiUrl,
  String? bearerToken,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String folderUuid,
  String newName,
) async {
  await _clearParent(
      driveApiUrl, bearerToken, folderCache, fileCache, folderUuid, 'folder');
  await inxt_api.updateFolderMetadata(driveApiUrl, bearerToken, folderUuid, {
    'plainName': newName,
  });
}

/// Set the modification time on a file. No cache invalidation —
/// listing content (names, UUIDs) is unchanged; only the timestamp
/// metadata changes, and the cache doesn't store it in a way the
/// CLI consumes.
Future<void> setFileTimestamp(
  String driveApiUrl,
  String? bearerToken,
  String fileUuid,
  DateTime mTime,
) async {
  await inxt_api.updateFileMetadata(driveApiUrl, bearerToken, fileUuid, {
    'modificationTime': mTime.toUtc().toIso8601String(),
  });
}

/// Set the modification time on a folder. Same no-invalidation
/// reasoning as [setFileTimestamp].
Future<void> setFolderTimestamp(
  String driveApiUrl,
  String? bearerToken,
  String folderUuid,
  DateTime mTime,
) async {
  await inxt_api.updateFolderMetadata(driveApiUrl, bearerToken, folderUuid, {
    'modificationTime': mTime.toUtc().toIso8601String(),
  });
}

/// POST /storage/trash/add  body: `{items: [{uuid, type}]}`.
/// Invalidates the source parent's listing.
Future<void> trashItems(
  String driveApiUrl,
  String? bearerToken,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String uuid,
  String type,
) async {
  await _clearParent(
      driveApiUrl, bearerToken, folderCache, fileCache, uuid, type);
  await inxt_api.makeRequest(
    'POST',
    Uri.parse('$driveApiUrl/storage/trash/add'),
    bearerToken: bearerToken,
    body: json.encode({
      'items': [
        {'uuid': uuid, 'type': type}
      ]
    }),
  );
}

/// DELETE /storage/trash  body: `{items: [{uuid, type}]}`.
/// Permanently destroys the item — the user cannot recover it from
/// the web UI. No cache invalidation because the item is in trash,
/// not in any parent listing.
Future<void> deletePermanently(
  String driveApiUrl,
  String? bearerToken,
  String uuid,
  String type,
) async {
  await inxt_api.makeRequest(
    'DELETE',
    Uri.parse('$driveApiUrl/storage/trash'),
    bearerToken: bearerToken,
    body: json.encode({
      'items': [
        {'uuid': uuid, 'type': type}
      ]
    }),
  );
}

/// Paginated trash listing — fetches one page of files AND one page
/// of folders at the given offset, returns the combined list. Each
/// `type=files` / `type=folders` call is independently fault-tolerant:
/// a failure on one branch returns an empty list there rather than
/// throwing, mirroring the monolith's "best-effort listing" behavior.
Future<List<Map<String, dynamic>>> getTrashContent(
  String driveApiUrl,
  String? bearerToken, {
  int offset = 0,
  int limit = 50,
}) async {
  final url = Uri.parse('$driveApiUrl/storage/trash/paginated');
  final allItems = <Map<String, dynamic>>[];

  try {
    final response = await inxt_api.makeRequest(
      'GET',
      url.replace(queryParameters: {
        'offset': offset.toString(),
        'limit': limit.toString(),
        'type': 'files',
      }),
      bearerToken: bearerToken,
    );
    final data = json.decode(response.body);
    final files = data['result'] ?? data['items'] ?? [];
    for (var item in files) {
      allItems.add({
        'type': 'file',
        'name': item['plainName'] ?? item['name'],
        'fileType': item['type'] ?? '',
        'uuid': item['uuid'] ?? item['id'],
        'size': item['size'],
      });
    }
  } catch (_) {
    // best-effort: continue to folders branch
  }

  try {
    final response = await inxt_api.makeRequest(
      'GET',
      url.replace(queryParameters: {
        'offset': offset.toString(),
        'limit': limit.toString(),
        'type': 'folders',
      }),
      bearerToken: bearerToken,
    );
    final data = json.decode(response.body);
    final folders = data['result'] ?? data['items'] ?? [];
    for (var item in folders) {
      allItems.add({
        'type': 'folder',
        'name': item['plainName'] ?? item['name'],
        'fileType': '',
        'uuid': item['uuid'] ?? item['id'],
        'size': null,
      });
    }
  } catch (_) {
    // best-effort: return whatever we got from the files branch
  }

  return allItems;
}
