// Drive domain operations — mutate, list, resolve.
//
// Extracted from cli.dart in Phase 4. This module owns the *user-
// facing* drive operations that combine an HTTP call with the right
// cache invalidation. The transport itself lives in api.dart; the
// cache primitives in cache.dart; this module is the layer that
// glues them.
//
// Stage 4.h.1 lifted the simple mutating ops (mv / rename / set
// timestamp / trash / delete / list-trash). Stage 4.h.2 adds the
// cache-aware paginated listing primitives plus path resolution
// (listFolders, listFolderFiles, resolvePath). Stage 4.h.3 will
// add recursive folder creation and search / findFiles / printTree.
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

// --- Cache-aware paginated listing ---
//
// `listFolders` and `listFolderFiles` are the two primitives that
// every other domain op (resolvePath, createFolderRecursive, search,
// findFiles, printTree) depends on. They share a shape:
//   1. Cache hit (within `cacheDuration`) -> return a defensive copy.
//   2. Otherwise paginate the gateway listing endpoint at limit=50.
//   3. Cache the full detailed result.
//   4. If detailed=false, return a stripped subset (only the fields
//      the CLI rendering paths use). The cache always stores the
//      full detailed shape so a later detailed=true call doesn't
//      have to refetch.

/// GET /folders/content/{folderId}/folders (paginated, sorted by
/// plainName ASC). Cache lives in [folderCache] keyed by [folderId].
///
/// `detailed=false` returns only `{type, name, uuid, size}`; the
/// cache always keeps the full record so a detailed call later is
/// served from cache.
Future<List<Map<String, dynamic>>> listFolders(
  String driveApiUrl,
  String? bearerToken,
  Map<String, inxt_cache.CacheEntry> folderCache,
  String folderId, {
  bool detailed = false,
}) async {
  final cached = folderCache[folderId];
  if (cached != null &&
      DateTime.now().difference(cached.timestamp) < inxt_cache.cacheDuration) {
    return List<Map<String, dynamic>>.from(cached.items);
  }

  final allItems = <Map<String, dynamic>>[];
  var currentOffset = 0;
  const limit = 50;

  while (true) {
    final url = Uri.parse('$driveApiUrl/folders/content/$folderId/folders');
    final response = await inxt_api.makeRequest(
      'GET',
      url.replace(queryParameters: {
        'offset': currentOffset.toString(),
        'limit': limit.toString(),
        'sort': 'plainName',
        'direction': 'ASC',
      }),
      bearerToken: bearerToken,
    );

    final data = json.decode(response.body);
    final folders = (data['result'] ?? data['folders'] ?? []) as List<dynamic>;

    for (var folder in folders) {
      allItems.add({
        'type': 'folder',
        'name': folder['plainName'] ?? folder['name'],
        'uuid': folder['uuid'] ?? folder['id'],
        'size': 0,
        'createdAt': folder['createdAt'],
        'updatedAt': folder['updatedAt'],
        'creationTime': folder['creationTime'],
        'modificationTime': folder['modificationTime'],
        'parentId': folder['parentId'],
        'parentUuid': folder['parentUuid'],
        'userId': folder['userId'],
        'deleted': folder['deleted'],
        'removed': folder['removed'],
      });
    }

    if (folders.length < limit) break;
    currentOffset += limit;
  }

  folderCache[folderId] =
      inxt_cache.CacheEntry(items: allItems, timestamp: DateTime.now());

  if (!detailed) {
    return allItems
        .map((item) => {
              'type': item['type'],
              'name': item['name'],
              'uuid': item['uuid'],
              'size': item['size'],
            })
        .toList();
  }
  return allItems;
}

/// GET /folders/content/{folderId}/files (paginated, sorted by
/// plainName ASC). Cache lives in [fileCache] keyed by [folderId].
///
/// `detailed=false` strips down to a subset (`type, name, fileType,
/// uuid, size, bucket, fileId`) — those are the fields the listing
/// rendering and the upload-conflict-detection path consume.
Future<List<Map<String, dynamic>>> listFolderFiles(
  String driveApiUrl,
  String? bearerToken,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String folderId, {
  bool detailed = false,
}) async {
  final cached = fileCache[folderId];
  if (cached != null &&
      DateTime.now().difference(cached.timestamp) < inxt_cache.cacheDuration) {
    return List<Map<String, dynamic>>.from(cached.items);
  }

  final allItems = <Map<String, dynamic>>[];
  var currentOffset = 0;
  const limit = 50;

  while (true) {
    final url = Uri.parse('$driveApiUrl/folders/content/$folderId/files');
    final response = await inxt_api.makeRequest(
      'GET',
      url.replace(queryParameters: {
        'offset': currentOffset.toString(),
        'limit': limit.toString(),
        'sort': 'plainName',
        'direction': 'ASC',
      }),
      bearerToken: bearerToken,
    );

    final data = json.decode(response.body);
    final files = (data['result'] ?? data['files'] ?? []) as List<dynamic>;

    for (var file in files) {
      allItems.add({
        'type': 'file',
        'name': file['plainName'] ?? file['name'],
        'fileType': file['type'] ?? '',
        'uuid': file['uuid'] ?? file['id'],
        'size': file['size'] is int
            ? file['size']
            : int.tryParse(file['size'].toString()) ?? 0,
        'bucket': file['bucket'],
        'fileId': file['fileId'],
        'createdAt': file['createdAt'],
        'updatedAt': file['updatedAt'],
        'creationTime': file['creationTime'],
        'modificationTime': file['modificationTime'],
        'folderId': file['folderId'],
        'folderUuid': file['folderUuid'],
        'userId': file['userId'],
        'encryptVersion': file['encryptVersion'],
        'deleted': file['deleted'],
        'removed': file['removed'],
        'status': file['status'],
      });
    }

    if (files.length < limit) break;
    currentOffset += limit;
  }

  fileCache[folderId] =
      inxt_cache.CacheEntry(items: allItems, timestamp: DateTime.now());

  if (!detailed) {
    return allItems
        .map((item) => {
              'type': item['type'],
              'name': item['name'],
              'fileType': item['fileType'],
              'uuid': item['uuid'],
              'size': item['size'],
              'bucket': item['bucket'],
              'fileId': item['fileId'],
            })
        .toList();
  }
  return allItems;
}

/// Resolves a `/foo/bar/baz` path to either a file or folder UUID by
/// walking the listing tree from the root. Returns a map with shape
/// `{type, uuid, metadata, path}`.
///
/// Lookup at each level uses [listFolders]; the final segment also
/// tries [listFolderFiles] so a path can resolve to a file. Folder
/// matches win when a folder and a file would both match the last
/// segment (matches the monolith — folder wins because the listing
/// is checked first).
///
/// Throws if [rootFolderId] is null (caller should have logged in)
/// or if any segment cannot be found.
Future<Map<String, dynamic>> resolvePath(
  String driveApiUrl,
  String? bearerToken,
  String? rootFolderId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String path,
) async {
  if (rootFolderId == null) {
    throw Exception('Root folder ID is not set. Please log in.');
  }
  var currentFolderUuid = rootFolderId;
  var resolvedPathStr = '/';

  var cleanPath = path.trim();
  if (cleanPath.startsWith('/')) cleanPath = cleanPath.substring(1);
  if (cleanPath.endsWith('/')) {
    cleanPath = cleanPath.substring(0, cleanPath.length - 1);
  }

  if (cleanPath.isEmpty || cleanPath == '.') {
    return {
      'type': 'folder',
      'uuid': currentFolderUuid,
      'metadata': {'uuid': currentFolderUuid, 'name': 'Root'},
      'path': '/',
    };
  }

  final pathParts =
      cleanPath.split('/').where((part) => part.isNotEmpty).toList();
  Map<String, dynamic>? currentMetadata = {
    'uuid': rootFolderId,
    'name': 'Root',
  };

  for (var i = 0; i < pathParts.length; i++) {
    final part = pathParts[i];
    final isLastPart = (i == pathParts.length - 1);

    final folders = await listFolders(
      driveApiUrl,
      bearerToken,
      folderCache,
      currentFolderUuid,
      detailed: true,
    );

    Map<String, dynamic>? foundFolder;
    for (var folder in folders) {
      if (folder['name'] == part) {
        foundFolder = folder;
        break;
      }
    }

    Map<String, dynamic>? foundFile;
    if (isLastPart) {
      final files = await listFolderFiles(
        driveApiUrl,
        bearerToken,
        fileCache,
        currentFolderUuid,
        detailed: true,
      );
      for (var file in files) {
        final plainName = file['name'] ?? '';
        final fileType = file['fileType'] ?? '';
        final fullName =
            fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
        if (plainName == part || fullName == part) {
          foundFile = file;
          break;
        }
      }
    }

    if (foundFolder != null && (!isLastPart || foundFile == null)) {
      currentFolderUuid = foundFolder['uuid'];
      currentMetadata = foundFolder;
      resolvedPathStr = '$resolvedPathStr$part/'.replaceAll('//', '/');
      if (isLastPart) {
        return {
          'type': 'folder',
          'uuid': foundFolder['uuid'],
          'metadata': foundFolder,
          'path': resolvedPathStr.substring(0, resolvedPathStr.length - 1),
        };
      }
    } else if (foundFile != null && isLastPart) {
      final plainName = foundFile['name'] ?? '';
      final fileType = foundFile['fileType'] ?? '';
      final fullName =
          fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
      resolvedPathStr = '$resolvedPathStr$fullName'.replaceAll('//', '/');
      return {
        'type': 'file',
        'uuid': foundFile['uuid'],
        'metadata': foundFile,
        'path': resolvedPathStr,
      };
    } else {
      final currentPath = '/${pathParts.sublist(0, i + 1).join('/')}';
      throw Exception('Path not found: $currentPath');
    }
  }

  return {
    'type': 'folder',
    'uuid': currentFolderUuid,
    'metadata': currentMetadata,
    'path': resolvedPathStr.isEmpty ? '/' : resolvedPathStr,
  };
}
