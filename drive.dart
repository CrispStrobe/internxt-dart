// Drive domain operations — mutate, list, resolve.
//
// Extracted from cli.dart in Phase 4. This module owns the *user-
// facing* drive operations that combine an HTTP call with the right
// cache invalidation. The transport itself lives in api.dart; the
// cache primitives in cache.dart; this module is the layer that
// glues them.
//
// Stages:
//   4.h.1  mutating ops (mv / rename / set timestamp / trash /
//          delete / list-trash).
//   4.h.2  cache-aware paginated listing primitives + path
//          resolution (listFolders, listFolderFiles, resolvePath).
//   4.h.3  recursive folder creation + search / find / tree
//          (createFolder, createFolderRecursive,
//          resolveOrCreateRemoteFolder, buildFullPath, search,
//          findFiles, printTree).
//
// State convention: nothing here holds instance state. Callers pass
// `driveApiUrl`, a bearer-token snapshot, and (where the operation
// touches the cache) the two cache maps. Cache invalidation is
// performed inline by calling `inxt_cache.invalidateCache` /
// `inxt_cache.clearParentCache` rather than via callbacks — drive
// is layered above cache so the direct dependency is fine.

import 'dart:convert';

import 'package:glob/glob.dart';
import 'package:path/path.dart' as p;

import 'api.dart' as inxt_api;
import 'cache.dart' as inxt_cache;
import 'utils.dart' as inxt_utils;

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

/// Restore an item from trash to a destination folder. Invalidates
/// the destination folder's listing cache so the next list call
/// surfaces the restored item.
///
/// Implementation note: the Python sibling documents
/// `POST /trash/restore` for this, but as of the Phase 8 audit
/// that endpoint returns 404 ("Cannot POST /api/trash/restore")
/// on the live gateway. The actual mechanism Internxt exposes is
/// `PATCH /files/{uuid}` (or `/folders/{uuid}`) with a
/// `destinationFolder` field — which both un-trashes AND moves in
/// one call. We try the documented endpoint first (in case it
/// comes online later) and fall back to the patch-with-destination
/// path on 404.
///
/// `destinationFolderUuid` is required for the fallback path
/// because move-based restore needs an explicit target. Pass the
/// original parent UUID (if known) or any folder where the user
/// wants the restored item to land.
Future<Map<String, dynamic>> restoreFromTrash(
  String driveApiUrl,
  String? bearerToken,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String itemUuid,
  String itemType, {
  String? destinationFolderUuid,
}) async {
  // Try the documented endpoint first.
  try {
    final result = await inxt_api.restoreItem(
      driveApiUrl,
      bearerToken,
      itemUuid,
      itemType,
      destinationFolderUuid: destinationFolderUuid,
    );
    if (destinationFolderUuid != null) {
      inxt_cache.invalidateCache(folderCache, fileCache, destinationFolderUuid);
    }
    return result;
  } on Exception catch (e) {
    final isNotFound = e.toString().contains('404');
    if (!isNotFound) rethrow;
    // Fall through to the move-based path.
  }

  if (destinationFolderUuid == null) {
    throw Exception('/trash/restore endpoint not available on this gateway, '
        'and no destinationFolderUuid was provided to fall back to '
        'a move-based restore. Pass an explicit destination folder.');
  }

  if (itemType == 'file') {
    await moveFile(driveApiUrl, bearerToken, folderCache, fileCache, itemUuid,
        destinationFolderUuid);
  } else {
    await moveFolder(driveApiUrl, bearerToken, folderCache, fileCache, itemUuid,
        destinationFolderUuid);
  }
  return {'success': true, 'restoredVia': 'move-fallback'};
}

/// Permanently empty the trash. **Destructive** — there is no
/// recovery after this. Caller must confirm before invoking.
Future<void> clearTrashAll(
  String driveApiUrl,
  String? bearerToken,
) =>
    inxt_api.clearTrash(driveApiUrl, bearerToken);

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
    final files = (data['result'] ?? data['items'] ?? []) as List<dynamic>;
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
    final folders = (data['result'] ?? data['items'] ?? []) as List<dynamic>;
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
    return List<Map<String, dynamic>>.from(cached.items as Iterable<dynamic>);
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
    return List<Map<String, dynamic>>.from(cached.items as Iterable<dynamic>);
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
        final plainName = (file['name'] ?? '') as String;
        final fileType = (file['fileType'] ?? '') as String;
        final fullName =
            fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
        if (plainName == part || fullName == part) {
          foundFile = file;
          break;
        }
      }
    }

    if (foundFolder != null && (!isLastPart || foundFile == null)) {
      currentFolderUuid = foundFolder['uuid'] as String;
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
      final plainName = (foundFile['name'] ?? '') as String;
      final fileType = (foundFile['fileType'] ?? '') as String;
      final fullName = fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
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

// --- Folder creation ---

/// POST /folders  body: `{plainName, parentFolderUuid, [creationTime,
/// modificationTime]}`. Invalidates the parent folder listing so a
/// subsequent listFolders call sees the new folder.
Future<Map<String, dynamic>> createFolder(
  String driveApiUrl,
  String? bearerToken,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String name,
  String parentFolderUuid, {
  String? creationTime,
  String? modificationTime,
}) async {
  final body = <String, dynamic>{
    "plainName": name,
    "parentFolderUuid": parentFolderUuid,
  };
  if (creationTime != null) body["creationTime"] = creationTime;
  if (modificationTime != null) body["modificationTime"] = modificationTime;

  final response = await inxt_api.makeRequest(
    "POST",
    Uri.parse("$driveApiUrl/folders"),
    bearerToken: bearerToken,
    body: json.encode(body),
  );

  inxt_cache.invalidateCache(folderCache, fileCache, parentFolderUuid);
  return json.decode(response.body) as Map<String, dynamic>;
}

/// Walks [path] from the root, creating any folder segments that
/// don't yet exist. Returns the metadata of the deepest segment with
/// an extra `path` field set to its full path.
///
/// On a 409 from `createFolder` (folder created concurrently — common
/// when two clients race or an in-flight retry crosses a successful
/// create), invalidates the parent listing, sleeps 1s, refetches,
/// and continues. Matches the monolith behavior exactly; the live
/// smoke suite exercises this path via the 3-level recursive create
/// test.
///
/// `creationTime` and `modificationTime` are applied only to the
/// final segment (matching how the WebDAV layer drives this).
/// Existing folders cannot have their timestamps updated through
/// this path — the gateway doesn't support it on existing folders.
Future<Map<String, dynamic>> createFolderRecursive(
  String driveApiUrl,
  String? bearerToken,
  String? rootFolderId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String path, {
  String? creationTime,
  String? modificationTime,
}) async {
  if (rootFolderId == null) throw Exception('Not logged in');
  final cleanPath = path.trim().replaceAll(RegExp(r'^/+|/+$'), '');
  if (cleanPath.isEmpty) {
    return {'uuid': rootFolderId, 'plainName': 'Root', 'path': '/'};
  }
  final parts = cleanPath.split('/');
  var currentParentUuid = rootFolderId;
  var currentPathSoFar = '/';
  Map<String, dynamic>? currentFolderInfo = {
    'uuid': rootFolderId,
    'plainName': 'Root',
    'path': '/',
  };

  for (var i = 0; i < parts.length; i++) {
    final part = parts[i];
    if (part.isEmpty) continue;
    final isLastPart = (i == parts.length - 1);
    final partPath = '$currentPathSoFar/$part'.replaceAll('//', '/');

    try {
      final folders = await listFolders(
          driveApiUrl, bearerToken, folderCache, currentParentUuid);
      Map<String, dynamic>? foundFolder;
      for (var folder in folders) {
        if (folder['name'] == part) {
          foundFolder = folder;
          break;
        }
      }

      if (foundFolder != null) {
        currentParentUuid = foundFolder['uuid'] as String;
        foundFolder['path'] = partPath;
        currentFolderInfo = foundFolder;
        currentPathSoFar = partPath;
        continue;
      }

      try {
        final newFolder = await createFolder(
          driveApiUrl,
          bearerToken,
          folderCache,
          fileCache,
          part,
          currentParentUuid,
          creationTime: isLastPart ? creationTime : null,
          modificationTime: isLastPart ? modificationTime : null,
        );
        currentParentUuid = newFolder['uuid'] as String;
        newFolder['path'] = partPath;
        currentFolderInfo = newFolder;
        currentPathSoFar = partPath;
      } on Exception catch (e) {
        final isConflict = e.toString().contains(' 409') ||
            e.toString().contains('already exists');
        if (!isConflict) rethrow;

        // Concurrent create: invalidate the parent listing, wait a
        // beat for backend consistency, refetch, and look for the
        // colliding folder.
        await Future.delayed(const Duration(seconds: 1));
        final parentUuidToList = currentFolderInfo!['uuid'] as String;
        inxt_cache.invalidateCache(folderCache, fileCache, parentUuidToList);
        final foldersAfterConflict = await listFolders(
            driveApiUrl, bearerToken, folderCache, parentUuidToList);

        Map<String, dynamic>? conflictingFolder;
        try {
          conflictingFolder = foldersAfterConflict.firstWhere(
            (folder) => folder['name'] == part,
          );
        } catch (_) {
          conflictingFolder = null;
        }

        if (conflictingFolder == null) {
          throw Exception(
              "Folder '$part' conflict (409) but could not re-fetch it.");
        }
        currentParentUuid = conflictingFolder['uuid'] as String;
        conflictingFolder['path'] = partPath;
        currentFolderInfo = conflictingFolder;
        currentPathSoFar = partPath;
      }
    } catch (e) {
      throw Exception(
          "Failed to process folder part '$part' in '$currentPathSoFar': $e");
    }
  }

  if (currentFolderInfo == null) {
    throw Exception(
        'Failed to resolve or create the final folder in the path.');
  }
  currentFolderInfo['path'] ??= currentPathSoFar;
  return currentFolderInfo;
}

/// Resolves [targetPath] if it exists, otherwise creates it
/// recursively. Throws if the path exists but is a file rather than
/// a folder. Used by upload/download flows that need a destination
/// folder on the remote, regardless of whether it already exists.
Future<Map<String, dynamic>> resolveOrCreateRemoteFolder(
  String driveApiUrl,
  String? bearerToken,
  String? rootFolderId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String targetPath,
) async {
  Map<String, dynamic> targetFolderInfo;
  try {
    targetFolderInfo = await resolvePath(driveApiUrl, bearerToken, rootFolderId,
        folderCache, fileCache, targetPath);
    if (targetFolderInfo['type'] != 'folder') {
      throw Exception("Target path '$targetPath' exists but is not a folder.");
    }
  } on Exception catch (e) {
    if (!e.toString().contains('Path not found')) rethrow;
    try {
      targetFolderInfo = await createFolderRecursive(driveApiUrl, bearerToken,
          rootFolderId, folderCache, fileCache, targetPath);
    } catch (createErr) {
      throw Exception(
          "Failed to create target folder '$targetPath': $createErr");
    }
  }
  return targetFolderInfo;
}

// --- Search / find / tree ---

/// Reconstruct the full readable path for an item by fetching its
/// folder ancestors and joining their plainNames. Used by [search]
/// when `detailed=true` so each result has a usable display path.
///
/// Returns `'/?/<itemName>'` on any failure rather than throwing —
/// the search UI prefers a "best guess" path over a failed search.
Future<String> buildFullPath(
  String driveApiUrl,
  String? bearerToken,
  String? rootFolderId,
  Map<String, dynamic> item,
  String? parentUuid,
) async {
  var itemName = (item['plainName'] ?? 'Unknown') as String;
  if (item['itemType'] == 'file' &&
      item['type'] != null &&
      (item['type'] as String).isNotEmpty) {
    itemName = '$itemName.${item['type']}';
  }

  if (parentUuid == null || parentUuid == rootFolderId) {
    return '/$itemName';
  }

  try {
    final ancestors =
        await inxt_api.getFolderAncestors(driveApiUrl, bearerToken, parentUuid);
    final pathParts = ancestors
        .map((ancestor) => ancestor['plainName'] as String?)
        .where((name) => name != null && name.toLowerCase() != 'root')
        .toList();
    final parentPath = '/${pathParts.join('/')}';
    return '${parentPath.replaceAll('//', '/')}/$itemName';
  } catch (_) {
    return '/?/$itemName';
  }
}

/// Server-side fuzzy search. With `detailed=true`, each result is
/// enriched with a full reconstructed path and the raw metadata
/// record. Without it the result is just `{uuid, name, itemType,
/// plainName, type}`.
///
/// Returns `{folders: [...], files: [...]}` partitioned by the
/// gateway-provided `itemType` field.
Future<Map<String, List<Map<String, dynamic>>>> search(
  String driveApiUrl,
  String? bearerToken,
  String? rootFolderId,
  String query, {
  bool detailed = false,
}) async {
  final results = await inxt_api.searchFiles(driveApiUrl, bearerToken, query);

  final folders = <Map<String, dynamic>>[];
  final files = <Map<String, dynamic>>[];

  for (var item in results) {
    final isFolder = item['itemType'] == 'folder';
    final itemMap = <String, dynamic>{
      'uuid': item['itemId'] ?? item['id'],
      'name': item['name'],
      'itemType': item['itemType'],
      'plainName': item['name'],
      'type': item['type'],
    };

    if (detailed) {
      try {
        Map<String, dynamic> metadata;
        String? parentUuid;
        if (isFolder) {
          metadata = await inxt_api.getFolderMetadata(
              driveApiUrl, bearerToken, itemMap['uuid'] as String);
          parentUuid = metadata['parentUuid'] as String?;
        } else {
          metadata = await inxt_api.getFileMetadata(
              driveApiUrl, bearerToken, itemMap['uuid'] as String);
          parentUuid = metadata['folderUuid'] as String?;
        }
        itemMap['fullPath'] = await buildFullPath(
            driveApiUrl, bearerToken, rootFolderId, itemMap, parentUuid);
        itemMap['metadata'] = metadata;
      } catch (e) {
        itemMap['fullPath'] = '/?/${itemMap['name']}';
        itemMap['metadata'] = {'error': e.toString()};
      }
    }

    if (isFolder) {
      folders.add(itemMap);
    } else {
      files.add(itemMap);
    }
  }
  return {'folders': folders, 'files': files};
}

/// Recursive client-side glob search. Walks the tree breadth-first
/// from [startPath], matching files against [pattern] (case-
/// insensitive Glob). [maxDepth] of -1 means unbounded.
///
/// Tolerant of resolve / list failures on individual subtrees:
/// errors on one branch are swallowed so the search returns whatever
/// it could find rather than aborting on the first transient
/// failure. Matches monolith behavior.
Future<List<Map<String, dynamic>>> findFiles(
  String driveApiUrl,
  String? bearerToken,
  String? rootFolderId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String startPath,
  String pattern, {
  int maxDepth = -1,
}) async {
  final glob = Glob(pattern, caseSensitive: false);
  final results = <Map<String, dynamic>>[];
  final pathStack = <MapEntry<String, int>>[MapEntry(startPath, 0)];

  while (pathStack.isNotEmpty) {
    final entry = pathStack.removeLast();
    final currentPath = entry.key;
    final currentDepth = entry.value;

    if (maxDepth != -1 && currentDepth >= maxDepth) continue;

    Map<String, dynamic> resolved;
    try {
      resolved = await resolvePath(driveApiUrl, bearerToken, rootFolderId,
          folderCache, fileCache, currentPath);
      if (resolved['type'] != 'folder') continue;
    } catch (_) {
      continue;
    }

    final currentFolderUuid = resolved['uuid'] as String;

    try {
      final files = await listFolderFiles(
          driveApiUrl, bearerToken, fileCache, currentFolderUuid);
      for (var file in files) {
        final plainName = (file['name'] ?? '') as String;
        final fileType = (file['fileType'] ?? '') as String;
        final fullName =
            fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
        if (glob.matches(fullName)) {
          final fullPath = '$currentPath/$fullName'.replaceAll('//', '/');
          results.add({
            ...file,
            'fullPath': fullPath,
            'displayName': fullName,
          });
        }
      }
    } catch (_) {
      // best-effort: skip this subtree's files
    }

    if (maxDepth == -1 || (currentDepth + 1) < maxDepth) {
      try {
        final folders = await listFolders(
            driveApiUrl, bearerToken, folderCache, currentFolderUuid);
        for (var folder in folders) {
          final folderName = (folder['name'] ?? 'unknown') as String;
          final subFolderPath =
              '$currentPath/$folderName'.replaceAll('//', '/');
          pathStack.add(MapEntry(subFolderPath, currentDepth + 1));
        }
      } catch (_) {
        // best-effort: skip this subtree's subfolders
      }
    }
  }
  return results;
}

/// Recursively renders an ASCII tree of [path] up to [maxDepth].
/// Output is delivered through the [printLine] callback so the
/// caller can route it to stdout, a buffer, or a log.
Future<void> printTree(
  String driveApiUrl,
  String? bearerToken,
  String? rootFolderId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String path,
  void Function(String) printLine, {
  int maxDepth = 3,
  int currentDepth = 0,
  String prefix = '',
}) async {
  if (currentDepth >= maxDepth) return;

  Map<String, dynamic> resolved;
  try {
    resolved = await resolvePath(
        driveApiUrl, bearerToken, rootFolderId, folderCache, fileCache, path);
    if (resolved['type'] != 'folder') {
      printLine('$prefix└── 📄 ${p.basename(path)}');
      return;
    }
  } catch (e) {
    printLine('$prefix└── ❌ Error reading path: $e');
    return;
  }

  try {
    final folderUuid = resolved['uuid'] as String;
    final folders =
        await listFolders(driveApiUrl, bearerToken, folderCache, folderUuid);
    final files =
        await listFolderFiles(driveApiUrl, bearerToken, fileCache, folderUuid);
    final allItems = [...folders, ...files];

    if (allItems.isEmpty) return;

    for (var i = 0; i < allItems.length; i++) {
      final item = allItems[i];
      final isLastItem = (i == allItems.length - 1);
      final connector = isLastItem ? '└── ' : '├── ';
      final childPrefix = prefix + (isLastItem ? '    ' : '│   ');
      final itemName = (item['name'] ?? 'Unknown') as String;

      if (item['type'] == 'folder') {
        final folderPath = '$path/$itemName'.replaceAll('//', '/');
        printLine('$prefix$connector📁 $itemName/');
        await printTree(
          driveApiUrl,
          bearerToken,
          rootFolderId,
          folderCache,
          fileCache,
          folderPath,
          printLine,
          maxDepth: maxDepth,
          currentDepth: currentDepth + 1,
          prefix: childPrefix,
        );
      } else {
        final fileType = (item['fileType'] ?? '') as String;
        final displayName =
            fileType.isNotEmpty ? '$itemName.$fileType' : itemName;
        final size = inxt_utils.formatSize(item['size'] ?? 0);
        printLine('$prefix$connector📄 $displayName ($size)');
      }
    }
  } catch (e) {
    printLine('$prefix└── ❌ Error listing folder: $e');
  }
}

/// Library-friendly enriched folder listing.
///
/// Wraps [resolvePath] + [listFolders] + [listFolderFiles] and
/// annotates each entry with:
///   - `path`         full readable path under the resolved folder
///   - `displayName`  `<plainName>.<type>` for files, `<plainName>` for folders
///   - `sizeDisplay`  `'<DIR>'` for folders; human-readable size for files
///   - `modified`     `modificationTime ?? updatedAt`
/// while preserving every original field from the listing.
///
/// Returns `{folders, files, currentPath}`. Mirrors the Python
/// sibling's `list_folder_with_paths`. Useful for UI layers (CLI
/// rendering, the Flutter app, future REPL) that want a single call
/// to get a fully populated row set.
Future<Map<String, dynamic>> listFolderWithPaths(
  String driveApiUrl,
  String? bearerToken,
  String? rootFolderId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String folderPath,
) async {
  final resolved = await resolvePath(driveApiUrl, bearerToken, rootFolderId,
      folderCache, fileCache, folderPath);
  if (resolved['type'] != 'folder') {
    throw Exception("Path '$folderPath' is a file, not a folder");
  }

  final folderUuid = resolved['uuid'] as String;
  final basePath = (resolved['path'] as String?) ?? folderPath;
  final basePathTrimmed = basePath.endsWith('/') && basePath.length > 1
      ? basePath.substring(0, basePath.length - 1)
      : basePath;

  final rawFolders = await listFolders(
      driveApiUrl, bearerToken, folderCache, folderUuid,
      detailed: true);
  final rawFiles = await listFolderFiles(
      driveApiUrl, bearerToken, fileCache, folderUuid,
      detailed: true);

  final enrichedFolders = rawFolders.map((folder) {
    final name = (folder['name'] ?? 'Unknown') as String;
    return {
      ...folder,
      'path': '$basePathTrimmed/$name',
      'displayName': name,
      'sizeDisplay': '<DIR>',
      'modified': folder['modificationTime'] ?? folder['updatedAt'] ?? '',
    };
  }).toList();

  final enrichedFiles = rawFiles.map((file) {
    final plainName = (file['name'] ?? '') as String;
    final fileType = (file['fileType'] ?? '') as String;
    final displayName =
        fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
    final sizeBytes = file['size'] is int
        ? file['size'] as int
        : int.tryParse((file['size'] ?? 0).toString()) ?? 0;
    return {
      ...file,
      'path': '$basePathTrimmed/$displayName',
      'displayName': displayName,
      'sizeDisplay': inxt_utils.formatSize(sizeBytes),
      'modified': file['modificationTime'] ?? file['updatedAt'] ?? '',
    };
  }).toList();

  return {
    'folders': enrichedFolders,
    'files': enrichedFiles,
    'currentPath': basePathTrimmed,
  };
}
