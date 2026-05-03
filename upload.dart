// Upload pipeline — encrypt, push shard, finalize, register.
//
// Extracted from cli.dart in Phase 4.i. Owns the full upload flow:
// the four primitive HTTP calls (start / chunk / finish / create-
// file-entry), the per-file orchestrator (`uploadFile`), the
// per-item conflict-policy + timestamp wrapper (`uploadSingleItem`),
// and the top-level batch driver (`upload`) with resumable state
// persistence.
//
// State convention: nothing here holds instance state. Callers pass
// (driveApiUrl, networkUrl, bearerToken, rootFolderId, mnemonic,
// bucketId), the cache maps, and the bridge auth credentials. The
// pipeline calls into `inxt_api`, `inxt_auth`, `inxt_cache`,
// `inxt_crypto`, `inxt_drive`, and `inxt_utils` directly.
//
// User-facing `print()` calls are preserved (these are the upload
// progress UX); `log()` debug noise was dropped per the extraction
// pattern.
//
// Coverage: every live test in test/live_smoke_test.dart performs
// at least one upload, so any regression here surfaces immediately.

import 'dart:convert';
import 'dart:io' as io;
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:glob/glob.dart';
import 'package:glob/list_local_fs.dart';
import 'package:http/http.dart' as http;
import 'package:path/path.dart' as p;

import 'api.dart' as inxt_api;
import 'auth.dart' as inxt_auth;
import 'cache.dart' as inxt_cache;
import 'crypto.dart' as inxt_crypto;
import 'drive.dart' as inxt_drive;
import 'utils.dart' as inxt_utils;

// --- Network primitives ---

/// POST /v2/buckets/{bucketId}/files/start?multiparts=1.
/// Returns the gateway response with a single-element `uploads`
/// array containing the shard upload URL and UUID.
Future<Map<String, dynamic>> startUpload(
  String networkUrl,
  String bucketId,
  int fileSize,
  String user,
  String pass,
) async {
  final response = await inxt_api.makeRequest(
    'POST',
    Uri.parse('$networkUrl/v2/buckets/$bucketId/files/start?multiparts=1'),
    useAuth: false,
    isNetworkAuth: true,
    networkUser: user,
    networkPass: pass,
    body: json.encode({
      'uploads': [
        {'index': 0, 'size': fileSize}
      ]
    }),
  );
  return json.decode(response.body);
}

/// PUT [chunkData] to [uploadUrl] in 128 KB sub-chunks, rendering a
/// stdout progress indicator.
///
/// The 5 ms inter-chunk delay is intentional and preserved from the
/// monolith — it prevents socket saturation that otherwise causes
/// the progress percentage to "jump" to 100% before the network has
/// caught up. Same pattern as the Go rclone adapter.
Future<void> uploadChunkWithProgress(
  String uploadUrl,
  Uint8List chunkData,
  String fileName,
) async {
  final totalBytes = chunkData.length;
  var bytesSent = 0;
  final stopwatch = Stopwatch()..start();

  print('     ☁️  [STEP 3/5] Streamed Network Transfer: $fileName');

  final request = http.StreamedRequest('PUT', Uri.parse(uploadUrl));
  request.headers['Content-Type'] = 'application/octet-stream';
  request.headers['internxt-client'] = 'cli';
  request.contentLength = totalBytes;

  const internalBuffer = 128 * 1024;
  final responseFuture = request.send();

  try {
    for (var i = 0; i < totalBytes; i += internalBuffer) {
      final end =
          (i + internalBuffer < totalBytes) ? i + internalBuffer : totalBytes;
      final chunk = chunkData.sublist(i, end);

      request.sink.add(chunk);
      bytesSent += chunk.length;

      final percent = (bytesSent / totalBytes * 100).toStringAsFixed(1);
      final elapsed = stopwatch.elapsedMilliseconds / 1000.0;
      final speed = bytesSent / (elapsed > 0 ? elapsed : 0.001);

      io.stdout.write(
          '\r        Progress: $percent% (${inxt_utils.formatSize(bytesSent)}/${inxt_utils.formatSize(totalBytes)}) [${inxt_utils.formatSize(speed)}/s]   ');

      // Mandatory delay — see doc comment.
      await Future.delayed(const Duration(milliseconds: 5));
    }
  } finally {
    await request.sink.close();
  }

  final response = await http.Response.fromStream(await responseFuture);
  print('');

  if (response.statusCode != 200 && response.statusCode != 201) {
    throw Exception('Upload failed: ${response.statusCode} - ${response.body}');
  }
}

/// POST /v2/buckets/{bucketId}/files/finish — finalize the network
/// shard transfer with the file index hex and the per-shard hash.
Future<Map<String, dynamic>> finishUpload(
  String networkUrl,
  String bucketId,
  Map<String, dynamic> payload,
  String user,
  String pass,
) async {
  final response = await inxt_api.makeRequest(
    'POST',
    Uri.parse('$networkUrl/v2/buckets/$bucketId/files/finish'),
    useAuth: false,
    isNetworkAuth: true,
    networkUser: user,
    networkPass: pass,
    body: json.encode(payload),
  );
  return json.decode(response.body);
}

/// POST /files — register the uploaded shard as a drive file entry.
/// Invalidates the destination folder's listing cache so a
/// subsequent listFolderFiles sees the new file.
Future<Map<String, dynamic>> createFileEntry(
  String driveApiUrl,
  String? bearerToken,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  Map<String, dynamic> payload,
) async {
  final response = await inxt_api.makeRequest(
    'POST',
    Uri.parse('$driveApiUrl/files'),
    bearerToken: bearerToken,
    body: json.encode(payload),
  );

  final folderUuid = payload['folderUuid'];
  if (folderUuid is String) {
    inxt_cache.invalidateCache(folderCache, fileCache, folderUuid);
  }

  return json.decode(response.body);
}

// --- Per-file orchestration ---

/// Encrypt → push shard → finalize → register, with stdout progress.
///
/// Steps mirror the Python sibling exactly:
///   1. Encrypt the entire file in memory (`encryptStream`).
///   2. Compute bridge auth (`computeBridgePass`).
///   3. POST start to get the shard URL.
///   4. PUT the encrypted bytes with progress.
///   5. POST finish with the file index and shard hash.
///   6. POST /files to register the drive entry.
Future<Map<String, dynamic>> uploadFile(
  String networkUrl,
  String driveApiUrl,
  String? bearerToken,
  String mnemonic,
  String bucketId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  io.File localFile,
  String destinationFolderUuid,
  String remoteFileName, {
  required String bridgeUser,
  required String userIdForAuth,
  String? creationTime,
  String? modificationTime,
}) async {
  final fileSize = await localFile.length();

  print(
      '\n     🔐 [STEP 1/5] Starting Encryption for ${inxt_utils.formatSize(fileSize)}...');
  final fileBytes = await localFile.readAsBytes();
  final encryptClock = Stopwatch()..start();

  final encryptedResult = inxt_crypto.encryptStream(fileBytes, mnemonic, bucketId);
  final encryptedData = encryptedResult['data']!;
  final fileIndexHex = encryptedResult['index']!;

  encryptClock.stop();
  final encryptSeconds = encryptClock.elapsed.inSeconds;
  print(
      '     ✅ Encryption complete! (${encryptSeconds}s, ${inxt_utils.formatSize(fileSize / (encryptSeconds + 0.001))}/s)');

  final bridgePass = inxt_auth.computeBridgePass(userIdForAuth);
  final startResponse = await startUpload(
      networkUrl, bucketId, encryptedData.length, bridgeUser, bridgePass);

  await uploadChunkWithProgress(
      startResponse['uploads'][0]['url'], encryptedData, remoteFileName);

  print('     ✅ [STEP 4/5] Finalizing network storage...');
  final encryptedHash = crypto.sha256.convert(encryptedData).toString();
  final finishResponse = await finishUpload(
    networkUrl,
    bucketId,
    {
      'index': fileIndexHex,
      'shards': [
        {'hash': encryptedHash, 'uuid': startResponse['uploads'][0]['uuid']}
      ]
    },
    bridgeUser,
    bridgePass,
  );

  print('     📋 [STEP 5/5] Creating Drive file entry...');
  return createFileEntry(driveApiUrl, bearerToken, folderCache, fileCache, {
    'folderUuid': destinationFolderUuid,
    'plainName': p.basenameWithoutExtension(remoteFileName),
    'type': p.extension(remoteFileName).replaceAll('.', ''),
    'size': fileSize,
    'bucket': bucketId,
    'fileId': finishResponse['id'],
    'encryptVersion': 'Aes03',
    'name': '',
    'creationTime': creationTime,
    'modificationTime': modificationTime,
  });
}

/// Single-file upload with conflict policy + timestamp preservation.
///
/// `onConflict` values:
///   - `skip`      — log and return `"skipped"`.
///   - `overwrite` — trash the existing file (errors on existing
///     folder), then upload.
///   - other       — proceed with upload regardless.
///
/// Returns one of `"uploaded"`, `"skipped"`, or `"error"`.
Future<String> uploadSingleItem(
  String networkUrl,
  String driveApiUrl,
  String? bearerToken,
  String? rootFolderId,
  String mnemonic,
  String bucketId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  io.File localFile,
  String targetRemoteParentPath,
  String targetFolderUuid,
  String onConflict, {
  required String bridgeUser,
  required String userIdForAuth,
  required bool preserveTimestamps,
  String? remoteFileName,
}) async {
  final effectiveRemoteFilename = remoteFileName ?? p.basename(localFile.path);
  final fullTargetRemotePath = p
      .join(targetRemoteParentPath, effectiveRemoteFilename)
      .replaceAll('\\', '/');
  print(
      "  -> Preparing upload: '${p.basename(localFile.path)}' to '$fullTargetRemotePath'");

  Map<String, dynamic>? existingItemInfo;
  try {
    existingItemInfo = await inxt_drive.resolvePath(driveApiUrl, bearerToken,
        rootFolderId, folderCache, fileCache, fullTargetRemotePath);
    print(
        "  -> Target exists: $fullTargetRemotePath (Type: ${existingItemInfo['type']})");
  } on Exception catch (e) {
    if (e.toString().contains('Path not found')) {
      print('  -> Target does not exist, proceeding with upload');
    } else {
      print('  -> ⚠️  Error checking target existence: $e');
    }
  }

  if (existingItemInfo != null) {
    if (onConflict == 'skip') {
      print('  -> ⏭️  Skipping due to conflict policy (file exists)');
      return 'skipped';
    } else if (onConflict == 'overwrite') {
      if (existingItemInfo['type'] == 'folder') {
        print(
            '  -> ❌ Cannot overwrite folder with a file: $fullTargetRemotePath');
        return 'error';
      } else {
        print('  -> 🔄 Overwriting existing file...');
        try {
          await inxt_drive.deletePermanently(
              driveApiUrl, bearerToken, existingItemInfo['uuid'], 'file');
          print('  -> 🗑️  Deleted existing file for overwrite');
        } catch (delErr) {
          print('  -> ❌ Error deleting existing file for overwrite: $delErr');
          return 'error';
        }
      }
    }
  }

  try {
    String? creationTime;
    String? modificationTime;

    if (preserveTimestamps) {
      try {
        final stat = await localFile.stat();
        modificationTime = stat.modified.toUtc().toIso8601String();
        creationTime = stat.changed.toUtc().toIso8601String();
      } catch (_) {
        // best-effort: skip timestamps if stat fails
      }
    }

    await uploadFile(
      networkUrl,
      driveApiUrl,
      bearerToken,
      mnemonic,
      bucketId,
      folderCache,
      fileCache,
      localFile,
      targetFolderUuid,
      effectiveRemoteFilename,
      bridgeUser: bridgeUser,
      userIdForAuth: userIdForAuth,
      creationTime: creationTime,
      modificationTime: modificationTime,
    );
    print('  -> ✅ Successfully uploaded: $effectiveRemoteFilename');
    return 'uploaded';
  } catch (upErr) {
    if (upErr.toString().contains('SKIPPED_EMPTY_FILE')) {
      print(
          '  -> ⏭️  Skipped empty file (API policy): $effectiveRemoteFilename');
      return 'skipped';
    }
    print('  -> ❌ Error during upload: $upErr');
    return 'error';
  }
}

// --- Top-level batch driver ---

/// Multi-file batch upload with resumable state persistence.
///
/// On a fresh run (`initialBatchState == null`), walks `sources`
/// (each is a glob), expands directories recursively when
/// `recursive`, applies include/exclude filters, generates a task
/// list, and persists it via [saveStateCallback]. On a resume run,
/// the supplied state is reused so previously-completed tasks are
/// skipped.
///
/// State is saved after every per-task status update so a crash
/// mid-batch can be resumed cleanly.
///
/// Throws on any error count > 0 at the end so the CLI exits
/// non-zero; the state file is preserved for inspection / retry.
Future<void> upload(
  String networkUrl,
  String driveApiUrl,
  String? bearerToken,
  String? rootFolderId,
  String mnemonic,
  String bucketId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  List<String> sources,
  String targetPath, {
  required bool recursive,
  required String onConflict,
  required bool preserveTimestamps,
  required List<String> include,
  required List<String> exclude,
  required String bridgeUser,
  required String userIdForAuth,
  required String batchId,
  Map<String, dynamic>? initialBatchState,
  required Future<void> Function(Map<String, dynamic>) saveStateCallback,
}) async {
  print('🎯 Preparing upload to remote path: $targetPath');

  Map<String, dynamic> batchState;
  List<dynamic> tasks;

  if (initialBatchState != null) {
    print('🔄 Resuming previous batch operation...');
    batchState = initialBatchState;
    tasks = batchState['tasks'] as List<dynamic>;
  } else {
    print('🔍 Generating new batch task list...');
    tasks = [];
    final targetFolderInfo = await inxt_drive.resolveOrCreateRemoteFolder(
        driveApiUrl, bearerToken, rootFolderId, folderCache, fileCache, targetPath);
    final targetFolderPathStr =
        targetFolderInfo['path'] as String? ?? targetPath;

    for (final sourceArg in sources) {
      final hasTrailingSlash =
          sourceArg.endsWith('/') || sourceArg.endsWith('\\');
      final glob = Glob(sourceArg.replaceAll('\\', '/'));

      await for (final entity in glob.list()) {
        if (await io.FileSystemEntity.isDirectory(entity.path)) {
          if (!recursive) continue;
          final localDir = io.Directory(entity.path);

          String? dirCreationTime;
          String? dirModTime;
          if (preserveTimestamps) {
            try {
              final stat = await localDir.stat();
              dirModTime = stat.modified.toUtc().toIso8601String();
              dirCreationTime = stat.changed.toUtc().toIso8601String();
            } catch (_) {
              // best-effort: skip dir timestamps if stat fails
            }
          }

          final remoteBase = hasTrailingSlash
              ? targetFolderPathStr
              : p
                  .join(targetFolderPathStr, p.basename(localDir.path))
                  .replaceAll('\\', '/');

          await inxt_drive.createFolderRecursive(
            driveApiUrl,
            bearerToken,
            rootFolderId,
            folderCache,
            fileCache,
            remoteBase,
            creationTime: dirCreationTime,
            modificationTime: dirModTime,
          );

          final filesInDir =
              localDir.list(recursive: true, followLinks: false);
          await for (final fileEntity in filesInDir) {
            if (fileEntity is io.File) {
              final relativePath =
                  p.relative(fileEntity.path, from: localDir.path);
              final remoteFilePath =
                  p.join(remoteBase, relativePath).replaceAll('\\', '/');

              if (inxt_utils.shouldIncludeFile(
                  p.basename(fileEntity.path), include, exclude)) {
                tasks.add({
                  'localPath': fileEntity.path,
                  'remotePath': remoteFilePath,
                  'status': 'pending',
                });
              }
            }
          }
        } else if (await io.FileSystemEntity.isFile(entity.path)) {
          final localFile = io.File(entity.path);
          final remoteFilePath = p
              .join(targetFolderPathStr, p.basename(localFile.path))
              .replaceAll('\\', '/');

          if (inxt_utils.shouldIncludeFile(
              p.basename(localFile.path), include, exclude)) {
            tasks.add({
              'localPath': localFile.path,
              'remotePath': remoteFilePath,
              'status': 'pending',
            });
          }
        }
      }
    }
    batchState = {
      'operationType': 'upload',
      'targetRemotePath': targetPath,
      'tasks': tasks,
    };
    await saveStateCallback(batchState);
    print('📝 Task list generated with ${tasks.length} files.');
  }

  var successCount = 0;
  var skippedCount = 0;
  var errorCount = 0;
  var completedPreviously = 0;

  for (var i = 0; i < tasks.length; i++) {
    final task = tasks[i] as Map<String, dynamic>;
    final localPath = task['localPath'] as String;
    final remotePath = task['remotePath'] as String;
    final status = task['status'] as String;

    final localFile = io.File(localPath);
    if (!await localFile.exists()) {
      print('⚠️ Source file no longer exists, skipping: $localPath');
      skippedCount++;
      task['status'] = 'skipped_missing_source';
      await saveStateCallback(batchState);
      continue;
    }

    if (status == 'completed') {
      completedPreviously++;
      continue;
    }

    if (status.startsWith('skipped')) {
      skippedCount++;
      continue;
    }

    final remoteParentPath = p.dirname(remotePath).replaceAll('\\', '/');
    Map<String, dynamic> parentFolderInfo;
    try {
      parentFolderInfo = await inxt_drive.createFolderRecursive(driveApiUrl,
          bearerToken, rootFolderId, folderCache, fileCache, remoteParentPath);
    } catch (createErr) {
      print(
          '     ❌ Error ensuring parent folder $remoteParentPath: $createErr');
      errorCount++;
      task['status'] = 'error_create_parent';
      await saveStateCallback(batchState);
      continue;
    }

    final result = await uploadSingleItem(
      networkUrl,
      driveApiUrl,
      bearerToken,
      rootFolderId,
      mnemonic,
      bucketId,
      folderCache,
      fileCache,
      localFile,
      remoteParentPath,
      parentFolderInfo['uuid'],
      onConflict,
      bridgeUser: bridgeUser,
      userIdForAuth: userIdForAuth,
      preserveTimestamps: preserveTimestamps,
      remoteFileName: p.basename(remotePath),
    );

    if (result == 'uploaded') {
      successCount++;
      task['status'] = 'completed';
    } else if (result == 'skipped') {
      skippedCount++;
      task['status'] = 'skipped_conflict';
    } else {
      errorCount++;
      task['status'] = 'error_upload';
    }
    await saveStateCallback(batchState);
  }

  print('=' * 40);
  print('📊 Batch Upload Summary:');
  if (completedPreviously > 0) {
    print('  ✅ Completed (previous run): $completedPreviously');
  }
  print('  ✅ Uploaded (this run): $successCount');
  print('  ⏭️  Skipped:  $skippedCount');
  print('  ❌ Errors:   $errorCount');
  print('=' * 40);

  if (errorCount > 0) {
    throw Exception(
        'Upload completed with $errorCount errors. State file kept for inspection/retry.');
  }
}
