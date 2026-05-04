// Download pipeline — fetch metadata, fetch links, GET, decrypt.
//
// Extracted from cli.dart in Phase 4.j (final extraction). Owns the
// download flow:
// - getDownloadLinks: GET /buckets/{id}/files/{id}/info with network
//   basic auth, returns the shard URL and the file-index hex needed
//   for decryption.
// - downloadFile: in-memory fetch+decrypt, returns the bytes plus
//   metadata for the caller to write.
// - downloadFileStreamed: streamed download with stdout progress,
//   writes directly to disk.
// - downloadPath: top-level entry point — resolves the remote path,
//   dispatches to single-file or recursive-folder download, with
//   resumable batch state.
//
// State convention: nothing here holds instance state. Callers pass
// (driveApiUrl, networkUrl, bearerToken, rootFolderId, mnemonic),
// the cache maps, and the bridge auth credentials. Bridge basic-auth
// password is computed via `inxt_auth.computeBridgePass`.
//
// User-facing `print()` calls are preserved (download progress UX);
// `log()` debug noise was dropped per the extraction pattern.

import 'dart:convert';
import 'dart:io' as io;
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:path/path.dart' as p;

import 'api.dart' as inxt_api;
import 'auth.dart' as inxt_auth;
import 'cache.dart' as inxt_cache;
import 'crypto.dart' as inxt_crypto;
import 'drive.dart' as inxt_drive;
import 'utils.dart' as inxt_utils;

/// GET /buckets/{bucketId}/files/{fileId}/info with network basic
/// auth. Returns `{shards: [{url, ...}], index, ...}` — the caller
/// uses `shards[0].url` as the download URL and `index` as the
/// per-file decryption index hex.
///
/// `pass` must be the SHA-256 hex of the user ID (i.e.
/// `inxt_auth.computeBridgePass(userId)`).
Future<Map<String, dynamic>> getDownloadLinks(
  String networkUrl,
  String bucketId,
  String fileId,
  String user,
  String pass,
) async {
  final response = await inxt_api.makeRequest(
    'GET',
    Uri.parse('$networkUrl/buckets/$bucketId/files/$fileId/info'),
    headers: {'x-api-version': '2'},
    useAuth: false,
    isNetworkAuth: true,
    networkUser: user,
    networkPass: pass,
  );
  return json.decode(response.body);
}

/// In-memory single-file download.
///
/// Returns `{data, filename, modificationTime, preserveTimestamps}`
/// — the caller is responsible for writing the bytes to disk and
/// applying timestamps. This split exists because some callers
/// (e.g. WebDAV GET) want the bytes in memory rather than on disk.
Future<Map<String, dynamic>> downloadFile(
  String driveApiUrl,
  String networkUrl,
  String? bearerToken,
  String mnemonic,
  String fileUuid,
  String bridgeUser,
  String userIdForAuth, {
  bool preserveTimestamps = false,
}) async {
  print('   📋 Fetching file metadata...');
  final metadata =
      await inxt_api.getFileMetadata(driveApiUrl, bearerToken, fileUuid);
  final bucketId = metadata['bucket'];
  final networkFileId = metadata['fileId'];

  final fileSize = metadata['size'] is int
      ? metadata['size'] as int
      : int.tryParse(metadata['size'].toString()) ?? 0;

  final fileName = metadata['plainName'] ?? 'file';
  final fileType = metadata['type'] ?? '';
  final filename = fileType.isNotEmpty ? '$fileName.$fileType' : fileName;

  final modificationTime =
      metadata['modificationTime'] ?? metadata['updatedAt'];

  print('   📄 File: $filename');
  print('   📊 Size: ${inxt_utils.formatSize(fileSize)}');

  final bridgePass = inxt_auth.computeBridgePass(userIdForAuth);

  print('   🔗 Fetching download links...');
  final linksResponse = await getDownloadLinks(
      networkUrl, bucketId, networkFileId, bridgeUser, bridgePass);
  final downloadUrl = linksResponse['shards'][0]['url'];
  final fileIndexHex = linksResponse['index'];

  print('   ☁️  Downloading encrypted data...');
  final downloadResponse = await http.get(Uri.parse(downloadUrl));
  if (downloadResponse.statusCode != 200) {
    throw Exception('Failed to download file: ${downloadResponse.statusCode}');
  }
  final encryptedData = downloadResponse.bodyBytes;

  print('   🔐 Decrypting...');
  final decryptedData = inxt_crypto.decryptStream(
    encryptedData,
    mnemonic,
    bucketId,
    fileIndexHex,
  );

  return {
    'data': decryptedData.sublist(0, fileSize),
    'filename': filename,
    'modificationTime': modificationTime,
    'preserveTimestamps': preserveTimestamps,
  };
}

/// Streamed single-file download — same flow as [downloadFile] but
/// writes the encrypted bytes to memory chunk-by-chunk while
/// rendering a stdout progress indicator, then decrypts and writes
/// to [destinationPath].
///
/// Note: still buffers the entire encrypted payload in memory before
/// decrypting. The "streaming" is in the network read; decryption
/// is done in one shot. Same as the monolith. A truly streaming
/// decrypt would need an AES-CTR streaming cipher.
Future<Map<String, dynamic>> downloadFileStreamed(
  String driveApiUrl,
  String networkUrl,
  String? bearerToken,
  String mnemonic,
  String fileUuid,
  String destinationPath,
  String bridgeUser,
  String userIdForAuth,
) async {
  final metadata =
      await inxt_api.getFileMetadata(driveApiUrl, bearerToken, fileUuid);
  final fileSize = int.parse(metadata['size'].toString());
  final fileName = metadata['plainName'] ?? 'file';
  final fileType = metadata['type'] ?? '';
  final fullFileName = fileType.isNotEmpty ? '$fileName.$fileType' : fileName;

  final bridgePass = inxt_auth.computeBridgePass(userIdForAuth);
  final links = await getDownloadLinks(networkUrl, metadata['bucket'],
      metadata['fileId'], bridgeUser, bridgePass);
  final downloadUrl = links['shards'][0]['url'];
  final fileIndexHex = links['index'];

  final client = http.Client();
  final request = http.Request('GET', Uri.parse(downloadUrl));
  final response = await client.send(request);

  var downloaded = 0;
  final encryptedBuffer = <int>[];
  final stopwatch = Stopwatch()..start();

  await for (var chunk in response.stream) {
    encryptedBuffer.addAll(chunk);
    downloaded += chunk.length;

    final percent =
        (downloaded / response.contentLength! * 100).toStringAsFixed(1);
    io.stdout.write(
        '\r        Progress: $percent% (${inxt_utils.formatSize(downloaded)}) [${inxt_utils.formatSize(downloaded / (stopwatch.elapsedMilliseconds / 1000 + 0.001))}/s]   ');
  }
  print('');

  final decryptedData = inxt_crypto.decryptStream(
      Uint8List.fromList(encryptedBuffer),
      mnemonic,
      metadata['bucket'],
      fileIndexHex);

  final file = io.File(destinationPath);
  await file.writeAsBytes(decryptedData.sublist(0, fileSize));

  return {
    'filename': fullFileName,
    'size': fileSize,
    'modificationTime': metadata['modificationTime'] ?? metadata['updatedAt'],
  };
}

/// Top-level download dispatcher: resolves [remotePath] and either
/// downloads a single file (with conflict policy) or, if `recursive`,
/// walks the folder tree generating per-file tasks and persisting a
/// batch state for resumability.
///
/// Single-file behavior:
/// - `localDestination` may be a directory (file is dropped inside)
///   or a file path (used verbatim) or null (uses the remote name).
/// - `onConflict='skip'` and an existing local file → returns early.
/// - `preserveTimestamps` and a metadata `modificationTime` → applies
///   it via `setLastModified`.
///
/// Recursive folder behavior:
/// - `recursive=false` on a folder path throws.
/// - Walks the tree depth-first via `listFolders` / `listFolderFiles`,
///   builds a flat task list, persists state, and downloads each task
///   sequentially.
/// - Errors per-task are counted; if any errors occurred, throws at
///   the end so the CLI exits non-zero (state file preserved).
Future<void> downloadPath(
  String driveApiUrl,
  String networkUrl,
  String? bearerToken,
  String? rootFolderId,
  String mnemonic,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String remotePath, {
  String? localDestination,
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
  final itemInfo = await inxt_drive.resolvePath(driveApiUrl, bearerToken,
      rootFolderId, folderCache, fileCache, remotePath);

  if (itemInfo['type'] == 'file') {
    final metadata = itemInfo['metadata'] as Map<String, dynamic>;
    final plainName = metadata['name'] ?? 'file';
    final fileType = metadata['fileType'] ?? '';
    final remoteFilename =
        fileType.isNotEmpty ? '$plainName.$fileType' : plainName;

    if (!inxt_utils.shouldIncludeFile(remoteFilename, include, exclude)) {
      print(
          '🚫 File filtered out by include/exclude patterns: $remoteFilename');
      return;
    }

    String localPath;
    if (localDestination != null) {
      final destEntity = io.FileSystemEntity.typeSync(localDestination);
      if (destEntity == io.FileSystemEntityType.directory) {
        localPath = p.join(localDestination, remoteFilename);
      } else {
        localPath = localDestination;
      }
    } else {
      localPath = remoteFilename;
    }

    final localFile = io.File(localPath);

    if (await localFile.exists() && onConflict == 'skip') {
      print('⏭️  File exists, skipping: $localPath');
      return;
    }

    final downloadResult = await downloadFile(
      driveApiUrl,
      networkUrl,
      bearerToken,
      mnemonic,
      itemInfo['uuid'],
      bridgeUser,
      userIdForAuth,
      preserveTimestamps: preserveTimestamps,
    );

    await localFile.parent.create(recursive: true);
    await localFile.writeAsBytes(downloadResult['data']);

    if (preserveTimestamps && downloadResult['modificationTime'] != null) {
      try {
        final mTime = DateTime.parse(downloadResult['modificationTime']);
        await localFile.setLastModified(mTime);
        print('   🕐 Set modification time: $mTime');
      } catch (e) {
        print('   ⚠️  Could not set modification time: $e');
      }
    }

    print('\n🎉 Downloaded successfully!');
    print('📄 From: $remotePath');
    print('💾 To: $localPath');
    return;
  }

  if (itemInfo['type'] == 'folder') {
    if (!recursive) {
      throw Exception(
          "'$remotePath' is a folder. Use -r to download recursively.");
    }

    final baseDestPath = localDestination ??
        ((itemInfo['metadata']?['name'] ?? 'download') as String);
    final baseDestDir = io.Directory(baseDestPath);
    await baseDestDir.create(recursive: true);

    print('📂 Downloading folder recursively: $remotePath');
    print('💾 Target directory: ${baseDestDir.path}');

    Map<String, dynamic> batchState;
    List<dynamic> tasks;

    if (initialBatchState != null) {
      print('🔄 Resuming previous batch operation...');
      batchState = initialBatchState;
      tasks = batchState['tasks'] as List<dynamic>;
    } else {
      print('🔍 Generating new batch task list...');
      tasks = [];

      Future<void> buildDownloadTasks(
          String currentRemoteFolderUuid, String currentLocalRelPath) async {
        final files = await inxt_drive.listFolderFiles(
            driveApiUrl, bearerToken, fileCache, currentRemoteFolderUuid,
            detailed: true);
        final folders = await inxt_drive.listFolders(
            driveApiUrl, bearerToken, folderCache, currentRemoteFolderUuid,
            detailed: true);

        for (var fileInfo in files) {
          final plainName = fileInfo['name'] ?? 'file';
          final fileType = fileInfo['fileType'] ?? '';
          final remoteFilename =
              fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
          final localFilePath =
              p.join(baseDestPath, currentLocalRelPath, remoteFilename);

          if (inxt_utils.shouldIncludeFile(remoteFilename, include, exclude)) {
            tasks.add({
              'remoteUuid': fileInfo['uuid'],
              'localPath': localFilePath,
              'status': 'pending',
              'remoteModificationTime':
                  fileInfo['modificationTime'] ?? fileInfo['updatedAt'],
            });
          }
        }

        for (var folderInfo in folders) {
          final folderName = folderInfo['name'] ?? 'subfolder';
          final nextLocalRelPath = p.join(currentLocalRelPath, folderName);
          final localSubDir =
              io.Directory(p.join(baseDestPath, nextLocalRelPath));
          await localSubDir.create(recursive: true);
          // Note: Dart's Directory class does not expose setLastModified
          // — folder timestamps cannot be preserved on download.
          await buildDownloadTasks(folderInfo['uuid'], nextLocalRelPath);
        }
      }

      await buildDownloadTasks(itemInfo['uuid'], '');
      batchState = {
        'operationType': 'download',
        'remotePath': remotePath,
        'localDestination': baseDestPath,
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
      final remoteUuid = task['remoteUuid'] as String;
      final localPath = task['localPath'] as String;
      final status = task['status'] as String;
      final remoteModTime = task['remoteModificationTime'] as String?;

      if (status == 'completed') {
        completedPreviously++;
        continue;
      }
      if (status.startsWith('skipped')) {
        skippedCount++;
        continue;
      }

      final localFile = io.File(localPath);

      if (await localFile.exists() && onConflict == 'skip') {
        print('   ⏭️  Skipping existing: ${p.basename(localPath)}');
        skippedCount++;
        task['status'] = 'skipped_conflict';
        await saveStateCallback(batchState);
        continue;
      }

      try {
        print('   -> Downloading: ${p.basename(localPath)}');
        final downloadResult = await downloadFile(
          driveApiUrl,
          networkUrl,
          bearerToken,
          mnemonic,
          remoteUuid,
          bridgeUser,
          userIdForAuth,
          preserveTimestamps: preserveTimestamps,
        );

        await localFile.parent.create(recursive: true);
        await localFile.writeAsBytes(downloadResult['data']);

        final modTimeStr = downloadResult['modificationTime'] ?? remoteModTime;
        if (preserveTimestamps && modTimeStr != null) {
          try {
            final mTime = DateTime.parse(modTimeStr);
            await localFile.setLastModified(mTime);
          } catch (_) {
            // best-effort: skip mtime if unparseable
          }
        }
        successCount++;
        task['status'] = 'completed';
      } catch (e) {
        print('   -> ❌ Error downloading ${p.basename(localPath)}: $e');
        errorCount++;
        task['status'] = 'error_download';
      }
      await saveStateCallback(batchState);
    }

    print('=' * 40);
    print('📊 Batch Download Summary:');
    if (completedPreviously > 0) {
      print('  ✅ Completed (previous run): $completedPreviously');
    }
    print('  ✅ Downloaded (this run): $successCount');
    print('  ⏭️  Skipped:  $skippedCount');
    print('  ❌ Errors:   $errorCount');
    print('=' * 40);

    if (errorCount > 0) {
      throw Exception(
          'Download completed with $errorCount errors. State file kept for inspection/retry.');
    }
  }
}
