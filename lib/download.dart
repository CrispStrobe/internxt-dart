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
import 'upload.dart' as inxt_upload; // runBoundedPool + MemoryGate (Step B)
import 'utils.dart' as inxt_utils;

// =============================================================================
// STEP B — PARALLEL RANGED DOWNLOADS (opt-in)
// =============================================================================
//
// A single presigned S3 GET is split into N 16-byte-aligned ranges fetched
// concurrently (S3 honours HTTP Range) and CTR-decrypted at their offsets
// (AES-CTR is seekable — see crypto.decryptStreamAt). This parallelises the
// network transfer for large files. Falls back to a single GET if the server
// ignores Range (200 not 206) or the file is small. Toggled by the CLI
// `download --ranged` flag, which sets [rangedDownload].

/// 30 MB ranges (a multiple of the 16-byte AES block).
const int downloadPartSize = 30 * 1024 * 1024;

/// Only parallelise downloads at or above this size (the probe round-trip
/// isn't worth it for small files).
const int rangedDownloadMinSize = 100 * 1024 * 1024;

const int defaultDownloadChunkWorkers = 4;

/// How many ranges may be in flight at once for a single file. Set by the CLI.
int downloadChunkWorkers = defaultDownloadChunkWorkers;

/// Whether large in-memory downloads use the parallel ranged path. Set by the
/// CLI `download --ranged` flag.
bool rangedDownload = false;

class _RangeNotSupported implements Exception {}

/// Sequential single-GET + one-shot CTR decrypt (the original download body).
Future<Uint8List> _sequentialDownloadAndDecrypt(
  String url,
  String mnemonic,
  String bucketId,
  String fileIndexHex,
) async {
  final resp = await http.get(Uri.parse(url));
  if (resp.statusCode != 200) {
    throw Exception('Failed to download file: ${resp.statusCode}');
  }
  return inxt_crypto.decryptStream(
      resp.bodyBytes, mnemonic, bucketId, fileIndexHex);
}

/// Fetch the file as N 16-byte-aligned ranges concurrently, CTR-decrypt each at
/// its offset, and assemble the plaintext. Returns null if the endpoint ignores
/// Range on the 1-byte probe (caller falls back to a single GET). Ranges finish
/// out of order but are placed at their byte offset, so the result is identical
/// to the sequential decrypt. Bounded by the worker pool and the memory gate.
Future<Uint8List?> downloadRangedToMemory(
  String url,
  int fileSize,
  String mnemonic,
  String bucketId,
  String fileIndexHex, {
  int? chunkWorkers,
  int? partSize,
}) async {
  final pSize = partSize ?? downloadPartSize;
  final nParts = (fileSize / pSize).ceil();

  // Cheap 1-byte probe: bail to the sequential path before any real work.
  final probe = await http.get(Uri.parse(url), headers: {'Range': 'bytes=0-0'});
  if (probe.statusCode != 206) return null;

  final out = Uint8List(fileSize);
  final workers = (chunkWorkers ?? downloadChunkWorkers).clamp(1, nParts);
  await inxt_upload.runBoundedPool<int>(
    List<int>.generate(nParts, (i) => i),
    workers,
    (i) async {
      final start = i * pSize;
      final end = (start + pSize < fileSize) ? start + pSize : fileSize;
      final length = end - start;
      await inxt_upload.MemoryGate.acquire(length);
      try {
        final resp = await http
            .get(Uri.parse(url), headers: {'Range': 'bytes=$start-${end - 1}'});
        if (resp.statusCode != 206) throw _RangeNotSupported();
        final plain = inxt_crypto.decryptStreamAt(
            resp.bodyBytes, mnemonic, bucketId, fileIndexHex, start);
        out.setRange(start, end, plain);
      } finally {
        inxt_upload.MemoryGate.release(length);
      }
    },
  );
  return out;
}

/// NATIVE disk-streaming ranged download (peak RAM bounded by in-flight ranges,
/// NOT the file size — unlike [downloadRangedToMemory]). Fetches N
/// 16-byte-aligned ranges concurrently, CTR-decrypts each at its offset, and
/// writes positionally into [raf]. Returns false if the endpoint ignores Range
/// on the 1-byte probe (caller falls back to a sequential stream).
///
/// Cross-platform: uses only `dart:io` [io.RandomAccessFile] sync seek+write,
/// which is atomic on Dart's single-threaded event loop (no `await` between
/// `setPositionSync` and `writeFromSync`, so concurrent range workers can't
/// interleave a write). Workers COLLECT errors rather than throwing, so the
/// pool always drains fully before the caller closes [raf] (no dangling writes
/// to a closed handle — [inxt_upload.runBoundedPool] does not cancel siblings
/// on the first error).
Future<bool> downloadRangedToFile(
  String url,
  int fileSize,
  String mnemonic,
  String bucketId,
  String fileIndexHex,
  io.RandomAccessFile raf, {
  int? chunkWorkers,
  int? partSize,
}) async {
  final pSize = partSize ?? downloadPartSize;
  final nParts = (fileSize / pSize).ceil();

  // Cheap 1-byte probe: bail to the sequential path before any real work.
  final probe = await http.get(Uri.parse(url), headers: {'Range': 'bytes=0-0'});
  if (probe.statusCode != 206) return false;

  raf.setPositionSync(0);
  await raf.truncate(fileSize);

  final errors = <Object>[];
  final workers = (chunkWorkers ?? downloadChunkWorkers).clamp(1, nParts);
  await inxt_upload.runBoundedPool<int>(
    List<int>.generate(nParts, (i) => i),
    workers,
    (i) async {
      if (errors.isNotEmpty) return; // stop dispatching once one range failed
      final start = i * pSize;
      final end = (start + pSize < fileSize) ? start + pSize : fileSize;
      final length = end - start;
      await inxt_upload.MemoryGate.acquire(length);
      try {
        final resp = await http
            .get(Uri.parse(url), headers: {'Range': 'bytes=$start-${end - 1}'});
        if (resp.statusCode != 206) {
          errors.add(_RangeNotSupported());
          return;
        }
        final plain = inxt_crypto.decryptStreamAt(
            resp.bodyBytes, mnemonic, bucketId, fileIndexHex, start);
        final n = plain.length < length ? plain.length : length;
        // Atomic seek+write: both sync, no await between → no interleaving.
        raf.setPositionSync(start);
        raf.writeFromSync(plain, 0, n);
      } catch (e) {
        errors.add(e);
      } finally {
        inxt_upload.MemoryGate.release(length);
      }
    },
  );

  if (errors.isNotEmpty) {
    final first = errors.first;
    if (first is _RangeNotSupported) return false; // → sequential fallback
    throw Exception('Ranged download failed: $first');
  }
  return true;
}

/// Single streaming GET decrypted chunk-by-chunk straight to [file] via an
/// incremental AES-CTR cipher — peak RAM is one network chunk, not the whole
/// file. The disk-path counterpart of [_sequentialDownloadAndDecrypt].
Future<void> _sequentialStreamToFile(
  String url,
  int fileSize,
  String mnemonic,
  String bucketId,
  String fileIndexHex,
  io.File file,
) async {
  final client = http.Client(); // honors runWithClient zone (testable)
  try {
    final response = await client.send(http.Request('GET', Uri.parse(url)));
    if (response.statusCode != 200) {
      throw Exception('Failed to download file: ${response.statusCode}');
    }
    final cipher =
        inxt_crypto.downloadDecryptor(mnemonic, bucketId, fileIndexHex);
    final raf = await file.open(mode: io.FileMode.write);
    try {
      await for (final chunk in response.stream) {
        final bytes = chunk is Uint8List ? chunk : Uint8List.fromList(chunk);
        final plain = cipher.process(bytes);
        raf.writeFromSync(plain);
      }
      raf.truncateSync(fileSize); // defensive: AES-CTR adds no padding
    } finally {
      await raf.close();
    }
  } finally {
    client.close();
  }
}

/// NATIVE disk download orchestrator used by the CLI (`download` /
/// `download-path`). Resolves metadata + links, then writes the decrypted file
/// to [destinationPath] with peak RAM bounded regardless of file size: parallel
/// ranged-to-disk when [rangedDownload] is on and the file is large (falling
/// back to a single streaming GET if the server ignores Range), otherwise a
/// single streaming GET. Returns metadata (`filename`, `size`,
/// `modificationTime`) — NOT the bytes; the caller applies timestamps.
///
/// [destinationPath] may be a directory (the remote filename is appended), a
/// full file path (used verbatim), or null (remote filename in the CWD). This
/// is the bounded-memory analogue of [downloadFile]; the in-memory functions
/// ([downloadFile] / [downloadFileBytes]) are unchanged for consumers (WebDAV,
/// Flutter/Web) that need the bytes in memory.
Future<Map<String, dynamic>> downloadFileToDisk(
  String driveApiUrl,
  String networkUrl,
  String? bearerToken,
  String mnemonic,
  String fileUuid,
  String? destinationPath,
  String bridgeUser,
  String userIdForAuth,
) async {
  final metadata =
      await inxt_api.getFileMetadata(driveApiUrl, bearerToken, fileUuid);
  final bucketId = metadata['bucket'] as String;
  final networkFileId = metadata['fileId'] as String;
  final fileSize = metadata['size'] is int
      ? metadata['size'] as int
      : int.tryParse(metadata['size'].toString()) ?? 0;
  final fileName = (metadata['plainName'] ?? 'file') as String;
  final fileType = (metadata['type'] ?? '') as String;
  final filename = fileType.isNotEmpty ? '$fileName.$fileType' : fileName;
  final modificationTime =
      (metadata['modificationTime'] ?? metadata['updatedAt']) as String?;

  // Resolve the final on-disk path.
  String finalPath;
  if (destinationPath == null) {
    finalPath = filename;
  } else if (io.FileSystemEntity.typeSync(destinationPath) ==
      io.FileSystemEntityType.directory) {
    finalPath = p.join(destinationPath, filename);
  } else {
    finalPath = destinationPath;
  }
  final file = io.File(finalPath);
  await file.parent.create(recursive: true);

  final bridgePass = inxt_auth.computeBridgePass(userIdForAuth);
  final links = await getDownloadLinks(
      networkUrl, bucketId, networkFileId, bridgeUser, bridgePass);
  final downloadUrl = links['shards'][0]['url'] as String;
  final fileIndexHex = links['index'] as String;

  var done = false;
  if (rangedDownload && fileSize >= rangedDownloadMinSize) {
    print('   ⛓️  Ranged download: '
        '${(fileSize / downloadPartSize).ceil()} range(s)');
    final raf = await file.open(mode: io.FileMode.write);
    try {
      done = await downloadRangedToFile(
          downloadUrl, fileSize, mnemonic, bucketId, fileIndexHex, raf);
    } on _RangeNotSupported {
      done = false;
    } finally {
      await raf.close();
    }
    if (!done) {
      print(
          '   ↩️  Server ignored Range (HTTP 200) — single sequential stream');
    }
  }
  if (!done) {
    await _sequentialStreamToFile(
        downloadUrl, fileSize, mnemonic, bucketId, fileIndexHex, file);
  }

  return {
    'filename': filename,
    'size': fileSize,
    'modificationTime': modificationTime,
  };
}

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
  String pass, {
  http.Client? client,
}) async {
  final response = await inxt_api.makeRequest(
    'GET',
    Uri.parse('$networkUrl/buckets/$bucketId/files/$fileId/info'),
    headers: {'x-api-version': '2'},
    useAuth: false,
    isNetworkAuth: true,
    networkUser: user,
    networkPass: pass,
    client: client,
  );
  return json.decode(response.body) as Map<String, dynamic>;
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
  final bucketId = metadata['bucket'] as String;
  final networkFileId = metadata['fileId'] as String;

  final fileSize = metadata['size'] is int
      ? metadata['size'] as int
      : int.tryParse(metadata['size'].toString()) ?? 0;

  final fileName = (metadata['plainName'] ?? 'file') as String;
  final fileType = (metadata['type'] ?? '') as String;
  final filename = fileType.isNotEmpty ? '$fileName.$fileType' : fileName;

  final modificationTime =
      (metadata['modificationTime'] ?? metadata['updatedAt']) as String?;

  print('   📄 File: $filename');
  print('   📊 Size: ${inxt_utils.formatSize(fileSize)}');

  final bridgePass = inxt_auth.computeBridgePass(userIdForAuth);

  print('   🔗 Fetching download links...');
  final linksResponse = await getDownloadLinks(
      networkUrl, bucketId, networkFileId, bridgeUser, bridgePass);
  final downloadUrl = linksResponse['shards'][0]['url'] as String;
  final fileIndexHex = linksResponse['index'] as String;

  print('   ☁️  Downloading encrypted data...');
  Uint8List decryptedData;
  if (rangedDownload && fileSize >= rangedDownloadMinSize) {
    print('   ⛓️  Ranged download: '
        '${(fileSize / downloadPartSize).ceil()} range(s)');
    Uint8List? ranged;
    try {
      ranged = await downloadRangedToMemory(
          downloadUrl, fileSize, mnemonic, bucketId, fileIndexHex);
    } on _RangeNotSupported {
      ranged = null;
    }
    if (ranged != null) {
      decryptedData = ranged;
    } else {
      print('   ↩️  Server ignored Range (HTTP 200) — single sequential GET');
      decryptedData = await _sequentialDownloadAndDecrypt(
          downloadUrl, mnemonic, bucketId, fileIndexHex);
    }
  } else {
    print('   🔐 Decrypting...');
    decryptedData = await _sequentialDownloadAndDecrypt(
        downloadUrl, mnemonic, bucketId, fileIndexHex);
  }

  return {
    'data': decryptedData.sublist(0, fileSize),
    'filename': filename,
    'modificationTime': modificationTime,
    'preserveTimestamps': preserveTimestamps,
  };
}

/// In-memory single-file download returning just the decrypted
/// bytes. Convenience wrapper for consumers (e.g. the cloud-dart
/// Flutter app's image preview / Web download) that don't want
/// the metadata-rich `Map` shape from [downloadFile].
///
/// Streams the encrypted payload chunk-by-chunk so [onProgress] can
/// report bytes-downloaded / content-length during the network read.
/// Decryption is still one-shot at the end (same constraint as
/// [downloadFileStreamed] — AES-CTR streaming would require a
/// different decrypt API).
///
/// `onProgress` is invoked with `(bytesDownloaded, totalBytes)` per
/// HTTP chunk; `totalBytes` is `-1` if the response has no
/// `Content-Length` header.
Future<Uint8List> downloadFileBytes(
  String driveApiUrl,
  String networkUrl,
  String? bearerToken,
  String mnemonic,
  String fileUuid,
  String bridgeUser,
  String userIdForAuth, {
  void Function(int bytesDownloaded, int totalBytes)? onProgress,
  http.Client? httpClient,
}) async {
  final metadata = await inxt_api
      .getFileMetadata(driveApiUrl, bearerToken, fileUuid, client: httpClient);
  final fileSize = int.parse(metadata['size'].toString());
  final bucketId = metadata['bucket'] as String;
  final networkFileId = metadata['fileId'] as String;

  final bridgePass = inxt_auth.computeBridgePass(userIdForAuth);
  final links = await getDownloadLinks(
      networkUrl, bucketId, networkFileId, bridgeUser, bridgePass,
      client: httpClient);
  final downloadUrl = links['shards'][0]['url'] as String;
  final fileIndexHex = links['index'] as String;

  final ownsClient = httpClient == null;
  final client = httpClient ?? http.Client();
  try {
    final request = http.Request('GET', Uri.parse(downloadUrl));
    final response = await client.send(request);
    if (response.statusCode != 200) {
      throw Exception('Failed to download file: ${response.statusCode}');
    }

    final total = response.contentLength ?? -1;
    final builder = BytesBuilder(copy: false);
    var downloaded = 0;
    await for (final chunk in response.stream) {
      builder.add(chunk);
      downloaded += chunk.length;
      if (onProgress != null) onProgress(downloaded, total);
    }

    final decryptedData = inxt_crypto.decryptStream(
      builder.toBytes(),
      mnemonic,
      bucketId,
      fileIndexHex,
    );
    return Uint8List.fromList(decryptedData.sublist(0, fileSize));
  } finally {
    if (ownsClient) client.close();
  }
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
  final fileName = (metadata['plainName'] ?? 'file') as String;
  final fileType = (metadata['type'] ?? '') as String;
  final fullFileName = fileType.isNotEmpty ? '$fileName.$fileType' : fileName;

  final bridgePass = inxt_auth.computeBridgePass(userIdForAuth);
  final links = await getDownloadLinks(networkUrl, metadata['bucket'] as String,
      metadata['fileId'] as String, bridgeUser, bridgePass);
  final downloadUrl = links['shards'][0]['url'] as String;
  final fileIndexHex = links['index'] as String;

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
      metadata['bucket'] as String,
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
    final plainName = (metadata['name'] ?? 'file') as String;
    final fileType = (metadata['fileType'] ?? '') as String;
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

    // Bounded-memory disk download (parallel ranged when enabled + large,
    // else a single streaming GET). Writes straight to disk — peak RAM is the
    // chunk/range size, not the file size.
    final downloadResult = await downloadFileToDisk(
      driveApiUrl,
      networkUrl,
      bearerToken,
      mnemonic,
      itemInfo['uuid'] as String,
      localPath,
      bridgeUser,
      userIdForAuth,
    );

    if (preserveTimestamps && downloadResult['modificationTime'] != null) {
      try {
        final mTime =
            DateTime.parse(downloadResult['modificationTime'] as String);
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
          final plainName = (fileInfo['name'] ?? 'file') as String;
          final fileType = (fileInfo['fileType'] ?? '') as String;
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
          final folderName = (folderInfo['name'] ?? 'subfolder') as String;
          final nextLocalRelPath = p.join(currentLocalRelPath, folderName);
          final localSubDir =
              io.Directory(p.join(baseDestPath, nextLocalRelPath));
          await localSubDir.create(recursive: true);
          // Note: Dart's Directory class does not expose setLastModified
          // — folder timestamps cannot be preserved on download.
          await buildDownloadTasks(
              folderInfo['uuid'] as String, nextLocalRelPath);
        }
      }

      await buildDownloadTasks(itemInfo['uuid'] as String, '');
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
        final downloadResult = await downloadFileToDisk(
          driveApiUrl,
          networkUrl,
          bearerToken,
          mnemonic,
          remoteUuid,
          localPath,
          bridgeUser,
          userIdForAuth,
        );

        final modTimeStr =
            (downloadResult['modificationTime'] ?? remoteModTime) as String?;
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
