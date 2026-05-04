// Path-based facade methods for InternxtClient.
//
// Phase 6.a B2. The protocol layer takes UUIDs; library consumers
// (cloud-dart's adapter and any future non-CLI caller) want path-
// based ergonomics. These extension methods do the resolvePath
// step internally and delegate to the existing UUID-based methods.
//
// Sourced from cloud-dart's internxt_client_extensions.dart with
// two improvements: hardcoded `onConflict: 'skip'` and
// `preserveTimestamps: false` are now named params with defaults,
// and the bridge-auth pair is read from InternxtClient state
// (populated by setAuth) instead of being passed by the caller.

import 'dart:io' as io;
import 'dart:typed_data';

import 'package:path/path.dart' as p;

import 'cli.dart' show InternxtClient;
import 'download.dart' as inxt_download;

extension InternxtClientPaths on InternxtClient {
  /// Resolves [path] (must be a folder) and returns
  /// `{folders: [...], files: [...]}` — the folders and files
  /// directly inside it. Both lists carry the detailed listing
  /// (timestamps + size + UUIDs).
  Future<Map<String, dynamic>> listPath(String path) async {
    final resolved = await resolvePath(path);
    if (resolved['type'] != 'folder') {
      throw Exception('Path is not a folder: $path');
    }
    final folderId = resolved['uuid'] as String;
    final folders = await listFolders(folderId, detailed: true);
    final files = await listFolderFiles(folderId, detailed: true);
    return {'folders': folders, 'files': files};
  }

  /// Uploads in-memory [fileData] as [fileName] under [targetPath]
  /// (must be a folder). Single-file convenience over the batch
  /// `upload(...)` API — writes the bytes to a temp file, runs the
  /// pipeline, cleans up.
  ///
  /// Requires a session: setAuth must have been called so the
  /// bridge-auth pair is populated.
  Future<void> uploadFileBytes(
    List<int> fileData,
    String fileName,
    String targetPath, {
    String onConflict = 'skip',
    bool preserveTimestamps = false,
  }) async {
    _requireSession();
    final tempDir = io.Directory.systemTemp;
    final tempFile = io.File(p.join(tempDir.path, fileName));
    await tempFile.writeAsBytes(fileData);
    try {
      final batchId =
          config.generateBatchId('upload-bytes', [tempFile.path], targetPath);
      await upload(
        [tempFile.path],
        targetPath,
        recursive: false,
        onConflict: onConflict,
        preserveTimestamps: preserveTimestamps,
        include: const [],
        exclude: const [],
        bridgeUser: bridgeUser!,
        userIdForAuth: userIdForAuth!,
        batchId: batchId,
        saveStateCallback: (_) async {},
      );
    } finally {
      if (await tempFile.exists()) {
        await tempFile.delete();
      }
    }
  }

  /// Downloads the file at [remotePath] to [localPath].
  ///
  /// If the resolved remote name differs from [localPath]'s basename,
  /// the downloaded file is renamed in place to match. Cloud-dart's
  /// original behavior, preserved for adapter compatibility.
  Future<void> downloadFileByPath(
    String remotePath,
    String localPath, {
    String onConflict = 'skip',
    bool preserveTimestamps = false,
  }) async {
    _requireSession();
    final resolved = await resolvePath(remotePath);
    if (resolved['type'] != 'file') {
      throw Exception('Path is not a file: $remotePath');
    }
    final localDir = io.File(localPath).parent.path;
    final batchId =
        config.generateBatchId('download-bypath', [remotePath], localPath);
    await downloadPath(
      remotePath,
      localDestination: localDir,
      recursive: false,
      onConflict: onConflict,
      preserveTimestamps: preserveTimestamps,
      include: const [],
      exclude: const [],
      bridgeUser: bridgeUser!,
      userIdForAuth: userIdForAuth!,
      batchId: batchId,
      saveStateCallback: (_) async {},
    );

    final downloadedName = (resolved['name'] ?? '') as String;
    final expectedPath = p.join(localDir, downloadedName);
    if (downloadedName.isNotEmpty &&
        expectedPath != localPath &&
        io.File(expectedPath).existsSync()) {
      try {
        if (io.File(localPath).existsSync()) {
          await io.File(localPath).delete();
        }
        await io.File(expectedPath).rename(localPath);
      } catch (_) {
        // Rename is best-effort: if it fails, the file is still
        // present at the resolved-name path.
      }
    }
  }

  /// Path-based wrapper around `downloadFileBytes(uuid, …)`. Resolves
  /// the path then returns just the decrypted bytes. For consumers
  /// (image preview, in-RAM download) that don't need an on-disk file.
  Future<Uint8List> downloadFileBytesByPath(
    String remotePath, {
    void Function(int bytesDownloaded, int totalBytes)? onProgress,
  }) async {
    _requireSession();
    final resolved = await resolvePath(remotePath);
    if (resolved['type'] != 'file') {
      throw Exception('Path is not a file: $remotePath');
    }
    return inxt_download.downloadFileBytes(
      driveApiUrl,
      networkUrl,
      newToken,
      mnemonic!,
      resolved['uuid'] as String,
      bridgeUser!,
      userIdForAuth!,
      onProgress: onProgress,
    );
  }

  /// Creates the folder at [path], including any missing
  /// intermediate folders.
  Future<void> createFolderPath(String path) async {
    await createFolderRecursive(path);
  }

  /// Trashes the item at [path] (file or folder). Same destructive
  /// semantics as the CLI's `trash` command — restorable until the
  /// trash is cleared.
  Future<void> deletePath(String path) async {
    final resolved = await resolvePath(path);
    await trashItems(resolved['uuid'] as String, resolved['type'] as String);
  }

  /// Moves the item at [sourcePath] into [targetPath] (must be a
  /// folder).
  Future<void> movePath(String sourcePath, String targetPath) async {
    final source = await resolvePath(sourcePath);
    final target = await resolvePath(targetPath);
    if (target['type'] != 'folder') {
      throw Exception('Target path is not a folder: $targetPath');
    }
    final destUuid = target['uuid'] as String;
    if (source['type'] == 'file') {
      await moveFile(source['uuid'] as String, destUuid);
    } else {
      await moveFolder(source['uuid'] as String, destUuid);
    }
  }

  /// Renames the item at [path] to [newName]. For files, splits
  /// [newName] on the last `.` to extract an extension (Internxt's
  /// rename API takes plainName and type separately).
  Future<void> renamePath(String path, String newName) async {
    final resolved = await resolvePath(path);
    if (resolved['type'] == 'file') {
      final (plainName, extension) = splitFileNameForRename(newName);
      await renameFile(resolved['uuid'] as String, plainName, extension);
    } else {
      await renameFolder(resolved['uuid'] as String, newName);
    }
  }

  void _requireSession() {
    if (bridgeUser == null || userIdForAuth == null || mnemonic == null) {
      throw StateError(
          'InternxtClient not authenticated — call setAuth(creds) first.');
    }
  }
}

/// Splits a filename into `(plainName, extension)` for Internxt's
/// rename-file API. Extension is the part after the last `.`; if
/// the name has no `.` (or starts with `.`, or ends with `.`), the
/// extension is null and plainName is the whole input.
///
/// Exposed at top level (not just inline in `renamePath`) so the
/// split rules are unit-testable independently of the network call.
(String, String?) splitFileNameForRename(String fileName) {
  final dot = fileName.lastIndexOf('.');
  if (dot <= 0 || dot >= fileName.length - 1) {
    return (fileName, null);
  }
  return (fileName.substring(0, dot), fileName.substring(dot + 1));
}
