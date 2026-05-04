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

import 'dart:async';
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
import 'download.dart' as inxt_download;
import 'drive.dart' as inxt_drive;
import 'utils.dart' as inxt_utils;

// =============================================================================
// MEMORY-GATED UPLOAD CONCURRENCY (Phase 7.1)
// =============================================================================
//
// Mirrors the Python sibling's _mem_acquire/_mem_release. Without this,
// parallel uploads (Phase 7.2) of large files OOM the process; even a
// single ~5 GB upload on a 4 GB machine can trip the OS killer.
//
// The gate is a process-wide counter of "reserved bytes". Each upload
// reserves ~2 * file_size before reading the plaintext (we hold both
// plaintext and encrypted copy briefly during encrypt). On release the
// counter goes down and any waiting uploads re-check.
//
// _availableMemory() is best-effort cross-platform:
//   - Linux:   /proc/meminfo `MemAvailable`
//   - macOS:   `vm_stat` + `sysctl hw.pagesize`
//   - other:   _fallbackAvailableBytes (4 GB)
//
// Override for tests via [memoryGateOverride].

const int _safetyMarginBytes = 1 * 1024 * 1024 * 1024; // 1 GB
const int _fallbackAvailableBytes = 4 * 1024 * 1024 * 1024; // 4 GB

/// Test seam: set to a non-null value to force [_availableMemory] to
/// return a specific value. Production code leaves this null.
int? memoryGateOverride;

int _availableMemory() {
  if (memoryGateOverride != null) return memoryGateOverride!;
  try {
    if (io.Platform.isLinux) {
      final lines = io.File('/proc/meminfo').readAsLinesSync();
      for (final line in lines) {
        if (line.startsWith('MemAvailable:')) {
          final kb = int.parse(line.split(RegExp(r'\s+'))[1]);
          return kb * 1024;
        }
      }
    } else if (io.Platform.isMacOS) {
      final ps = int.parse(io.Process.runSync('sysctl', ['-n', 'hw.pagesize'])
          .stdout
          .toString()
          .trim());
      final vm =
          io.Process.runSync('vm_stat', []).stdout.toString();
      var free = 0;
      var spec = 0;
      for (final line in vm.split('\n')) {
        if (line.contains('Pages free')) {
          free = int.parse(
              line.split(':')[1].trim().replaceAll('.', ''));
        } else if (line.contains('Pages speculative')) {
          spec = int.parse(
              line.split(':')[1].trim().replaceAll('.', ''));
        }
      }
      return (free + spec) * ps;
    }
  } catch (_) {
    // best-effort: fall through to the fallback
  }
  return _fallbackAvailableBytes;
}

/// Process-wide memory gate for upload concurrency. Single-threaded
/// Dart so the counter doesn't need a mutex; the async-friendly
/// "wake waiters" pattern is implemented with completers + a 5-second
/// timeout poll (re-check the OS memory in case the OS released
/// caches between waits).
///
/// Public for testability — test/upload_test.dart pokes at the
/// counter directly. Production callers should not touch this class
/// outside of `acquire` / `release` / `currentReserved`.
class MemoryGate {
  static int _reserved = 0;
  static final List<Completer<void>> _waiters = [];

  /// Total currently reserved across all in-flight uploads.
  static int get currentReserved => _reserved;

  /// Number of waiters parked on the gate. Test-only signal.
  static int get waiterCount => _waiters.length;

  /// Reserve [need] bytes. Returns when the reservation succeeds.
  /// If no other reservation is active but the OS reports tight
  /// memory anyway, we let one through to avoid deadlock — caches
  /// are typically reclaimable.
  static Future<void> acquire(int need) async {
    while (true) {
      final avail = _availableMemory();
      final headroom = (avail - _safetyMarginBytes).clamp(0, 1 << 62);
      if (need <= headroom - _reserved) {
        _reserved += need;
        return;
      }
      if (_reserved == 0) {
        _reserved += need;
        return;
      }
      // Wait for a release. 5-second timeout polls the OS in case
      // memory pressure dropped between waits.
      final completer = Completer<void>();
      _waiters.add(completer);
      try {
        await completer.future.timeout(const Duration(seconds: 5));
      } on TimeoutException {
        // fall through to re-check
      }
      _waiters.remove(completer);
    }
  }

  /// Release [amount] bytes from the reservation. Wakes any waiters.
  static void release(int amount) {
    _reserved = (_reserved - amount).clamp(0, 1 << 62);
    final waiters = List<Completer<void>>.of(_waiters);
    _waiters.clear();
    for (final w in waiters) {
      if (!w.isCompleted) w.complete();
    }
  }

  /// Test-only: drop all reservations and waiters back to zero.
  static void resetForTesting() {
    _reserved = 0;
    for (final w in _waiters) {
      if (!w.isCompleted) w.complete();
    }
    _waiters.clear();
  }
}

/// Run [tasks] through [work] with at most [concurrency] in flight at
/// once. Errors thrown by [work] propagate out of the returned
/// future; tasks beyond the failure are NOT cancelled but the
/// returned future doesn't wait for them. Order is not preserved.
///
/// Public so test/upload_test.dart can verify the concurrency
/// invariant; production callers inside this module use it
/// internally for the upload pool.
Future<void> runBoundedPool<T>(
  Iterable<T> tasks,
  int concurrency,
  Future<void> Function(T) work,
) async {
  if (concurrency < 1) concurrency = 1;
  final iter = tasks.iterator;
  final inFlight = <Future<void>>[];
  void launch() {
    while (inFlight.length < concurrency && iter.moveNext()) {
      final t = iter.current;
      late final Future<void> f;
      f = work(t).whenComplete(() {
        inFlight.remove(f);
      });
      inFlight.add(f);
    }
  }

  launch();
  while (inFlight.isNotEmpty) {
    await Future.any(inFlight);
    launch();
  }
}

// =============================================================================
// SIZE LIMIT + DYNAMIC TIMEOUT (Phase 7.9)
// =============================================================================
//
// Mirrors Python's TWENTY_GIGABYTES + dynamic timeout calculation
// (services/drive.py:52, drive.py:803-806). Files larger than the
// upper bound are rejected up front rather than failing later in
// the pipeline with confusing errors. Per-stream timeouts scale
// with file size assuming a ~100 KB/s minimum throughput, so very
// large uploads don't hit a fixed default mid-stream.

/// Internxt's per-file upload upper bound. Mirrors the Python
/// sibling's `TWENTY_GIGABYTES` constant. Files larger than this
/// are rejected with a clear error before encryption starts.
const int maxFileSizeBytes = 20 * 1024 * 1024 * 1024; // 20 GB

/// Compute a per-file upload timeout based on size. Floor of 5 min
/// (for tiny files where setup latency dominates), then scale up
/// at 100 KB/s + 60s headroom. Mirrors Python's formula
/// `max(300, file_size / (100 KB/s)) + 60`.
Duration uploadTimeoutForSize(int fileSize) {
  final byBandwidth = fileSize ~/ (100 * 1024);
  final seconds = (byBandwidth > 300 ? byBandwidth : 300) + 60;
  return Duration(seconds: seconds);
}

// =============================================================================
// CANCELLATION TOKEN (Phase 7.7)
// =============================================================================
//
// Signal-driven abort for long-running batch operations. cli.dart
// subscribes to SIGINT (Ctrl+C) and calls `cancel()` on the token.
// Workers check `isCancelled` at the top of each per-task callback
// and return early with status 'cancelled' instead of doing work.
//
// In-flight network calls can't be cancelled mid-stream (Dart's
// http.Client doesn't expose abort), so a single Ctrl+C lets
// already-started uploads finish but prevents queued workers from
// starting new ones. A second Ctrl+C does a hard exit.

class CancellationToken {
  bool _cancelled = false;

  /// True once [cancel] has been invoked. Idempotent; once set,
  /// stays set.
  bool get isCancelled => _cancelled;

  /// Mark cancelled. Subsequent calls are no-ops.
  void cancel() {
    _cancelled = true;
  }
}

// =============================================================================
// THROTTLED PROGRESS LINE (Phase 7.6)
// =============================================================================
//
// In-place stdout progress counter throttled to ~5/sec, modeled
// after the Python sibling's _scan_tick / _plan_tick / _upload_tick
// (cli.py). Provides a single line that gets overwritten via \r so
// big batches don't flood the terminal but the user still sees the
// CLI is alive.
//
// Usage:
//   final tick = ProgressLine();
//   tick.update('Scanning: 1234 folders, 5678 files');
//   ...
//   tick.update('Scanning: 1235 folders, ...');  // throttled
//   tick.finish();  // flush + newline so next log line starts clean

class ProgressLine {
  /// Minimum gap between stdout writes. ~5/sec to avoid flicker
  /// without burning the terminal scrollback.
  static const Duration interval = Duration(milliseconds: 200);

  final void Function(String) _writer;
  Stopwatch? _clock;

  ProgressLine({void Function(String)? writer})
      : _writer = writer ?? io.stdout.write;

  /// Maybe write [line] to stdout, prefixed with \r so it overwrites
  /// the previous progress line. The first call always writes; later
  /// calls are throttled — calls within [interval] of the last write
  /// are dropped unless [force] is set.
  void update(String line, {bool force = false}) {
    if (_clock == null) {
      _writer('\r$line');
      _clock = Stopwatch()..start();
      return;
    }
    if (!force && _clock!.elapsed < interval) return;
    _writer('\r$line');
    _clock = Stopwatch()..start();
  }

  /// Force a final write + newline so the next stdout line starts
  /// cleanly. Idempotent.
  void finish([String? finalLine]) {
    if (finalLine != null) _writer('\r$finalLine');
    _writer('\n');
    _clock = null;
  }
}

// =============================================================================
// PRE-SCAN + SIZE-BASED SKIP (Phase 7.4)
// =============================================================================
//
// Walks the remote target subtree once at the start of a batch upload,
// returning a map of `parentRemotePath -> {filename -> size}`. The
// caller uses this to:
//   (a) Short-circuit Pass 1 (mkdir): folders already in the map
//       don't need a `createFolderRecursive` call.
//   (b) Implement size-based skip in task generation: if local file
//       size matches the remote entry, mark the task as
//       'skipped_size_match' before queuing it for Pass 2.
//
// The walk also seeds the listFolderFiles cache so Pass 2 makes
// zero listing calls when target subtree is already populated.
//
// Mirrors Python's _seed_recursive (cli.py:874).

/// Decide whether a local file should be skipped because the remote
/// already has a same-name file with the same size. Pure function;
/// unit-tested.
///
/// `mtimeCompare` is intentionally limited to size-only for now —
/// mtime equality across upload-roundtrip is unreliable on Internxt
/// (the gateway re-stamps modificationTime on store), and the
/// Python sibling's `_should_skip` only enforces mtime equality
/// when `preserve_timestamps` is on AND both sides have a timestamp.
/// We can revisit when the test rig confirms parity.
bool shouldSkipForSizeMatch({
  required Map<String, int>? remoteFilesInParent,
  required String filename,
  required int localSize,
  required String onConflict,
}) {
  if (onConflict != 'skip') return false;
  if (remoteFilesInParent == null) return false;
  final remoteSize = remoteFilesInParent[filename];
  if (remoteSize == null) return false;
  // Size 0 (folder placeholder, missing-data marker, etc.) is never
  // a confident match — fall through to upload.
  if (remoteSize == 0) return false;
  return remoteSize == localSize;
}

/// Recursive remote pre-scan. Returns null if [targetPath] does not
/// exist on the remote (caller falls back to "no pre-scan" mode).
///
/// Otherwise returns `{filesByPath, folderPaths}` where:
/// - `filesByPath[parentRemotePath]` is `{filename -> sizeBytes}` for
///   every file under the target subtree.
/// - `folderPaths` is the set of remote folder paths under target;
///   useful for Pass 1 short-circuit.
///
/// Throws if [targetPath] resolves to a file (not a folder).
///
/// `progress` is invoked at most ~5/sec with `(folderCount,
/// fileCount)` so the caller can render a throttled progress line.
Future<({
  Map<String, Map<String, int>> filesByPath,
  Set<String> folderPaths,
})?> preScanRemote(
  String driveApiUrl,
  String? bearerToken,
  String? rootFolderId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String targetPath, {
  void Function(int folderCount, int fileCount)? progress,
}) async {
  Map<String, dynamic> rootInfo;
  try {
    rootInfo = await inxt_drive.resolvePath(driveApiUrl, bearerToken,
        rootFolderId, folderCache, fileCache, targetPath);
  } on Exception catch (e) {
    if (e.toString().contains('Path not found')) return null;
    rethrow;
  }
  if (rootInfo['type'] != 'folder') {
    throw Exception("Target '$targetPath' is a file, not a folder.");
  }

  final filesByPath = <String, Map<String, int>>{};
  final folderPaths = <String>{};
  var folderCount = 0;
  var fileCount = 0;

  Future<void> walk(String currentPath, String currentUuid) async {
    folderPaths.add(currentPath);
    folderCount++;

    final files = await inxt_drive.listFolderFiles(
        driveApiUrl, bearerToken, fileCache, currentUuid,
        detailed: true);
    final filesMap = <String, int>{};
    for (final f in files) {
      final plain = (f['name'] ?? '') as String;
      final ext = (f['fileType'] ?? '') as String;
      final leaf = ext.isNotEmpty ? '$plain.$ext' : plain;
      final size = f['size'] is int
          ? f['size'] as int
          : int.tryParse((f['size'] ?? 0).toString()) ?? 0;
      filesMap[leaf] = size;
    }
    filesByPath[currentPath] = filesMap;
    fileCount += filesMap.length;
    if (progress != null) progress(folderCount, fileCount);

    final folders = await inxt_drive.listFolders(
        driveApiUrl, bearerToken, folderCache, currentUuid,
        detailed: true);
    for (final d in folders) {
      final name = (d['name'] ?? '') as String;
      final uuid = (d['uuid'] ?? '') as String;
      if (name.isEmpty || uuid.isEmpty) continue;
      final subPath = '$currentPath/$name'.replaceAll('//', '/');
      await walk(subPath, uuid);
    }
  }

  final rootPath = (rootInfo['path'] as String?) ?? targetPath;
  await walk(rootPath, rootInfo['uuid'] as String);
  return (filesByPath: filesByPath, folderPaths: folderPaths);
}

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
///
/// [timeout] caps the entire stream; defaults to no timeout for
/// callers (e.g. uploadChunk used directly in tests). Production
/// callers in this module pass `uploadTimeoutForSize(fileSize)`.
Future<void> uploadChunkWithProgress(
  String uploadUrl,
  Uint8List chunkData,
  String fileName, {
  Duration? timeout,
}) async {
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

  // Apply the dynamic timeout to the response wait. The 5ms-per-
  // chunk loop above is throughput-bounded; the timeout here covers
  // the actual network completion handshake.
  final pendingResponse = http.Response.fromStream(await responseFuture);
  final response = timeout != null
      ? await pendingResponse.timeout(timeout)
      : await pendingResponse;
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

  // Phase 7.9: reject oversized files up front. Internxt rejects
  // these later anyway, but we want a clean error before encrypt.
  if (fileSize > maxFileSizeBytes) {
    throw Exception(
        'File too large: ${inxt_utils.formatSize(fileSize)} '
        '> ${inxt_utils.formatSize(maxFileSizeBytes)} (Internxt limit).');
  }
  final perFileTimeout = uploadTimeoutForSize(fileSize);

  // Memory gate: reserve ~2x file_size for the plaintext+encrypted
  // copies that overlap during encrypt. Released in `finally`. With
  // a single sequential uploader this is a no-op (the gate lets it
  // straight through); under concurrent workers (Phase 7.2) the gate
  // serializes large uploads when RAM is tight.
  final memNeed = fileSize * 2;
  await MemoryGate.acquire(memNeed);
  try {
    print(
        '\n     🔐 [STEP 1/5] Starting Encryption for ${inxt_utils.formatSize(fileSize)}...');
    final fileBytes = await localFile.readAsBytes();
    final encryptClock = Stopwatch()..start();

    final encryptedResult =
        inxt_crypto.encryptStream(fileBytes, mnemonic, bucketId);
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
        startResponse['uploads'][0]['url'], encryptedData, remoteFileName,
        timeout: perFileTimeout);

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
  } finally {
    MemoryGate.release(memNeed);
  }
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
  int workers = 4,
  CancellationToken? cancellationToken,
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

    // Phase 7.4: pre-scan the remote target subtree once (if it
    // exists) so Pass 2 can do size-based skip without re-listing
    // each parent. Pass 1 (mkdir) is also short-circuited because
    // the cache is already warmed by the recursive walk.
    //
    // Phase 7.6: render a throttled in-place counter during the
    // recursive walk so big subtrees don't show a long silence.
    Map<String, Map<String, int>>? remoteFilesByPath;
    try {
      final scanProgress = ProgressLine();
      final scan = await preScanRemote(driveApiUrl, bearerToken,
          rootFolderId, folderCache, fileCache, targetFolderPathStr,
          progress: (folders, files) {
        scanProgress.update('  -> 📋 Scanning remote: $folders folders, '
            '$files files');
      });
      if (scan != null) {
        remoteFilesByPath = scan.filesByPath;
        final totalFiles = remoteFilesByPath.values
            .fold<int>(0, (sum, m) => sum + m.length);
        scanProgress.finish(
            '  -> 📋 Pre-scanned ${remoteFilesByPath.length} folders, '
            '$totalFiles files in target subtree');
      }
    } catch (e) {
      print('⚠️  Pre-scan failed (continuing without size-based skip): $e');
    }

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
              final filename = p.basename(fileEntity.path);

              if (!inxt_utils.shouldIncludeFile(filename, include, exclude)) {
                continue;
              }

              // Phase 7.4: size-based skip via pre-scan map.
              final remoteParent =
                  p.dirname(remoteFilePath).replaceAll('\\', '/');
              final localSize = await fileEntity.length();
              final preSkip = shouldSkipForSizeMatch(
                remoteFilesInParent: remoteFilesByPath?[remoteParent],
                filename: filename,
                localSize: localSize,
                onConflict: onConflict,
              );

              tasks.add({
                'localPath': fileEntity.path,
                'remotePath': remoteFilePath,
                'status': preSkip ? 'skipped_size_match' : 'pending',
              });
            }
          }
        } else if (await io.FileSystemEntity.isFile(entity.path)) {
          final localFile = io.File(entity.path);
          final filename = p.basename(localFile.path);
          final remoteFilePath = p
              .join(targetFolderPathStr, filename)
              .replaceAll('\\', '/');

          if (!inxt_utils.shouldIncludeFile(filename, include, exclude)) {
            continue;
          }

          // Phase 7.4: size-based skip.
          final remoteParent =
              p.dirname(remoteFilePath).replaceAll('\\', '/');
          final localSize = await localFile.length();
          final preSkip = shouldSkipForSizeMatch(
            remoteFilesInParent: remoteFilesByPath?[remoteParent],
            filename: filename,
            localSize: localSize,
            onConflict: onConflict,
          );

          tasks.add({
            'localPath': localFile.path,
            'remotePath': remoteFilePath,
            'status': preSkip ? 'skipped_size_match' : 'pending',
          });
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

  // Pass 2 — parallel uploads.
  //
  // Pre-create each unique parent folder once, sequentially, so N
  // concurrent workers don't all hit the 409-conflict-recovery path
  // on the same path. Then run uploads through a bounded async pool.
  final uniqueParents = <String>{};
  for (final t in tasks.cast<Map<String, dynamic>>()) {
    uniqueParents
        .add(p.dirname(t['remotePath'] as String).replaceAll('\\', '/'));
  }
  final parentInfoCache = <String, Map<String, dynamic>>{};
  for (final parent in uniqueParents) {
    try {
      parentInfoCache[parent] = await inxt_drive.createFolderRecursive(
          driveApiUrl, bearerToken, rootFolderId, folderCache, fileCache, parent);
    } catch (e) {
      print('     ❌ Error ensuring parent folder $parent: $e');
      // Tasks under this parent will fail; we record the failure
      // when they run.
    }
  }

  // Counters mutated from worker callbacks. Safe under Dart's
  // single-threaded async model — all increments happen at await
  // boundaries inside individual workers, never atomically across
  // workers, but always serialized at the event-loop level.
  var successCount = 0;
  var skippedCount = 0;
  var errorCount = 0;
  var completedPreviously = 0;

  // Serialize saveStateCallback so concurrent workers don't race on
  // the on-disk state file. Each call appends to the chain; the
  // returned Future completes when *this* save lands.
  var saveTail = Future<void>.value();
  Future<void> serializedSave() {
    saveTail = saveTail.then((_) => saveStateCallback(batchState));
    return saveTail;
  }

  // Phase 7.6: throttled progress for the upload pass. Updates ~5/sec
  // while workers complete tasks; force-finishes with a final summary.
  final uploadProgress = ProgressLine();
  void renderUploadProgress({bool force = false}) {
    final done = successCount + skippedCount + errorCount + completedPreviously;
    final total = tasks.length;
    final pct = total > 0 ? (done / total * 100).toStringAsFixed(1) : '0.0';
    uploadProgress.update(
      '  -> 📤 Uploaded $done/$total ($pct%) ok=$successCount '
      'err=$errorCount skip=$skippedCount',
      force: force,
    );
  }

  var cancelledCount = 0;

  Future<void> runOne(Map<String, dynamic> task) async {
    // Phase 7.7: queued workers see the cancellation flag at the
    // top and return early. In-flight tasks past this point run to
    // completion (network calls can't be cancelled mid-stream).
    if (cancellationToken?.isCancelled ?? false) {
      cancelledCount++;
      task['status'] = 'cancelled';
      await serializedSave();
      return;
    }
    try {
      final localPath = task['localPath'] as String;
      final remotePath = task['remotePath'] as String;
      final status = task['status'] as String;

      final localFile = io.File(localPath);
      if (!await localFile.exists()) {
        print('⚠️ Source file no longer exists, skipping: $localPath');
        skippedCount++;
        task['status'] = 'skipped_missing_source';
        await serializedSave();
        return;
      }
      if (status == 'completed') {
        completedPreviously++;
        return;
      }
      if (status.startsWith('skipped')) {
        skippedCount++;
        return;
      }

      final remoteParentPath = p.dirname(remotePath).replaceAll('\\', '/');
      final parentFolderInfo = parentInfoCache[remoteParentPath];
      if (parentFolderInfo == null) {
        // Parent pre-create failed earlier; record the per-task failure.
        errorCount++;
        task['status'] = 'error_create_parent';
        await serializedSave();
        return;
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
        parentFolderInfo['uuid'] as String,
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
      await serializedSave();
      renderUploadProgress();
    } catch (e) {
      print('  -> ❌ Worker exception for ${task['localPath']}: $e');
      errorCount++;
      task['status'] = 'error_worker';
      await serializedSave();
      renderUploadProgress();
    }
  }

  final maxWorkers = workers.clamp(1, tasks.isEmpty ? 1 : tasks.length);
  if (maxWorkers > 1 && tasks.isNotEmpty) {
    print('🧵 Uploading ${tasks.length} file(s) with $maxWorkers worker(s)');
  }

  await runBoundedPool<Map<String, dynamic>>(
    tasks.cast<Map<String, dynamic>>(),
    maxWorkers,
    runOne,
  );

  // Final progress flush + newline so the summary lines start clean.
  if (tasks.isNotEmpty) {
    renderUploadProgress(force: true);
    uploadProgress.finish();
  }

  // Wait for any tail saves (the chain may still have queued saves).
  await saveTail;

  print('=' * 40);
  if (cancellationToken?.isCancelled ?? false) {
    print('🛑 ABORTED by user (Ctrl+C)');
  }
  print('📊 Batch Upload Summary:');
  if (completedPreviously > 0) {
    print('  ✅ Completed (previous run): $completedPreviously');
  }
  print('  ✅ Uploaded (this run): $successCount');
  print('  ⏭️  Skipped:  $skippedCount');
  if (cancelledCount > 0) {
    print('  🛑 Cancelled: $cancelledCount');
  }
  print('  ❌ Errors:   $errorCount');
  print('=' * 40);

  if (errorCount > 0) {
    throw Exception(
        'Upload completed with $errorCount errors. State file kept for inspection/retry.');
  }
}

/// In-place file content replacement. The drive entry's UUID is
/// preserved; only its network shard pointer + size change.
///
/// Used by the WebDAV PUT-on-existing path (mirrors the Python
/// sibling's `update_file`). Pipeline:
///   1. Read + encrypt local file.
///   2. start/chunk/finish to push the new shard (gets a new
///      `fileId` network UUID).
///   3. PUT /files/{uuid} with `{fileId, size}` so the drive entry
///      points to the new shard.
///   4. Invalidate the parent listing cache so a subsequent
///      listFolderFiles sees the new size.
///
/// Returns the gateway's PUT response. The drive entry's UUID is
/// unchanged from the input [fileUuid].
Future<Map<String, dynamic>> updateFile(
  String driveApiUrl,
  String networkUrl,
  String? bearerToken,
  String mnemonic,
  String bucketId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String fileUuid,
  io.File localFile, {
  required String bridgeUser,
  required String userIdForAuth,
}) async {
  final fileSize = await localFile.length();
  // Phase 7.9: same upper bound check as uploadFile.
  if (fileSize > maxFileSizeBytes) {
    throw Exception(
        'File too large: ${inxt_utils.formatSize(fileSize)} '
        '> ${inxt_utils.formatSize(maxFileSizeBytes)} (Internxt limit).');
  }
  final perFileTimeout = uploadTimeoutForSize(fileSize);
  // Memory gate: same 2x reservation as uploadFile.
  final memNeed = fileSize * 2;
  await MemoryGate.acquire(memNeed);
  try {
    // 1. Read + encrypt.
    final fileBytes = await localFile.readAsBytes();
    final encryptedResult =
        inxt_crypto.encryptStream(fileBytes, mnemonic, bucketId);
    final encryptedData = encryptedResult['data']!;
    final fileIndexHex = encryptedResult['index']!;

    // 2. Network upload of the new shard.
    final bridgePass = inxt_auth.computeBridgePass(userIdForAuth);
    final startResponse = await startUpload(
        networkUrl, bucketId, encryptedData.length, bridgeUser, bridgePass);
    await uploadChunkWithProgress(
        startResponse['uploads'][0]['url'],
        encryptedData,
        'update-$fileUuid',
        timeout: perFileTimeout);

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

    // 3. Repoint the drive entry.
    final result = await inxt_api.replaceFile(
      driveApiUrl,
      bearerToken,
      fileUuid,
      {'fileId': finishResponse['id'], 'size': fileSize},
    );

    // 4. Invalidate parent listing so the new size shows up.
    try {
      final metadata =
          await inxt_api.getFileMetadata(driveApiUrl, bearerToken, fileUuid);
      final parentUuid = (metadata['folderUuid'] as String?) ??
          metadata['folderId']?.toString();
      if (parentUuid != null) {
        inxt_cache.invalidateCache(folderCache, fileCache, parentUuid);
      }
    } catch (_) {
      // best-effort: cache will expire on its own after `cacheDuration`
    }

    return result;
  } finally {
    MemoryGate.release(memNeed);
  }
}

/// Copy a file to a different folder, preserving timestamps.
///
/// Mirrors the Python sibling's `copy_item` exactly: there's no
/// server-side copy endpoint, so this downloads the source to a
/// temp file, then re-uploads it under its original plainName +
/// type with the original creationTime/modificationTime preserved.
///
/// The result has a *new* file UUID — copy is upload-shaped, not a
/// pointer duplication. The original is left untouched.
///
/// Returns the new file's drive entry record (the `createFileEntry`
/// response).
Future<Map<String, dynamic>> copyItem(
  String driveApiUrl,
  String networkUrl,
  String? bearerToken,
  String mnemonic,
  String bucketId,
  Map<String, inxt_cache.CacheEntry> folderCache,
  Map<String, inxt_cache.CacheEntry> fileCache,
  String itemUuid,
  String destinationFolderUuid, {
  required String bridgeUser,
  required String userIdForAuth,
}) async {
  final metadata =
      await inxt_api.getFileMetadata(driveApiUrl, bearerToken, itemUuid);
  final plainName = (metadata['plainName'] ?? '') as String;
  final fileType = (metadata['type'] ?? '') as String;
  final creationTime = (metadata['creationTime'] ?? metadata['createdAt']) as String?;
  final modificationTime = (metadata['modificationTime'] ?? metadata['updatedAt']) as String?;

  final tempDir = await io.Directory.systemTemp.createTemp('inxt-copy-');
  final tempPath = '${tempDir.path}/${plainName.isEmpty ? 'copy' : plainName}';
  try {
    await inxt_download.downloadFileStreamed(
      driveApiUrl,
      networkUrl,
      bearerToken,
      mnemonic,
      itemUuid,
      tempPath,
      bridgeUser,
      userIdForAuth,
    );

    final remoteFileName = fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
    return await uploadFile(
      networkUrl,
      driveApiUrl,
      bearerToken,
      mnemonic,
      bucketId,
      folderCache,
      fileCache,
      io.File(tempPath),
      destinationFolderUuid,
      remoteFileName,
      bridgeUser: bridgeUser,
      userIdForAuth: userIdForAuth,
      creationTime: creationTime,
      modificationTime: modificationTime,
    );
  } finally {
    try {
      await tempDir.delete(recursive: true);
    } catch (_) {
      // best-effort cleanup; OS will reclaim eventually
    }
  }
}
