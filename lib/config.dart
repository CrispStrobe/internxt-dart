// ConfigService — credential / batch-state / WebDAV PID persistence.
//
// Extracted from cli.dart in Phase 4 (see PLAN.md). All file I/O lives
// here; nothing in this file talks to the network or holds auth state.
//
// Tests import it via `import '../cli.dart';` — cli.dart re-exports
// this module for backwards compatibility.

import 'dart:convert';
import 'dart:io' as io;

import 'package:crypto/crypto.dart' as crypto;
import 'package:path/path.dart' as p;

class ConfigService {
  late final String internxtCliDataDir;
  late final String internxtCliLogsDir;
  late final String credentialsFile;
  late final String batchStateDir;
  late final String webdavPidFile;

  /// [configPath] override is for tests and Flutter consumers that
  /// supply their own data directory (e.g., `path_provider`'s app
  /// support dir on mobile). Production CLI use defaults to
  /// `~/.internxt-cli`.
  ConfigService({String? configPath}) {
    final home = configPath ??
        io.Platform.environment['HOME'] ??
        io.Platform.environment['USERPROFILE'] ??
        '.';
    internxtCliDataDir = configPath ?? p.join(home, '.internxt-cli');
    internxtCliLogsDir = p.join(internxtCliDataDir, 'logs');
    batchStateDir = p.join(internxtCliDataDir, 'batch_states');
    credentialsFile = p.join(internxtCliDataDir, '.inxtcli-dart-creds.json');
    webdavPidFile = p.join(internxtCliDataDir, 'webdav.pid');

    io.Directory(internxtCliDataDir).createSync(recursive: true);
    io.Directory(internxtCliLogsDir).createSync(recursive: true);
    io.Directory(batchStateDir).createSync(recursive: true);
  }

  String get configDir => internxtCliDataDir;

  // --- WebDAV PID Management ---
  Future<void> saveWebdavPid(int pid) async {
    try {
      await io.File(webdavPidFile).writeAsString(pid.toString());
    } catch (e) {
      print('⚠️  Warning: Could not save WebDAV PID file: $e');
    }
  }

  Future<int?> readWebdavPid() async {
    try {
      if (await io.File(webdavPidFile).exists()) {
        final content = await io.File(webdavPidFile).readAsString();
        return int.tryParse(content.trim());
      }
    } catch (e) {
      print('⚠️  Warning: Could not read WebDAV PID file: $e');
    }
    return null;
  }

  Future<void> clearWebdavPid() async {
    try {
      if (await io.File(webdavPidFile).exists()) {
        await io.File(webdavPidFile).delete();
      }
    } catch (e) {
      print('⚠️  Warning: Could not clear WebDAV PID file: $e');
    }
  }

  // --- Batch State Management ---
  String generateBatchId(
      String operationType, List<String> sources, String target) {
    final input = '$operationType-${sources.join('|')}-$target';
    final bytes = utf8.encode(input);
    final digest = crypto.sha1.convert(bytes);
    return digest.toString().substring(0, 16);
  }

  String getBatchStateFilePath(String batchId) {
    return p.join(batchStateDir, 'batch_state_$batchId.json');
  }

  Future<Map<String, dynamic>?> loadBatchState(String batchId) async {
    final filePath = getBatchStateFilePath(batchId);
    final file = io.File(filePath);
    if (await file.exists()) {
      try {
        final content = await file.readAsString();
        return json.decode(content) as Map<String, dynamic>;
      } catch (e) {
        print("⚠️ Warning: Could not read batch state file '$filePath': $e");
        await deleteBatchState(batchId);
        return null;
      }
    }
    return null;
  }

  Future<void> saveBatchState(
      String batchId, Map<String, dynamic> state) async {
    final filePath = getBatchStateFilePath(batchId);
    final file = io.File(filePath);
    try {
      await file.writeAsString(json.encode(state));
    } catch (e) {
      print("⚠️ Warning: Could not save batch state file '$filePath': $e");
    }
  }

  Future<void> deleteBatchState(String batchId) async {
    final filePath = getBatchStateFilePath(batchId);
    final file = io.File(filePath);
    if (await file.exists()) {
      try {
        await file.delete();
      } catch (e) {
        print("⚠️ Warning: Could not delete batch state file '$filePath': $e");
      }
    }
  }

  // --- Hydrated Credentials Management ---
  // SECURITY NOTE: stored as PLAIN JSON. The Python sibling encrypts
  // this file with AES-256-CBC + a fixed APP_CRYPTO_SECRET. Pinned by
  // a regression test in test/config_test.dart so a future encryption
  // upgrade is intentional, not accidental.
  Future<void> saveCredentials(Map<String, dynamic> credentials) async {
    final file = io.File(credentialsFile);
    await file.writeAsString(json.encode(credentials), flush: true);
  }

  Future<Map<String, dynamic>?> readCredentials() async {
    final file = io.File(credentialsFile);
    if (!await file.exists()) return null;
    try {
      final contents = await file.readAsString();
      return json.decode(contents) as Map<String, dynamic>;
    } catch (e) {
      return null;
    }
  }

  Future<void> clearCredentials() async {
    final file = io.File(credentialsFile);
    if (await file.exists()) {
      await file.delete();
    }
  }
}
