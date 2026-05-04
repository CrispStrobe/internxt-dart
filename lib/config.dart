// ConfigService — credential / batch-state / WebDAV PID persistence.
//
// Extracted from cli.dart in Phase 4 (see PLAN.md). All persistence
// goes through the [ConfigStorage] interface (Phase 6.a B5), which
// defaults to file-system I/O — production CLI behavior unchanged.
// Cloud-dart's Web build can pass a SharedPreferences-backed
// [ConfigStorage] without touching this class.

import 'dart:convert';
import 'dart:io' as io;

import 'package:crypto/crypto.dart' as crypto;
import 'package:path/path.dart' as p;

import 'config_storage.dart';

class ConfigService {
  late final String internxtCliDataDir;
  late final String internxtCliLogsDir;
  late final String credentialsFile;
  late final String batchStateDir;
  late final String webdavPidFile;

  final ConfigStorage storage;

  /// [configPath] override is for tests and Flutter consumers that
  /// supply their own data directory (e.g., `path_provider`'s app
  /// support dir on mobile). Production CLI use defaults to
  /// `~/.internxt-cli`.
  ///
  /// [storage] override (Phase 6.a B5) lets non-CLI consumers
  /// (e.g. cloud-dart's Flutter Web build) plug in a
  /// SharedPreferences-backed impl. Defaults to file-system I/O
  /// via [FileConfigStorage].
  ConfigService({String? configPath, ConfigStorage? storage})
      : storage = storage ?? FileConfigStorage() {
    final home = configPath ??
        io.Platform.environment['HOME'] ??
        io.Platform.environment['USERPROFILE'] ??
        '.';
    internxtCliDataDir = configPath ?? p.join(home, '.internxt-cli');
    internxtCliLogsDir = p.join(internxtCliDataDir, 'logs');
    batchStateDir = p.join(internxtCliDataDir, 'batch_states');
    credentialsFile = p.join(internxtCliDataDir, '.inxtcli-dart-creds.json');
    webdavPidFile = p.join(internxtCliDataDir, 'webdav.pid');

    this.storage.init(internxtCliDataDir, [internxtCliLogsDir, batchStateDir]);
  }

  String get configDir => internxtCliDataDir;

  // --- WebDAV PID Management ---
  Future<void> saveWebdavPid(int pid) async {
    try {
      await storage.write(webdavPidFile, pid.toString());
    } catch (e) {
      print('⚠️  Warning: Could not save WebDAV PID file: $e');
    }
  }

  Future<int?> readWebdavPid() async {
    try {
      final content = await storage.read(webdavPidFile);
      if (content == null) return null;
      return int.tryParse(content.trim());
    } catch (e) {
      print('⚠️  Warning: Could not read WebDAV PID file: $e');
      return null;
    }
  }

  Future<void> clearWebdavPid() async {
    try {
      await storage.delete(webdavPidFile);
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
    final content = await storage.read(filePath);
    if (content == null) return null;
    try {
      return json.decode(content) as Map<String, dynamic>;
    } catch (e) {
      print("⚠️ Warning: Could not parse batch state '$filePath': $e");
      await deleteBatchState(batchId);
      return null;
    }
  }

  Future<void> saveBatchState(
      String batchId, Map<String, dynamic> state) async {
    final filePath = getBatchStateFilePath(batchId);
    try {
      await storage.write(filePath, json.encode(state));
    } catch (e) {
      print("⚠️ Warning: Could not save batch state file '$filePath': $e");
    }
  }

  Future<void> deleteBatchState(String batchId) async {
    final filePath = getBatchStateFilePath(batchId);
    try {
      await storage.delete(filePath);
    } catch (e) {
      print("⚠️ Warning: Could not delete batch state file '$filePath': $e");
    }
  }

  // --- Hydrated Credentials Management ---
  // SECURITY NOTE: stored as PLAIN JSON. The Python sibling encrypts
  // this file with AES-256-CBC + a fixed APP_CRYPTO_SECRET. Pinned by
  // a regression test in test/config_test.dart so a future encryption
  // upgrade is intentional, not accidental.
  Future<void> saveCredentials(Map<String, dynamic> credentials) async {
    await storage.write(credentialsFile, json.encode(credentials));
  }

  Future<Map<String, dynamic>?> readCredentials() async {
    final contents = await storage.read(credentialsFile);
    if (contents == null) return null;
    try {
      return json.decode(contents) as Map<String, dynamic>;
    } catch (_) {
      return null;
    }
  }

  Future<void> clearCredentials() async {
    await storage.delete(credentialsFile);
  }
}
