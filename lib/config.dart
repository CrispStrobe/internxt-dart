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
import 'crypto.dart' as inxt_crypto;

// Credential-at-rest format (CLI, file-backed storage only). The file holds a
// small JSON envelope {"fmt","src","ct"} where ct is the credentials JSON
// encrypted with a wrapping key whose source is "src":
//   - env    : INTERNXT_CREDENTIALS_KEY (a key you supply; good for CI)
//   - static : the legacy public app constant (obfuscation; the file is 0600)
// Legacy plaintext-JSON credential files are read and migrated on first read.
// NOTE: when a custom ConfigStorage is injected (e.g. CrispCloud's secure
// storage), this encryption is SKIPPED — that consumer encrypts at its own
// layer (flutter_secure_storage / WebEncryptedStorage), so double-encrypting
// would be wrong.
const String credentialsFmt = 'inxt-cred-v1';
const String credentialsKeyEnv = 'INTERNXT_CREDENTIALS_KEY';
const String _staticCredentialsKey = '6KYQBP847D4ATSFA';

class ConfigService {
  late final String internxtCliDataDir;
  late final String internxtCliLogsDir;
  late final String credentialsFile;
  late final String batchStateDir;
  late final String webdavPidFile;

  final ConfigStorage storage;

  /// Whether ConfigService encrypts credentials itself before persisting. True
  /// only when using the default file-backed storage (the standalone CLI);
  /// false when a consumer injects its own (already-secure) storage.
  final bool _encryptCredentials;

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
      : storage = storage ?? FileConfigStorage(),
        _encryptCredentials = storage == null {
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
    if (_encryptCredentials) _restrictPerms(internxtCliDataDir, '700');
  }

  /// Best-effort POSIX chmod (dart:io has no native chmod). No-op on Windows
  /// (relies on user-profile ACLs) and if `chmod` isn't available. The path is
  /// the only argv — no secret is exposed.
  void _restrictPerms(String path, String mode) {
    if (io.Platform.isWindows) return;
    try {
      io.Process.runSync('chmod', [mode, path]);
    } catch (_) {/* best effort */}
  }

  (String, String) _wrappingSecretForSave() {
    final envKey = io.Platform.environment[credentialsKeyEnv];
    if (envKey != null && envKey.isNotEmpty) return ('env', envKey);
    return ('static', _staticCredentialsKey);
  }

  String? _resolveWrappingSecret(String? src) {
    if (src == 'env') {
      final k = io.Platform.environment[credentialsKeyEnv];
      return (k != null && k.isNotEmpty) ? k : null;
    }
    if (src == 'static') return _staticCredentialsKey;
    return null;
  }

  String get configDir => internxtCliDataDir;

  /// Symmetric with the constructor's `configPath:` named param —
  /// returns the path the data dir was rooted at (or the resolved
  /// default if no override was passed). Cloud-dart's adapter
  /// compares this against other providers' equivalent fields.
  String get configPath => internxtCliDataDir;

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
  // Encrypted at rest for the file-backed CLI (envelope + chmod 600); a custom
  // injected ConfigStorage (e.g. CrispCloud) is left to encrypt at its own
  // layer. See the credential-format note at the top of this file.
  Future<void> saveCredentials(Map<String, dynamic> credentials) async {
    final plain = json.encode(credentials);
    if (!_encryptCredentials) {
      // Custom storage (e.g. CrispCloud) encrypts at its own layer.
      await storage.write(credentialsFile, plain);
      return;
    }
    final (src, secret) = _wrappingSecretForSave();
    final ct = inxt_crypto.encryptTextWithKey(plain, secret);
    await storage.write(credentialsFile,
        json.encode({'fmt': credentialsFmt, 'src': src, 'ct': ct}));
    _restrictPerms(credentialsFile, '600');
  }

  Future<Map<String, dynamic>?> readCredentials() async {
    final contents = await storage.read(credentialsFile);
    if (contents == null) return null;
    try {
      if (!_encryptCredentials) {
        return json.decode(contents) as Map<String, dynamic>;
      }
      if (contents.trimLeft().startsWith('{')) {
        final obj = json.decode(contents);
        if (obj is Map && obj['fmt'] == credentialsFmt) {
          final secret = _resolveWrappingSecret(obj['src'] as String?);
          if (secret == null) return null; // wrapping key unavailable
          final plain =
              inxt_crypto.decryptTextWithKey(obj['ct'] as String, secret);
          return json.decode(plain) as Map<String, dynamic>;
        }
        // Legacy plaintext-JSON credentials → migrate to the encrypted envelope.
        final creds = obj as Map<String, dynamic>;
        try {
          await saveCredentials(creds);
        } catch (_) {/* keep legacy on failure */}
        return creds;
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  Future<void> clearCredentials() async {
    await storage.delete(credentialsFile);
  }
}
