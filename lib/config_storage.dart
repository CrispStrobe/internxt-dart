// ConfigStorage — pluggable backend for ConfigService persistence.
//
// Phase 6.a B5. Splits the file-IO portion of ConfigService into a
// small interface so non-CLI consumers (cloud-dart's Flutter Web
// build) can swap in a SharedPreferences-backed impl without
// forking the whole config layer.
//
// The default impl, FileConfigStorage, mirrors the original
// behavior bit-for-bit — production CLI use is unchanged.
//
// Keys: a single string per stored value. For FileConfigStorage,
// the key IS the absolute file path (which is what ConfigService's
// `credentialsFile` / `webdavPidFile` / batch-state path getters
// already return). For SharedPreferences-backed impls, the key
// is just a logical name.

import 'dart:io' as io;

/// Abstract persistence layer for ConfigService.
///
/// All values are strings. Callers (ConfigService) handle JSON
/// encode/decode at their layer — keeping this interface minimal
/// avoids leaking serialization concerns into Web-only impls.
abstract class ConfigStorage {
  /// Called once from `ConfigService`'s constructor with the
  /// `dataDir` it computed plus any subdirectories it needs.
  ///
  /// File-backed impls create the directories. Storage backends
  /// without a filesystem (SharedPreferences, in-memory) can no-op.
  void init(String dataDir, List<String> subDirs);

  Future<bool> exists(String key);

  /// Returns null if the key doesn't exist OR if reading it fails
  /// (parse-friendly callers should treat both cases the same).
  Future<String?> read(String key);

  Future<void> write(String key, String value);

  Future<void> delete(String key);
}

/// Default file-system-backed storage. Behavior matches what
/// `ConfigService` did directly before B5.
class FileConfigStorage implements ConfigStorage {
  @override
  void init(String dataDir, List<String> subDirs) {
    io.Directory(dataDir).createSync(recursive: true);
    for (final s in subDirs) {
      io.Directory(s).createSync(recursive: true);
    }
  }

  @override
  Future<bool> exists(String key) => io.File(key).exists();

  @override
  Future<String?> read(String key) async {
    final file = io.File(key);
    if (!await file.exists()) return null;
    try {
      return await file.readAsString();
    } catch (_) {
      return null;
    }
  }

  @override
  Future<void> write(String key, String value) async {
    await io.File(key).writeAsString(value, flush: true);
  }

  @override
  Future<void> delete(String key) async {
    final file = io.File(key);
    if (await file.exists()) await file.delete();
  }
}

/// In-memory storage for tests. Useful for asserting
/// ConfigService's behavior without touching the real filesystem.
class InMemoryConfigStorage implements ConfigStorage {
  final Map<String, String> _store = {};

  @override
  void init(String dataDir, List<String> subDirs) {
    // No filesystem to set up.
  }

  @override
  Future<bool> exists(String key) async => _store.containsKey(key);

  @override
  Future<String?> read(String key) async => _store[key];

  @override
  Future<void> write(String key, String value) async {
    _store[key] = value;
  }

  @override
  Future<void> delete(String key) async {
    _store.remove(key);
  }
}
