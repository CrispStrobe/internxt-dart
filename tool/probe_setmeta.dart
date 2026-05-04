// One-off probe: empirically verify the live gateway's PUT /meta
// behavior for files and folders, with both payload shapes:
//
//   (A) bare {modificationTime: ...} — what Python sends
//   (B) {plainName, type, modificationTime} — what Dart Phase 9.6 sends
//
// Goal: find a payload shape that DOESN'T 409 / doesn't get
// silently overwritten. If (A) works for files, our 409 might
// just be the plainName-echo provoking a buggy uniqueness check;
// drop the echo and the gap closes.
//
// Run: dart run tool/probe_setmeta.dart
// Needs IXT_ACCOUNT / IXT_PWD in env or .env (or sibling
// internxt-cli/.env).

import 'dart:convert';
import 'dart:io';

import 'package:internxt_client/internxt_client.dart';
import 'package:http/http.dart' as http;

Future<String?> _envLookup(String key) async {
  final fromEnv = Platform.environment[key];
  if (fromEnv != null) return fromEnv;
  for (final candidate in [
    File('${Directory.current.path}/.env'),
    File('${Directory.current.path}/../internxt-cli/.env'),
  ]) {
    if (!candidate.existsSync()) continue;
    for (final line in candidate.readAsLinesSync()) {
      final t = line.trim();
      if (t.isEmpty || t.startsWith('#') || !t.contains('=')) continue;
      final eq = t.indexOf('=');
      final k = t.substring(0, eq).trim();
      if (k == key) {
        return t
            .substring(eq + 1)
            .trim()
            .replaceAll('"', '')
            .replaceAll("'", '');
      }
    }
  }
  return null;
}

Future<Map<String, dynamic>> _put(
    String url, String token, Map<String, dynamic> body) async {
  final r = await http.put(
    Uri.parse(url),
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Authorization': 'Bearer $token',
      'internxt-client': 'cli',
    },
    body: jsonEncode(body),
  );
  return {'status': r.statusCode, 'body': r.body};
}

Future<void> main() async {
  final email = await _envLookup('IXT_ACCOUNT');
  final password = await _envLookup('IXT_PWD');
  if (email == null || password == null) {
    stderr.writeln('Need IXT_ACCOUNT + IXT_PWD');
    exit(2);
  }

  final tmpCfg = Directory.systemTemp.createTempSync('inxt-probe-');
  try {
    final config = ConfigService(configPath: tmpCfg.path);
    final client = InternxtClient(config: config);
    print('🔑 Logging in as $email...');
    final creds = await client.login(email, password);
    client.setAuth(creds);
    final token = client.newToken!;

    // Make a sentinel folder + file under a unique name.
    final stamp = DateTime.now().millisecondsSinceEpoch;
    final folderName = 'probe_setmeta_$stamp';
    print('📁 Creating sentinel /$folderName ...');
    final folderInfo = await client.createFolderRecursive('/$folderName');
    final folderUuid = folderInfo['uuid'] as String;

    final probeFile = File('${tmpCfg.path}/probe.txt');
    probeFile.writeAsBytesSync(utf8.encode('probe-content'));
    print('☁️  Uploading probe.txt ...');
    await client.uploadSingleItem(
      probeFile,
      '/$folderName',
      folderUuid,
      'overwrite',
      bridgeUser: client.bridgeUser!,
      userIdForAuth: client.userIdForAuth!,
      preserveTimestamps: false,
      remoteFileName: 'probe.txt',
    );
    // Skip resolvePath (cache from createFolderRecursive can be stale);
    // list the folder we just created to get the file uuid directly.
    final files = await client.listFolderFiles(folderUuid, detailed: true);
    final probe = files.firstWhere(
      (f) => (f['name'] ?? '') == 'probe',
      orElse: () => throw StateError('probe file not found after upload: '
          '${files.map((f) => f['name']).toList()}'),
    );
    final fileUuid = probe['uuid'] as String;

    final targetMtime = DateTime.utc(2021, 6, 1, 8, 15, 30).toIso8601String();
    print('🎯 Target modificationTime: $targetMtime\n');

    // --- FOLDER probes ---
    print('=== PUT /folders/$folderUuid/meta ===');
    print('  (A) bare {modificationTime}:');
    var r = await _put('${client.driveApiUrl}/folders/$folderUuid/meta', token,
        {'modificationTime': targetMtime});
    print(
        '       status=${r['status']}  body=${(r['body'] as String).substring(0, (r['body'] as String).length > 200 ? 200 : (r['body'] as String).length)}');

    print('  (B) {plainName, modificationTime}:');
    final folderMeta = await client.getFolderMetadata(folderUuid);
    r = await _put('${client.driveApiUrl}/folders/$folderUuid/meta', token, {
      'plainName': folderMeta['plainName'] ?? folderMeta['name'],
      'modificationTime': targetMtime,
    });
    print(
        '       status=${r['status']}  body=${(r['body'] as String).substring(0, (r['body'] as String).length > 200 ? 200 : (r['body'] as String).length)}');

    final folderAfter = await client.getFolderMetadata(folderUuid);
    print(
        '  → after both: modificationTime=${folderAfter['modificationTime']}');
    print('');

    // --- FILE probes ---
    print('=== PUT /files/$fileUuid/meta ===');
    print('  (A) bare {modificationTime}:');
    r = await _put('${client.driveApiUrl}/files/$fileUuid/meta', token,
        {'modificationTime': targetMtime});
    print(
        '       status=${r['status']}  body=${(r['body'] as String).substring(0, (r['body'] as String).length > 200 ? 200 : (r['body'] as String).length)}');

    print('  (B) {plainName, type, modificationTime}:');
    final fileMeta = await client.getFileMetadata(fileUuid);
    r = await _put('${client.driveApiUrl}/files/$fileUuid/meta', token, {
      'plainName': fileMeta['plainName'] ?? fileMeta['name'],
      'type': fileMeta['type'] ?? '',
      'modificationTime': targetMtime,
    });
    print(
        '       status=${r['status']}  body=${(r['body'] as String).substring(0, (r['body'] as String).length > 200 ? 200 : (r['body'] as String).length)}');

    print('  (C) bare same-name rename {plainName, type} (no mtime):');
    r = await _put('${client.driveApiUrl}/files/$fileUuid/meta', token, {
      'plainName': fileMeta['plainName'] ?? fileMeta['name'],
      'type': fileMeta['type'] ?? '',
    });
    print(
        '       status=${r['status']}  body=${(r['body'] as String).substring(0, (r['body'] as String).length > 200 ? 200 : (r['body'] as String).length)}');

    print('  (D) rename to NEW name + mtime (then rename back):');
    final tempName =
        '${(fileMeta['plainName'] ?? fileMeta['name'])}_tmp_$stamp';
    r = await _put('${client.driveApiUrl}/files/$fileUuid/meta', token, {
      'plainName': tempName,
      'type': fileMeta['type'] ?? '',
      'modificationTime': targetMtime,
    });
    print(
        '       status=${r['status']}  body=${(r['body'] as String).substring(0, (r['body'] as String).length > 200 ? 200 : (r['body'] as String).length)}');

    // Rename back to avoid leaking state.
    if (r['status'] == 200) {
      await _put('${client.driveApiUrl}/files/$fileUuid/meta', token, {
        'plainName': fileMeta['plainName'] ?? fileMeta['name'],
        'type': fileMeta['type'] ?? '',
      });
    }

    final fileAfter = await client.getFileMetadata(fileUuid);
    print(
        '  → after all: modificationTime=${fileAfter['modificationTime']}  plainName=${fileAfter['plainName']}');

    // Cleanup
    print('\n🧹 Cleaning up sentinel folder ...');
    await client.trashItems(folderUuid, 'folder');
  } finally {
    if (tmpCfg.existsSync()) tmpCfg.deleteSync(recursive: true);
  }
}
