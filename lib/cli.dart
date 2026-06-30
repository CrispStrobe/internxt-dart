#!/usr/bin/env dart

import 'dart:convert'; // Required for latin1, json, utf8, base64
import 'dart:async'; // For TimeoutException
import 'dart:io' as io; // Use a prefix for dart:io
import 'dart:math';
import 'dart:typed_data';
import 'package:args/args.dart';
import 'package:http/http.dart' as http;
import 'package:bip39/bip39.dart' as bip39;
import 'package:hex/hex.dart';
import 'package:path/path.dart' as p;
import 'package:glob/glob.dart';

// WebDAV Imports
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_dav/shelf_dav.dart';
import 'webdav_filesystem.dart'; // Our custom implementation

// Phase 4 module split — re-exported so existing tests that do
// `import '../cli.dart';` keep finding ConfigService etc.
import 'config.dart';
import 'crypto.dart' as inxt_crypto;
import 'utils.dart' as inxt_utils;
import 'utils.dart' show formatSize; // unprefixed for in-file callers
import 'cache.dart' show CacheEntry; // for field types on InternxtClient
import 'api.dart' as inxt_api;
import 'auth.dart' as inxt_auth;
import 'drive.dart' as inxt_drive;
import 'upload.dart' as inxt_upload;
import 'download.dart' as inxt_download;
export 'config.dart' show ConfigService;
export 'config_storage.dart';
export 'paths.dart';
export 'crypto.dart';
export 'utils.dart';
export 'cache.dart';
export 'api.dart';
export 'auth.dart';
export 'drive.dart';
export 'upload.dart';
export 'download.dart';

/// Internxt CLI in Dart
void main(List<String> arguments) async {
  final cli = InternxtCLI();
  await cli.run(arguments);
}

class InternxtCLI {
  // Use a final config and pass it to the client
  final ConfigService config = ConfigService();
  late final InternxtClient client;
  bool debugMode = false;

  // Constructor to initialize the client with the config
  InternxtCLI() {
    client = InternxtClient(config: config);
  }

  Future<void> run(List<String> arguments) async {
    final parser = ArgParser()
      ..addFlag('debug', abbr: 'd', help: 'Enable debug output')
      ..addFlag('uuids', help: 'Show full UUIDs in list command')
      ..addFlag('recursive', abbr: 'r', help: 'Recursive operation')
      ..addFlag('preserve-timestamps',
          abbr: 'p', help: 'Preserve file modification times')
      ..addOption('target',
          abbr: 't', help: 'Destination path on Internxt Drive')
      ..addOption('on-conflict',
          help: 'Action if target exists '
              '(skip = leave; overwrite = trash old + upload new; '
              'safety_pattern = rename old to .bak then upload)',
          allowed: ['overwrite', 'skip', 'safety_pattern'],
          defaultsTo: 'skip')
      ..addMultiOption('include', help: 'Include only files matching pattern')
      ..addMultiOption('exclude', help: 'Exclude files matching pattern')
      ..addOption('workers',
          abbr: 'w',
          help: 'Number of parallel upload/move workers (default: 4)',
          defaultsTo: '4')
      ..addOption('chunk-workers',
          help: 'Parallel multipart part PUTs / ranged-download GETs within a '
              'single large file (default: 4)',
          defaultsTo: '4')
      ..addFlag('ranged',
          help: 'Download large files (>=100 MiB) as parallel byte ranges '
              '(falls back to a single GET if the server ignores Range)',
          defaultsTo: false)
      ..addFlag('dry-run',
          abbr: 'n', help: 'Show what would be done without making changes')
      ..addFlag('force',
          abbr: 'f', help: 'Skip confirmation for destructive actions')
      ..addOption('depth',
          abbr: 'l', help: 'Maximum depth to show for tree', defaultsTo: '3')
      ..addOption('maxdepth',
          help: 'Limit find to N levels deep (-1 for infinite)',
          defaultsTo: '-1')
      ..addFlag('background',
          abbr: 'b', help: 'Run WebDAV server in background')
      ..addOption('port',
          help: 'Port for WebDAV server (default: 8080)', defaultsTo: '8080')
      ..addOption('temp-dir',
          help:
              'Directory for the rcat stdin spool file (default: system temp)');

    final argResults = parser.parse(arguments);
    debugMode = argResults['debug'] as bool;
    client.debugMode = debugMode;

    final commandArgs = argResults.rest;

    if (commandArgs.isEmpty) {
      printWelcome();
      return;
    }

    final command = commandArgs[0];

    try {
      switch (command) {
        case 'login':
          await handleLogin(commandArgs.sublist(1));
          break;
        case 'whoami':
          await handleWhoami();
          break;
        case 'logout':
          await handleLogout();
          break;
        case 'list':
          await handleList(argResults);
          break;
        case 'download':
          inxt_download.rangedDownload = argResults['ranged'] as bool;
          inxt_download.downloadChunkWorkers =
              (int.tryParse(argResults['chunk-workers'] as String? ?? '4') ?? 4)
                  .clamp(1, 1 << 30);
          await handleDownload(argResults.rest.sublist(1));
          break;
        case 'download-path':
          await handleDownloadPath(argResults);
          break;
        case 'upload':
          await handleUpload(argResults);
          break;
        case 'rcat':
          inxt_upload.uploadChunkWorkers =
              (int.tryParse(argResults['chunk-workers'] as String? ?? '4') ?? 4)
                  .clamp(1, 1 << 30);
          await handleRcat(argResults);
          break;
        case 'config':
          await handleConfig();
          break;
        case 'quota':
          await handleQuota();
          break;
        case 'test':
          await handleTest();
          break;
        case 'mkdir-path':
          await handleMkdirPath(argResults);
          break;
        case 'resolve':
          await handleResolve(argResults);
          break;
        case 'trash-path':
          await handleTrashPath(argResults);
          break;
        case 'delete-path':
          await handleDeletePath(argResults);
          break;
        case 'list-trash':
          await handleListTrash(argResults);
          break;
        case 'restore-uuid':
          await handleRestoreUuid(argResults);
          break;
        case 'restore-path':
          await handleRestorePath(argResults);
          break;
        case 'trash-clear':
          await handleTrashClear(argResults);
          break;
        case 'move-path':
          await handleMovePath(argResults);
          break;
        case 'rename-path':
          await handleRenamePath(argResults);
          break;
        case 'search':
          await handleSearch(argResults);
          break;
        case 'find':
          await handleFind(argResults);
          break;
        case 'tree':
          await handleTree(argResults);
          break;
        case 'webdav-start':
          await handleWebdavStart(argResults);
          break;
        case 'webdav-stop':
          await handleWebdavStop(argResults);
          break;
        case 'webdav-status':
          await handleWebdavStatus(argResults);
          break;
        case 'webdav-mount':
          await handleWebdavMount(argResults);
          break;
        case 'webdav-test':
          await handleWebdavTest(argResults);
          break;
        case 'webdav-config':
          await handleWebdavConfig(argResults);
          break;
        case 'help':
        case '--help':
        case '-h':
          printHelp();
          break;
        default:
          io.stderr.writeln('❌ Unknown command: $command');
          io.stderr
              .writeln('💡 Use "dart cli.dart help" for available commands');
          io.exit(1);
      }
    } catch (e, stackTrace) {
      io.stderr.writeln('❌ Error: $e');
      if (debugMode) {
        io.stderr.writeln('\nStack trace:');
        io.stderr.writeln(stackTrace);
      }
      io.exit(1);
    }
  }

  void printWelcome() {
    print('╔════════════════════════════════════════╗');
    print('║     Internxt CLI - Dart Edition        ║');
    print('║  Python Blueprint Compatible v1.0      ║');
    print('╚════════════════════════════════════════╝');
    print('');
    print('Available commands:');
    print('  login              Login to your account');
    print('  logout             Logout and clear credentials');
    print('  whoami             Show current user info');
    print('  list [path]        List files and folders (default: root)');
    print('  download <file-uuid> Download a file by its UUID');
    print('  download-path <path> Download a file/folder by its path');
    print('  upload <sources...>  Upload files/folders to Internxt');
    print('  rcat <remote_path>   Stream stdin to a Drive file '
        '(e.g. dump | xz | inxt rcat /backups/db.xz)');

    print('  mkdir-path <path>  Create a new folder (and subfolders) by path');
    print('  resolve <path>     Show what a path points to (debugging)');
    print('  trash-path <path>  Move a file or folder to trash by path');
    print('  delete-path <path> Permanently delete a file or folder by path');
    print('  list-trash         List items currently in the trash');
    print('  restore-uuid <uuid> [-t <dest_path>] Restore item by UUID');
    print(
        '  restore-path <name> [-t <dest_path>] Restore item by Name (from trash list)');
    print('  move-path <src_path> <dest_path> Move a file or folder');
    print('  rename-path <path> <new_name> Rename a file or folder');

    print('  search <query>     Server-side search for files/folders');
    print('  find <path> <pattern> Recursively find files (e.g., "*.pdf")');
    print('  tree [path]        Show folder structure as a tree');

    print('\n  WebDAV Server:');
    print('  webdav-start       Start WebDAV server (mount as local drive)');
    print('  webdav-stop        Stop background WebDAV server');
    print('  webdav-status      Check WebDAV server status');
    print('  webdav-mount       Show mount instructions for your OS');
    print('  webdav-test        Test connection to running WebDAV server');
    print('  webdav-config      Show WebDAV configuration');

    print('\n  config             Show configuration');
    print('  test               Run crypto tests');
    print('  help               Show this help message');
    print('');
    print('Options:');
    print('  --debug            Enable debug output');
    print('  --uuids            Show full UUIDs in "list" and "search"');
    print(
        '  -f, --force        Skip confirmation for "trash-path" and "delete-path"');
    print('  -l, --depth <l>    Maximum depth for "tree" command (default: 3)');
    print('  --maxdepth <l>   Limit "find" to N levels deep (-1 for infinite)');

    print('  --port <port>      WebDAV server port (default: 8080)');
    print('  -b, --background   Run WebDAV server in background');

    print('');
    print('Upload/Download Options:');
    print('  -t, --target <path>  Remote destination path (default: /)');
    print('  -r, --recursive    Recursive operation for directories');
    print('  -p, --preserve-timestamps');
    print('                     Preserve file modification times');
    print(
        '  --on-conflict <mode> Action on conflict (overwrite/skip) (default: skip)');
    print('  --include <pattern>  Include files matching pattern');
    print('  --exclude <pattern>  Exclude files matching pattern');
    print('');
    print('Examples:');
    print('  dart cli.dart login --debug');
    print('  dart cli.dart list /Documents');
    print('  dart cli.dart tree /Documents -l 2');
    print('  dart cli.dart find / --maxdepth 3 "*.jpg"');
    print('  dart cli.dart upload file.txt -t /Documents -p');
    print('  dart cli.dart download-path /Documents/file.txt -p');
    print('  dart cli.dart mkdir-path /New/SubFolder');
    print('  dart cli.dart trash-path /OldFile.txt');
  }

  void printHelp() {
    printWelcome();
  }

  Future<void> handleWebdavStart(ArgResults argResults) async {
    final bool background = argResults['background'] as bool;
    final int port =
        int.tryParse(argResults['port'] as String? ?? '8080') ?? 8080;

    final existingPid = await config.readWebdavPid();
    if (existingPid != null) {
      io.stderr.writeln(
          '❌ WebDAV server may already be running (PID: $existingPid).');
      io.stderr.writeln('💡 Run "dart cli.dart webdav-stop" to clear it.');
      io.exit(1);
    }

    if (background) {
      print('🚀 Starting WebDAV server in background...');
      try {
        final process = await io.Process.start(
          io.Platform.executable,
          [
            io.Platform.script.toFilePath(),
            'webdav-start',
            '--port=$port',
          ],
          mode: io.ProcessStartMode.detached,
          runInShell: true,
        );

        await config.saveWebdavPid(process.pid);

        print('✅ WebDAV server started in background (PID: ${process.pid})');
        print('   URL: http://localhost:$port/');
        print('   User: internxt');
        print('   Pass: internxt-webdav');
        print('\n💡 Use "dart cli.dart webdav-status" to check');
        print('💡 Use "dart cli.dart webdav-stop" to stop');
        io.exit(0);
      } catch (e) {
        io.stderr.writeln('❌ Failed to start background process: $e');
        await config.clearWebdavPid();
        io.exit(1);
      }
    }

    print('🚀 Starting WebDAV server in foreground...');
    print('   (Press Ctrl+C to stop)');

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      // FIX: creds is Map<String, String>? but setAuth expects Map<String, String?>
      // We can safely cast here because creds is non-null
      client.setAuth(
          creds); // InternxtClient.setAuth already accepts Map<String, dynamic>

      final fs = InternxtFileSystem(client: client);

      final davConfig = DAVConfig(
        root: fs.directory('/'),
        prefix: '/',
        authenticationProvider: BasicAuthenticationProvider.plaintext(
          realm: 'Internxt WebDAV',
          users: {'internxt': 'internxt-webdav'},
        ),
        authorizationProvider: RoleBasedAuthorizationProvider(
          readWriteUsers: {'internxt'},
          allowAnonymousRead: false,
        ),
        enableLocking: true,
      );

      final dav = ShelfDAV.withConfig(davConfig);
      final server = await shelf_io.serve(
        dav.handler,
        'localhost',
        port,
      );

      print('✅ WebDAV server running!');
      print('   URL: http://${server.address.host}:${server.port}/');
      print('   User: internxt');
      print('   Pass: internxt-webdav');

      io.ProcessSignal.sigint.watch().listen((_) async {
        print('\n🛑 Stopping WebDAV server...');
        await server.close(force: true);
        await config.clearWebdavPid();
        io.exit(0);
      });
    } catch (e) {
      if (e.toString().contains('Address already in use')) {
        io.stderr.writeln('❌ Error: Port $port is already in use.');
      } else {
        io.stderr.writeln('❌ Failed to start WebDAV server: $e');
      }
      await config.clearWebdavPid();
      io.exit(1);
    }
  }

  Future<void> handleWebdavStop(ArgResults argResults) async {
    print('🛑 Stopping WebDAV server...');
    final pid = await config.readWebdavPid();

    if (pid == null) {
      print('❌ Server does not appear to be running (no PID file).');
      await config.clearWebdavPid();
      io.exit(1);
    }

    try {
      // FIX: pid is int?, killPid needs int
      final success = io.Process.killPid(pid);
      if (success) {
        print('✅ Server process (PID: $pid) terminated.');
      } else {
        print(
            '⚠️  Could not terminate process (PID: $pid). It may already be stopped.');
      }
    } catch (e) {
      print('⚠️  Error terminating process: $e. It may already be stopped.');
    }

    await config.clearWebdavPid();
  }

  Future<void> handleWebdavStatus(ArgResults argResults) async {
    final pid = await config.readWebdavPid();
    final port = int.tryParse(argResults['port'] as String? ?? '8080') ?? 8080;

    if (pid == null) {
      print('❌ WebDAV server is not running (no PID file).');
      print('💡 Start with: dart cli.dart webdav-start');
      io.exit(1);
    }

    print('✅ WebDAV server appears to be running in background.');
    print('   PID: $pid');
    print('   URL: http://localhost:$port/');
    print('   User: internxt');
    print('   Pass: internxt-webdav');
    print('\n💡 Use "dart cli.dart webdav-test" to verify connection.');
    print('💡 Use "dart cli.dart webdav-stop" to stop it.');
  }

  Future<void> handleWebdavMount(ArgResults argResults) async {
    final port = int.tryParse(argResults['port'] as String? ?? '8080') ?? 8080;
    final url = 'http://localhost:$port/';

    print('🗂️  Mount Instructions for Internxt Drive');
    print('=' * 50);
    print('Server URL: $url');
    print('Username:   internxt');
    print('Password:   internxt-webdav');

    print('\n--- macOS ---');
    print('1. Open Finder');
    print('2. Press Cmd+K (Go > Connect to Server)');
    print('3. Enter: $url');
    print('4. Connect, then enter username and password.');

    print('\n--- Windows ---');
    print('1. Open File Explorer');
    print('2. Right-click "This PC" > "Map network drive..."');
    print('3. Enter: $url');
    print('4. Check "Connect using different credentials"');
    print('5. Connect, then enter username and password.');

    print('\n--- Linux (davfs2) ---');
    print('sudo apt install davfs2');
    print('sudo mkdir -p /mnt/internxt');
    print('sudo mount -t davfs $url /mnt/internxt');
    print('(You will be prompted for username and password)');
  }

  Future<void> handleWebdavTest(ArgResults argResults) async {
    final port = int.tryParse(argResults['port'] as String? ?? '8080') ?? 8080;
    final url = Uri.parse('http://localhost:$port/');

    print('🧪 Testing WebDAV server connection at $url ...');

    final propfindBody = '''
    <?xml version="1.0" encoding="utf-8"?>
    <D:propfind xmlns:D="DAV:">
        <D:prop>
            <D:resourcetype/>
        </D:prop>
    </D:propfind>
    ''';

    final basicAuth =
        'Basic ${base64Encode(utf8.encode('internxt:internxt-webdav'))}';

    try {
      final request = http.Request('PROPFIND', url)
        ..headers['Authorization'] = basicAuth
        ..headers['Depth'] = '0'
        ..headers['Content-Type'] = 'application/xml'
        ..body = propfindBody;

      final response =
          await http.Client().send(request).timeout(Duration(seconds: 10));

      final responseBody = await response.stream.bytesToString();

      if (response.statusCode == 207 && responseBody.contains('<?xml')) {
        print('✅ Connection successful! (Received 207 Multi-Status)');
        print('   Server is running and authentication is working.');
      } else {
        print('❌ Connection failed.');
        print('   Server returned status: ${response.statusCode}');
        print(
            '   Response: ${responseBody.substring(0, min(100, responseBody.length))}...');
      }
    } catch (e) {
      if (e is io.SocketException) {
        // <-- FIX: Use io.SocketException
        print(
            '❌ Connection failed: Server is not running or unreachable at $url');
      } else if (e is TimeoutException) {
        // <-- FIX: Use imported TimeoutException
        print('❌ Connection timed out. Is the server running?');
      } else {
        print('❌ Connection test failed: $e');
      }
    }
  }

  Future<void> handleWebdavConfig(ArgResults argResults) async {
    final port = int.tryParse(argResults['port'] as String? ?? '8080') ?? 8080;

    print('⚙️  WebDAV Server Configuration');
    print('=' * 40);
    print('   Host: localhost');
    print('   Port: $port');
    print('   User: internxt');
    print('   Pass: internxt-webdav');
    print('   Protocol: http (SSL not implemented in this version)');
    print('   Background PID File: ${config.webdavPidFile}');
  }

  /// Split an rcat REMOTE_PATH into its parent folder path and filename.
  /// Returns null when the path is a folder (trailing slash) or has no
  /// filename. Pure + testable (the handler proper touches stdin/network).
  static ({String parent, String filename})? parseRcatRemotePath(String raw) {
    final trimmed = raw.trim();
    if (trimmed.isEmpty) return null;
    final normalized = '/${trimmed.replaceAll(RegExp(r'^/+'), '')}';
    if (normalized.endsWith('/')) return null;
    final slash = normalized.lastIndexOf('/');
    final parent = slash <= 0 ? '/' : normalized.substring(0, slash);
    final filename = normalized.substring(slash + 1);
    if (filename.isEmpty) return null;
    return (parent: parent, filename: filename);
  }

  /// `rcat <remote_path>` — read stdin and upload it to a single Drive file
  /// (rclone-rcat style). Internxt needs the exact size up front (the gateway
  /// pre-issues the presigned part URLs at upload start), so the stream is
  /// spooled to a temp file to measure its size, then encrypted+uploaded in one
  /// pass. Empty stdin aborts non-zero; a TTY (no pipe) is rejected.
  Future<void> handleRcat(ArgResults argResults) async {
    final rest = argResults.rest;
    if (rest.length < 2) {
      io.stderr.writeln('❌ Usage: inxt rcat <remote_path>   '
          '(e.g. inxt rcat /backups/db.xz)');
      io.exit(1);
    }
    final parsed = parseRcatRemotePath(rest[1]);
    if (parsed == null) {
      io.stderr.writeln('❌ REMOTE_PATH must include a filename '
          '(e.g. /backups/db.xz), got: "${rest[1]}"');
      io.exit(1);
    }
    final parentPath = parsed.parent;
    final filename = parsed.filename;
    final normalized =
        parentPath == '/' ? '/$filename' : '$parentPath/$filename';

    if (io.stdin.hasTerminal) {
      io.stderr
          .writeln('❌ No data piped to stdin. rcat reads from a pipe, e.g.:');
      io.stderr
          .writeln('   mariadb-dump db | xz -6 | inxt rcat /backups/db.xz');
      io.exit(1);
    }

    final onConflict = argResults['on-conflict'] as String;
    final tempDirOpt = argResults['temp-dir'] as String?;

    io.File? spool;
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "inxt login" first.');
        io.exit(1);
      }
      client.setAuth(creds);
      final bridgeUser = creds['bridgeUser']?.toString();
      final userIdForAuth = creds['userId']?.toString();
      if (bridgeUser == null || userIdForAuth == null) {
        throw Exception(
            'Credentials missing bridgeUser/userId. Please login again.');
      }

      print('🎯 Target: $normalized (parent $parentPath)');
      final parentInfo = await client._resolveOrCreateRemoteFolder(parentPath);
      final parentUuid = parentInfo['uuid'] as String;

      // Spool stdin to a temp file (size must be known before upload start).
      final dir = (tempDirOpt != null && tempDirOpt.isNotEmpty)
          ? io.Directory(tempDirOpt)
          : io.Directory.systemTemp;
      if (!dir.existsSync()) dir.createSync(recursive: true);
      spool = io.File(p.join(
          dir.path, 'inxt-rcat-${DateTime.now().microsecondsSinceEpoch}.tmp'));

      print('📥 Buffering stdin to a temporary file...');
      final sink = spool.openWrite();
      var bytes = 0;
      await for (final chunk in io.stdin) {
        sink.add(chunk);
        bytes += chunk.length;
      }
      await sink.close();
      print('✅ Buffered ${formatSize(bytes)} from stdin');

      if (bytes == 0) {
        io.stderr.writeln('❌ stdin was empty — nothing to upload. (Aborting so '
            'an unattended backup does not silently succeed with no data.)');
        io.exit(1);
      }

      final result = await client.uploadSingleItem(
        spool,
        parentPath,
        parentUuid,
        onConflict,
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
        preserveTimestamps: false,
        remoteFileName: filename,
      );
      if (result == 'uploaded') {
        print('🎉 Streamed ${formatSize(bytes)} to $normalized');
      } else if (result == 'skipped') {
        print('⏭️  Skipped $normalized (already exists; --on-conflict=skip)');
      } else {
        io.stderr.writeln('❌ Failed to upload to $normalized');
        io.exit(1);
      }
    } catch (e) {
      io.stderr.writeln('❌ rcat failed: $e');
      io.exit(1);
    } finally {
      try {
        if (spool != null && spool.existsSync()) spool.deleteSync();
      } catch (_) {/* best effort */}
    }
  }

  Future<void> handleLogin(List<String> args) async {
    if (debugMode) {
      print('🔍 Debug mode enabled\n');
      print('📋 API Configuration:');
      print('   NETWORK_URL (data): ${client.networkUrl}');
      print('   DRIVE_API_URL (auth/meta): ${client.driveApiUrl}');
      print('   APP_CRYPTO_SECRET: ${InternxtClient.appCryptoSecret}');
      print('');
    }

    io.stdout.write('What is your email? ');
    final email = io.stdin.readLineSync()?.trim().toLowerCase() ?? '';
    if (email.isEmpty) {
      io.stderr.writeln('❌ Email is required');
      io.exit(1);
    }

    io.stdout.write('What is your password? ');
    io.stdin.echoMode = false;
    final password = io.stdin.readLineSync()?.trim() ?? '';
    io.stdin.echoMode = true;
    print('');

    if (password.isEmpty) {
      io.stderr.writeln('❌ Password is required');
      io.exit(1);
    }

    try {
      print('🔍 Checking 2FA requirements...');
      final needs2fa = await client.is2faNeeded(email);

      String? tfaCode;
      if (needs2fa) {
        print('🔐 Two-factor authentication is enabled');
        io.stdout.write('Enter your 2FA code (6 digits): ');
        tfaCode = io.stdin.readLineSync()?.trim();
        if (tfaCode == null || tfaCode.isEmpty) {
          io.stderr.writeln('❌ 2FA code is required');
          io.exit(1);
        }
      }

      print('🔐 Logging in...');
      final credentials = await client.login(email, password, tfaCode: tfaCode);

      // CRITICAL: Update the client's internal state with hydrated info (bucketId, etc.)
      client.setAuth(credentials);

      // Save to disk
      await config.saveCredentials(credentials);

      print('✅ Login successful!');
      print('👤 User: ${credentials['email']}');
      print('🆔 User ID: ${credentials['userId']}');
      print('📁 Root Folder ID: ${credentials['rootFolderId']}');
      if (debugMode) {
        print('🪣 Bucket ID: ${credentials['bucketId']}');
      }
    } catch (e) {
      io.stderr.writeln('❌ Login failed: $e');
      io.exit(1);
    }
  }

  Future<void> handleWhoami() async {
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }

      print('╔════════════════════════════════════════╗');
      print('║         Current User Info              ║');
      print('╚════════════════════════════════════════╝');
      print('📧 Email: ${creds['email']}');
      print('🆔 User ID: ${creds['userId']}');
      print('📁 Root Folder: ${creds['rootFolderId']}');
    } catch (e) {
      io.stderr.writeln('❌ Error: $e');
      io.exit(1);
    }
  }

  Future<void> handleLogout() async {
    try {
      await config.clearCredentials();
      print('✅ Logged out successfully');
    } catch (e) {
      io.stderr.writeln('❌ Error: $e');
      io.exit(1);
    }
  }

  Future<void> handleMkdirPath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      io.stderr.writeln('❌ Usage: dart cli.dart mkdir-path <path>');
      io.exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      final path = args[0];
      print("📁 Creating folder(s): $path");

      final createdFolder = await client.createFolderRecursive(path);

      print("✅ Folder created successfully!");
      print("   Name: ${createdFolder['plainName']}");
      print("   UUID: ${createdFolder['uuid']}");
    } catch (e) {
      io.stderr.writeln('❌ Error creating folder: $e');
      io.exit(1);
    }
  }

  Future<void> handleListTrash(ArgResults argResults) async {
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      print('🗑️  Listing trash contents...\n');

      final trashItems = await client.getTrashContent();

      if (trashItems.isEmpty) {
        print('📭 Trash is empty');
        return;
      }

      final bool showFullUUIDs = argResults['uuids'] as bool;
      if (showFullUUIDs) {
        print(
            '╔════════════════════════════════════════════════════════════════════════════════════════════════════╗');
        print(
            '║  Type    Name                                    Size            UUID                                 ║');
        print(
            '╠════════════════════════════════════════════════════════════════════════════════════════════════════╣');
      } else {
        print(
            '╔═══════════════════════════════════════════════════════════════════════════════╗');
        print(
            '║  Type    Name                                    Size            UUID        ║');
        print(
            '╠═══════════════════════════════════════════════════════════════════════════════╣');
      }
      int folderCount = 0;
      int fileCount = 0;
      for (var item in trashItems) {
        final type = item['type'] == 'folder' ? '📁' : '📄';
        if (item['type'] == 'folder') {
          folderCount++;
        } else {
          fileCount++;
        }
        final plainName = (item['name'] ?? 'Unknown') as String;
        final fileType = (item['fileType'] ?? '') as String;
        final displayName = (fileType.isNotEmpty && item['type'] == 'file')
            ? '$plainName.$fileType'
            : plainName;
        final name = displayName.padRight(40);
        final size =
            item['type'] == 'folder' ? '<DIR>' : formatSize(item['size'] ?? 0);
        final uuid = (item['uuid'] ?? 'N/A') as String;
        if (showFullUUIDs) {
          print(
              '║  $type  ${name.substring(0, min(name.length, 40))}  ${size.padLeft(12)}  $uuid ║');
        } else {
          print(
              '║  $type  ${name.substring(0, min(name.length, 40))}  ${size.padLeft(12)}  ${uuid.substring(0, 8)}... ║');
        }
      }
      if (showFullUUIDs) {
        print(
            '╚════════════════════════════════════════════════════════════════════════════════════════════════════╝');
      } else {
        print(
            '╚═══════════════════════════════════════════════════════════════════════════════╝');
      }
      print(
          '\n📊 Total: ${trashItems.length} items ($folderCount folders, $fileCount files)');
      print(
          '\n💡 Use "restore-path <name> -t /dest" or "restore-uuid <uuid> -t /dest" to restore.');
    } catch (e) {
      io.stderr.writeln('❌ Error listing trash: $e');
      io.exit(1);
    }
  }

  Future<void> handleRestoreUuid(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      io.stderr.writeln(
          '❌ Usage: dart cli.dart restore-uuid <item-uuid> [-t /destination/path]');
      io.exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      final itemUuid = args[0];
      final destinationPath = argResults['target'] as String? ?? '/';
      final force = argResults['force'] as bool;

      print("🔍 Resolving destination path: $destinationPath");
      final destFolderInfo = await client.resolvePath(destinationPath);
      if (destFolderInfo['type'] != 'folder') {
        throw Exception("Destination path '$destinationPath' is not a folder.");
      }
      final destinationFolderUuid = destFolderInfo['uuid'] as String;

      final prompt =
          '❓ Restore item "$itemUuid" to "$destinationPath"? (Type unknown, will try file then folder)';
      if (!_confirmAction(prompt, force)) {
        print("❌ Cancelled");
        io.exit(0);
      }

      // Phase 8.1: use the dedicated /trash/restore endpoint
      // instead of moveFile/moveFolder. moveFile on a trashed item
      // is a no-op or error on the gateway side; restore is the
      // correct path. We try both types (file then folder) since
      // the user may not know which.
      print("🚀 Restoring item (trying file first)...");
      try {
        await client.restoreFromTrash(itemUuid, 'file',
            destinationFolderUuid: destinationFolderUuid);
        print("✅ Item restored successfully (as file) to: $destinationPath");
      } catch (fileErr) {
        print("   File restore failed ($fileErr), trying folder...");
        try {
          await client.restoreFromTrash(itemUuid, 'folder',
              destinationFolderUuid: destinationFolderUuid);
          print(
              "✅ Item restored successfully (as folder) to: $destinationPath");
        } catch (folderErr) {
          print("   Folder restore also failed ($folderErr)");
          throw Exception(
              "Failed to restore item $itemUuid as either file or folder.");
        }
      }
    } catch (e) {
      io.stderr.writeln('❌ Error restoring item: $e');
      io.exit(1);
    }
  }

  Future<void> handleRestorePath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      io.stderr.writeln(
          '❌ Usage: dart cli.dart restore-path <item-name-in-trash> [-t /destination/path]');
      io.exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      final itemNameInTrash = args[0];
      final destinationPath = argResults['target'] as String? ?? '/';
      final force = argResults['force'] as bool;

      print("🔍 Resolving destination path: $destinationPath");
      final destFolderInfo = await client.resolvePath(destinationPath);
      if (destFolderInfo['type'] != 'folder') {
        throw Exception("Destination path '$destinationPath' is not a folder.");
      }
      final destinationFolderUuid = destFolderInfo['uuid'] as String;

      print("🔍 Finding item(s) named '$itemNameInTrash' in trash...");
      final trashItems = await client.getTrashContent(limit: 1000);

      final matchingItems = trashItems.where((item) {
        final plainName = (item['name'] ?? 'Unknown') as String;
        final fileType = (item['fileType'] ?? '') as String;
        final displayName = (fileType.isNotEmpty && item['type'] == 'file')
            ? '$plainName.$fileType'
            : plainName;
        return displayName == itemNameInTrash;
      }).toList();

      if (matchingItems.isEmpty) {
        throw Exception("Item named '$itemNameInTrash' not found in trash.");
      }

      if (matchingItems.length > 1) {
        io.stderr.writeln(
            "❌ Error: Multiple items named '$itemNameInTrash' found in trash.");
        io.stderr
            .writeln("   Please use 'restore-uuid' with the specific UUID:");
        for (var item in matchingItems) {
          io.stderr.writeln("   - ${item['type']} ${item['uuid']}");
        }
        io.exit(1);
      }

      final itemToRestore = matchingItems.first;
      final itemUuid = itemToRestore['uuid'] as String;
      final itemType = itemToRestore['type'] as String;

      print("✅ Found unique ${itemType}: $itemNameInTrash ($itemUuid)");

      final prompt =
          '❓ Restore ${itemType} "$itemNameInTrash" ($itemUuid) to "$destinationPath"?';
      if (!_confirmAction(prompt, force)) {
        print("❌ Cancelled");
        io.exit(0);
      }

      // Phase 8.1: use /trash/restore (was incorrectly using
      // moveFile / moveFolder, which silently no-ops on trashed
      // items on the gateway side).
      print("🚀 Restoring item...");
      await client.restoreFromTrash(itemUuid, itemType,
          destinationFolderUuid: destinationFolderUuid);
      print("✅ Item restored successfully to: $destinationPath");
    } catch (e) {
      io.stderr.writeln('❌ Error restoring item: $e');
      io.exit(1);
    }
  }

  Future<void> handleTrashClear(ArgResults argResults) async {
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      final force = argResults['force'] as bool;
      print('🗑️  Empty trash — this is PERMANENT and cannot be undone.');
      if (!_confirmAction('❓ Permanently delete ALL items in trash?', force)) {
        print('❌ Cancelled');
        return;
      }

      await client.clearTrashAll();
      print('✅ Trash emptied.');
    } catch (e) {
      io.stderr.writeln('❌ Error clearing trash: $e');
      io.exit(1);
    }
  }

  /// Build a per-item move plan from already-resolved sources + a
  /// snapshot of the target's existing contents. Pure function so
  /// it's unit-testable without touching the network.
  ///
  /// Each `expanded` entry is `{srcPath, type, uuid, leaf}`. Each
  /// `targetExisting` entry is `{type, uuid}` keyed by leaf name.
  /// Each plan entry is `{srcPath, type, uuid, leaf, action,
  /// existingUuid?}` where action is one of `move`, `overwrite`, or
  /// `skip`. Skipped entries are NOT included in the plan; the
  /// `skipReason` for each skip is collected separately.
  static ({
    List<Map<String, dynamic>> plan,
    List<Map<String, String>> skips,
  }) buildMovePlan({
    required List<Map<String, dynamic>> expanded,
    required Map<String, Map<String, dynamic>> targetExisting,
    required String onConflict, // 'skip' | 'overwrite'
    required String targetResolvedPath,
  }) {
    final plan = <Map<String, dynamic>>[];
    final skips = <Map<String, String>>[];
    for (final item in expanded) {
      final srcPath = item['srcPath'] as String;
      final type = item['type'] as String;
      final uuid = item['uuid'] as String;
      final leaf = item['leaf'] as String;

      // Refuse to move an item into its current parent (no-op).
      final lastSlash = srcPath.lastIndexOf('/');
      final srcParent = lastSlash <= 0 ? '/' : srcPath.substring(0, lastSlash);
      if (srcParent == targetResolvedPath) {
        skips.add({'srcPath': srcPath, 'reason': 'already in target'});
        continue;
      }

      final existing = targetExisting[leaf];
      if (existing == null) {
        plan.add({
          'srcPath': srcPath,
          'type': type,
          'uuid': uuid,
          'leaf': leaf,
          'action': 'move',
        });
        continue;
      }
      if (onConflict == 'skip') {
        skips.add({'srcPath': srcPath, 'reason': 'target has $leaf'});
        continue;
      }
      // overwrite
      if ((existing['type'] as String?) == 'folder') {
        skips.add({
          'srcPath': srcPath,
          'reason': 'refusing to overwrite folder at target: $leaf',
        });
        continue;
      }
      plan.add({
        'srcPath': srcPath,
        'type': type,
        'uuid': uuid,
        'leaf': leaf,
        'action': 'overwrite',
        'existingUuid': existing['uuid'],
      });
    }
    return (plan: plan, skips: skips);
  }

  /// Library-callable batch-move: takes already-validated inputs,
  /// runs the resolve → plan → execute pipeline, returns counts.
  /// CLI-output side effects are gated by [silent] so tests can call
  /// this without flooding test output.
  ///
  /// Static so callers can pass an explicit [client] (e.g. tests
  /// that already have an authenticated InternxtClient and don't
  /// want to spin up a second one).
  ///
  /// Returns `(success, skipped, errors, planSize)` — tests assert
  /// on these.
  static Future<({int success, int skipped, int errors, int planSize})>
      executeMoveBatch({
    required InternxtClient client,
    required List<String> sources,
    required String targetPath,
    required String onConflict, // 'skip' | 'overwrite'
    required bool dryRun,
    required int workers,
    bool silent = false,
  }) async {
    void say(String m) {
      if (!silent) print(m);
    }

    // 1. Resolve target folder once.
    say('🔍 Resolving target: $targetPath');
    final targetInfo = await client.resolvePath(targetPath);
    if (targetInfo['type'] != 'folder') {
      throw Exception("Target '$targetPath' is a file, not a folder.");
    }
    final targetUuid = targetInfo['uuid'] as String;
    final targetResolvedPath = (targetInfo['path'] as String?) ?? targetPath;

    // 2. Pre-scan target listing once for conflict detection.
    final targetExisting = <String, Map<String, dynamic>>{};
    try {
      final tFolders = await client.listFolders(targetUuid);
      final tFiles = await client.listFolderFiles(targetUuid);
      for (final f in tFiles) {
        final plain = (f['name'] ?? '') as String;
        final ext = (f['fileType'] ?? '') as String;
        final leaf = ext.isNotEmpty ? '$plain.$ext' : plain;
        targetExisting[leaf] = {'type': 'file', 'uuid': f['uuid']};
      }
      for (final d in tFolders) {
        final leaf = (d['name'] ?? '') as String;
        if (leaf.isNotEmpty) {
          targetExisting[leaf] = {'type': 'folder', 'uuid': d['uuid']};
        }
      }
    } catch (e) {
      say('⚠️  Could not pre-scan target folder: $e');
    }

    // 3. Expand each source — wildcards or literal.
    final expanded = <Map<String, dynamic>>[];
    final notFound = <String>[];
    for (final src in sources) {
      if (src.contains('*') || src.contains('?') || src.contains('[')) {
        var parentPath = p.dirname(src);
        if (parentPath == '.') parentPath = '/';
        final leafPattern = p.basename(src);
        final glob = Glob(leafPattern);

        try {
          final parentInfo = await client.resolvePath(parentPath);
          final parentUuid = parentInfo['uuid'] as String;
          final folders = await client.listFolders(parentUuid);
          final files = await client.listFolderFiles(parentUuid);
          var matched = false;
          for (final f in files) {
            final name = (f['name'] ?? '') as String;
            final ext = (f['fileType'] ?? '') as String;
            final leaf = ext.isNotEmpty ? '$name.$ext' : name;
            if (glob.matches(leaf)) {
              expanded.add({
                'srcPath': '$parentPath/$leaf'.replaceAll('//', '/'),
                'type': 'file',
                'uuid': f['uuid'],
                'leaf': leaf,
              });
              matched = true;
            }
          }
          for (final d in folders) {
            final leaf = (d['name'] ?? '') as String;
            if (glob.matches(leaf)) {
              expanded.add({
                'srcPath': '$parentPath/$leaf'.replaceAll('//', '/'),
                'type': 'folder',
                'uuid': d['uuid'],
                'leaf': leaf,
              });
              matched = true;
            }
          }
          if (!matched) notFound.add(src);
        } catch (e) {
          if (!silent) {
            io.stderr.writeln("❌ Could not list parent of '$src': $e");
          }
        }
      } else {
        try {
          final info = await client.resolvePath(src);
          final resolvedPath = (info['path'] as String?) ?? src;
          final lastSlash = resolvedPath.lastIndexOf('/');
          final leaf = lastSlash < 0
              ? resolvedPath
              : resolvedPath.substring(lastSlash + 1);
          expanded.add({
            'srcPath': resolvedPath,
            'type': info['type'],
            'uuid': info['uuid'],
            'leaf': leaf,
          });
        } on Exception catch (e) {
          if (e.toString().contains('Path not found')) {
            notFound.add(src);
          } else {
            if (!silent) io.stderr.writeln("❌ Error resolving '$src': $e");
            notFound.add(src);
          }
        }
      }
    }

    if (!silent) {
      for (final m in notFound) {
        io.stderr.writeln('⚠️  Not found: $m');
      }
    }
    if (expanded.isEmpty) {
      throw Exception('Nothing to move.');
    }

    // 4. Build the per-item plan (pure function; unit-tested).
    final planResult = InternxtCLI.buildMovePlan(
      expanded: expanded,
      targetExisting: targetExisting,
      onConflict: onConflict,
      targetResolvedPath: targetResolvedPath,
    );
    final plan = planResult.plan;
    final skips = planResult.skips;

    say('🚚 Moving ${plan.length} item(s) → $targetResolvedPath');
    if (dryRun) say('🔬 DRY RUN — no changes will be made');
    for (final s in skips) {
      say("  ⏭️  Skip (${s['reason']}): ${s['srcPath']}");
    }
    for (final entry in plan) {
      final marker = entry['action'] == 'overwrite' ? '🔁' : '➡️';
      say("  $marker ${entry['type']}: ${entry['srcPath']}");
    }

    if (dryRun) {
      say('📊 Would move: ${plan.length}, skipped: ${skips.length}');
      return (
        success: 0,
        skipped: skips.length,
        errors: 0,
        planSize: plan.length,
      );
    }

    if (plan.isEmpty) {
      say('✅ All sources are already in target / fully skipped.');
      return (success: 0, skipped: skips.length, errors: 0, planSize: 0);
    }

    // 5. Run the plan with bounded parallelism.
    final maxWorkers = workers.clamp(1, plan.length);
    var success = 0;
    var errors = 0;
    await inxt_upload.runBoundedPool<Map<String, dynamic>>(
      plan,
      maxWorkers,
      (entry) async {
        try {
          if (entry['action'] == 'overwrite') {
            final existingUuid = entry['existingUuid'] as String?;
            if (existingUuid != null) {
              try {
                // trashItems → POST /storage/trash/add. Recoverable
                // from Internxt's 30-day trash if the user changes
                // their mind. deletePermanently here would no-op
                // because the file isn't in trash yet.
                await client.trashItems(existingUuid, 'file');
                // Force a fresh listing of the target folder so the
                // trash propagation is observable before the move
                // PATCH fires. Without this, Internxt's move
                // endpoint can see a stale "duplicate name in dst"
                // condition and silently no-op the move. Also pause
                // briefly to let backend indexes catch up.
                await Future<void>.delayed(const Duration(milliseconds: 500));
                await client.listFolderFiles(targetUuid);
              } catch (delErr) {
                if (!silent) {
                  io.stderr.writeln(
                      "  ❌ ${entry['srcPath']}: could not remove existing target ($delErr)");
                }
                errors++;
                return;
              }
            }
          }
          if (entry['type'] == 'file') {
            await client.moveFile(entry['uuid'] as String, targetUuid);
          } else {
            await client.moveFolder(entry['uuid'] as String, targetUuid);
          }
          success++;
        } catch (e) {
          if (!silent) {
            io.stderr.writeln("  ❌ ${entry['srcPath']}: $e");
          }
          errors++;
        }
      },
    );

    say('=' * 40);
    say('📊 Move Summary:');
    say('  ✅ Moved:    $success');
    say('  ⏭️  Skipped:  ${skips.length}');
    say('  ❌ Errors:   $errors');
    say('=' * 40);

    return (
      success: success,
      skipped: skips.length,
      errors: errors,
      planSize: plan.length,
    );
  }

  Future<void> handleMovePath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.length < 2) {
      io.stderr.writeln(
          '❌ Usage: dart cli.dart move-path <source...> <target-folder>');
      io.exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) throw Exception('Not logged in.');
      client.setAuth(creds);

      final sources = args.sublist(0, args.length - 1);
      final targetPath = args.last;
      final onConflict = argResults['on-conflict'] as String;
      final dryRun = argResults['dry-run'] as bool;
      final workers =
          int.tryParse(argResults['workers'] as String? ?? '4') ?? 4;

      final result = await InternxtCLI.executeMoveBatch(
        client: client,
        sources: sources,
        targetPath: targetPath,
        onConflict: onConflict,
        dryRun: dryRun,
        workers: workers,
      );
      if (result.errors > 0) io.exit(1);
    } catch (e) {
      io.stderr.writeln('❌ Move operation failed: $e');
      io.exit(1);
    }
  }

  Future<void> handleRenamePath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.length < 2) {
      io.stderr.writeln('❌ Usage: dart cli.dart rename-path <path> <new-name>');
      io.exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      final path = args[0];
      final newName = args[1];
      final force = argResults['force'] as bool;

      print("🔍 Resolving path: $path");
      final itemInfo = await client.resolvePath(path);
      final itemUuid = itemInfo['uuid'] as String;
      final itemType = itemInfo['type'] as String;
      final oldName = (itemInfo['metadata'] as Map)['name'] ?? path;

      final prompt = '❓ Rename ${itemType} "$oldName" to "$newName"?';
      if (!_confirmAction(prompt, force)) {
        print("❌ Cancelled");
        io.exit(0);
      }

      print("🚀 Renaming item...");
      if (itemType == 'file') {
        final String newPlainName;
        final String? newFileType;
        if (newName.contains('.')) {
          newPlainName = p.basenameWithoutExtension(newName);
          newFileType = p.extension(newName).replaceAll('.', '');
        } else {
          newPlainName = newName;
          newFileType = null;
        }
        await client.renameFile(itemUuid, newPlainName, newFileType);
      } else if (itemType == 'folder') {
        await client.renameFolder(itemUuid, newName);
      } else {
        throw Exception("Unknown item type: $itemType");
      }

      print("✅ Item renamed successfully to: $newName");
    } catch (e) {
      io.stderr.writeln('❌ Error renaming item: $e');
      io.exit(1);
    }
  }

  Future<void> handleResolve(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      io.stderr.writeln('❌ Usage: dart cli.dart resolve <path>');
      io.exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      final path = args[0];
      print("🔍 Resolving path: $path");

      final resolved = await client.resolvePath(path);

      print("\n✅ Path resolved successfully!");
      print("=" * 40);
      print("  Type: ${resolved['type']?.toString().toUpperCase()}");
      print("  UUID: ${resolved['uuid']}");
      print("\n  Metadata:");
      (resolved['metadata'] as Map<String, dynamic>).forEach((key, value) {
        print("    $key: $value");
      });
      print("=" * 40);
    } catch (e) {
      io.stderr.writeln('❌ Error resolving path: $e');
      io.exit(1);
    }
  }

  // Helper for confirmation
  bool _confirmAction(String prompt, bool force) {
    if (force) {
      return true;
    }
    io.stdout.write('$prompt [y/N]: ');
    final response = io.stdin.readLineSync()?.toLowerCase().trim();
    return response == 'y' || response == 'yes';
  }

  Future<void> handleTrashPath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      io.stderr.writeln('❌ Usage: dart cli.dart trash-path <path> [--force]');
      io.exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      final path = args[0];
      final force = argResults['force'] as bool;

      print("🔍 Resolving path: $path");
      final resolved = await client.resolvePath(path);

      final prompt = '❓ Move ${resolved['type']} "$path" to trash?';
      if (!_confirmAction(prompt, force)) {
        print("❌ Cancelled");
        io.exit(0);
      }

      await client.trashItems(
          resolved['uuid'] as String, resolved['type'] as String);

      print("✅ Item moved to trash: $path");
    } catch (e) {
      io.stderr.writeln('❌ Error trashing item: $e');
      io.exit(1);
    }
  }

  Future<void> handleDeletePath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      io.stderr.writeln('❌ Usage: dart cli.dart delete-path <path> [--force]');
      io.exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      final path = args[0];
      final force = argResults['force'] as bool;

      print("🔍 Resolving path: $path");
      final resolved = await client.resolvePath(path);

      print(
          "⚠️  WARNING: This will PERMANENTLY delete the item. This action cannot be undone!");
      final prompt = '❓ Permanently delete ${resolved['type']} "$path"?';
      if (!_confirmAction(prompt, force)) {
        print("❌ Cancelled");
        io.exit(0);
      }

      await client.deletePermanently(
          resolved['uuid'] as String, resolved['type'] as String);

      print("✅ Item permanently deleted: $path");
    } catch (e) {
      io.stderr.writeln('❌ Error deleting item: $e');
      io.exit(1);
    }
  }

  /// Format a remote mtime/ctime (ISO 8601, possibly null) to a
  /// fixed-width display string `YYYY-MM-DD HH:MM`. Falls back to a
  /// 16-space placeholder for missing/unparseable values so the
  /// column stays aligned. Public for testability.
  static String formatMtime(dynamic isoString) {
    if (isoString == null) return '                ';
    final s = isoString.toString();
    // Most strings come back as 2026-05-04T12:34:56.789Z. We only
    // want the date + HH:MM (16 chars total, indexes 0-15 with the
    // 'T' replaced by a space).
    if (s.length < 16) return s.padRight(16).substring(0, 16);
    return '${s.substring(0, 10)} ${s.substring(11, 16)}';
  }

  Future<void> handleList(ArgResults argResults) async {
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      final commandRestArgs = argResults.rest.sublist(1);
      final pathToList = commandRestArgs.isNotEmpty ? commandRestArgs[0] : '/';
      final bool showFullUUIDs = argResults['uuids'] as bool;

      print("🔍 Resolving path: $pathToList");
      final resolvedInfo = await client.resolvePath(pathToList);

      if (resolvedInfo['type'] != 'folder') {
        io.stderr
            .writeln("❌ Error: Path '$pathToList' is a file, not a folder.");
        io.exit(1);
      }
      final folderId = resolvedInfo['uuid'] as String;
      final resolvedPathDisplay = resolvedInfo['path'] ?? pathToList;

      print('📂 Listing folder: $resolvedPathDisplay (UUID: $folderId)\n');

      // detailed: true so each entry carries modificationTime /
      // updatedAt for the new Modified column (Phase 7.8). The cache
      // stores the full record either way, so this isn't a perf cost
      // beyond the first listing.
      final folders = await client.listFolders(folderId, detailed: true);
      final files = await client.listFolderFiles(folderId, detailed: true);

      final items = [...folders, ...files];

      if (items.isEmpty) {
        print('📭 Folder is empty');
        return;
      }

      // Column widths: Type(2) Name(40) Size(12) Modified(16) UUID
      // (8 short, 36 full). Box width adjusts for showFullUUIDs.
      final boxLen = showFullUUIDs ? 96 : 86;
      final headerSep = '═' * boxLen;
      print('╔$headerSep╗');
      print('║  Type  Name${' ' * 36}'
          '  Size${' ' * 8}'
          '  Modified${' ' * 8}'
          '  UUID${' ' * (showFullUUIDs ? 32 : 8)}║');
      print('╠$headerSep╣');

      int folderCount = 0;
      int fileCount = 0;
      for (var item in items) {
        final type = item['type'] == 'folder' ? '📁' : '📄';
        if (item['type'] == 'folder') {
          folderCount++;
        } else {
          fileCount++;
        }
        final plainName = (item['name'] ?? 'Unknown') as String;
        final fileType =
            (item['type'] == 'file' ? (item['fileType'] ?? '') : '') as String;
        final displayName = (fileType.isNotEmpty && item['type'] == 'file')
            ? '$plainName.$fileType'
            : plainName;
        final name = displayName.toString();
        final clippedName =
            name.length > 40 ? name.substring(0, 40) : name.padRight(40);
        final size =
            (item['type'] == 'folder' ? '<DIR>' : formatSize(item['size'] ?? 0))
                .padLeft(12);
        final mtime =
            formatMtime(item['modificationTime'] ?? item['updatedAt']);
        final uuid = (item['uuid'] ?? 'N/A') as String;
        final uuidCell = showFullUUIDs
            ? uuid.padRight(36)
            : '${uuid.substring(0, 8).padRight(8)}...';
        print('║  $type  $clippedName  $size  $mtime  $uuidCell║');
      }
      print('╚$headerSep╝');
      print(
          '\n📊 Total: ${items.length} items ($folderCount folders, $fileCount files)');
    } catch (e) {
      if (e.toString().contains("Path not found")) {
        io.stderr.writeln('❌ Error: Path not found.');
      } else {
        io.stderr.writeln('❌ Error listing folder: $e');
      }
      io.exit(1);
    }
  }

  // NOTE: This method 'handleListUUID' will probably be soon redundant given 'handleList'
  // now supports paths. I'm keeping it for compatibility, but note
  // that 'handleList' is the primary method.
  Future<void> handleListUUID(ArgResults argResults) async {
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      final commandRestArgs = argResults.rest.sublist(1);

      final folderId = commandRestArgs.isNotEmpty
          ? commandRestArgs[0]
          : creds['rootFolderId']! as String;
      final bool showFullUUIDs = argResults['uuids'] as bool;

      print('📂 Listing folder: $folderId\n');

      // Refactored calls (now use cache)
      final folders = await client.listFolders(folderId);
      final files = await client.listFolderFiles(folderId);

      final items = [...folders, ...files];

      if (items.isEmpty) {
        print('📭 Folder is empty');
        return;
      }

      if (showFullUUIDs) {
        print(
            '╔════════════════════════════════════════════════════════════════════════════════════════════════════╗');
        print(
            '║  Type    Name                                    Size            UUID                                 ║');
        print(
            '╠════════════════════════════════════════════════════════════════════════════════════════════════════╣');
      } else {
        print(
            '╔═══════════════════════════════════════════════════════════════════════════════╗');
        print(
            '║  Type    Name                                    Size            UUID        ║');
        print(
            '╠═══════════════════════════════════════════════════════════════════════════════╣');
      }
      for (var item in items) {
        final type = item['type'] == 'folder' ? '📁' : '📄';
        final plainName = (item['name'] ?? 'Unknown') as String;
        final fileType =
            (item['type'] == 'file' ? (item['fileType'] ?? '') : '') as String;
        final displayName = (fileType.isNotEmpty && item['type'] == 'file')
            ? '$plainName.$fileType'
            : plainName;
        final name = displayName.padRight(40);
        final size =
            item['type'] == 'folder' ? '<DIR>' : formatSize(item['size'] ?? 0);
        final uuid = (item['uuid'] ?? 'N/A') as String;
        if (showFullUUIDs) {
          print(
              '║  $type  ${name.substring(0, min(name.length, 40))}  ${size.padLeft(12)}  $uuid ║');
        } else {
          print(
              '║  $type  ${name.substring(0, min(name.length, 40))}  ${size.padLeft(12)}  ${uuid.substring(0, 8)}... ║');
        }
      }
      if (showFullUUIDs) {
        print(
            '╚════════════════════════════════════════════════════════════════════════════════════════════════════╝');
      } else {
        print(
            '╚═══════════════════════════════════════════════════════════════════════════════╝');
      }
      print(
          '\n📊 Total: ${items.length} items (${folders.length} folders, ${files.length} files)');
    } catch (e) {
      io.stderr.writeln('❌ Error: $e');
      io.exit(1);
    }
  }

  Future<void> handleUpload(ArgResults argResults) async {
    final sources = argResults.rest.sublist(1);
    if (sources.isEmpty) {
      io.stderr.writeln('❌ No source files or directories specified.');
      io.exit(1);
    }

    if (debugMode) {
      print('🚀 TRACE: Starting high-performance upload batch');
      print('📋 Target Path: ${argResults['target'] ?? '/'}');
      print('📋 On-Conflict: ${argResults['on-conflict']}');
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }

      // Load session into client (Hydrated Flow)
      client.setAuth(creds);

      // Extract Bridge Metadata from Hydrated Store
      final bridgeUser = creds['bridgeUser']?.toString();
      final userIdForAuth = creds['userId']?.toString();

      if (bridgeUser == null || userIdForAuth == null) {
        throw Exception(
            'Credentials file is missing bridgeUser or userId. Please login again to re-hydrate the session.');
      }

      final targetPath = argResults['target'] as String? ?? '/';
      final recursive = argResults['recursive'] as bool;
      final onConflict = argResults['on-conflict'] as String;
      final preserveTimestamps = argResults['preserve-timestamps'] as bool;
      final include = argResults['include'] as List<String>;
      final exclude = argResults['exclude'] as List<String>;
      final workers =
          int.tryParse(argResults['workers'] as String? ?? '4') ?? 4;
      // Within-file multipart concurrency for single large files (>= 100 MiB).
      inxt_upload.uploadChunkWorkers =
          (int.tryParse(argResults['chunk-workers'] as String? ?? '4') ?? 4)
              .clamp(1, 1 << 30);

      // Generate Batch ID for resumability (Go/Python style)
      final batchId = config.generateBatchId('upload', sources, targetPath);
      print("🔄 Batch ID: $batchId");

      var batchState = await config.loadBatchState(batchId);
      if (batchState != null) {
        print(
            "🔄 DEBUG: Resuming existing batch with ${batchState['tasks'].length} tasks.");
      }

      // Phase 7.7: Ctrl+C cancellation. First Ctrl+C cancels queued
      // workers (in-flight ones finish their current network call);
      // a second Ctrl+C does a hard exit. The subscription is
      // disposed in the finally below.
      final cancellationToken = inxt_upload.CancellationToken();
      late final StreamSubscription<io.ProcessSignal> sigintSub;
      sigintSub = io.ProcessSignal.sigint.watch().listen((_) {
        if (cancellationToken.isCancelled) {
          print('\n⚠️  Force-exiting on second Ctrl+C');
          io.exit(130);
        }
        print('\n🛑 Cancelling — finishing in-flight uploads, queued '
            'ones will be skipped. Press Ctrl+C again to force-exit.');
        cancellationToken.cancel();
      });

      // Step 1: Optimization - Resolve target once. We compute this for
      // its side effect (creates intermediate folders if needed); the
      // returned uuid is unused here because client.upload below resolves
      // the path again internally.
      await client._resolveOrCreateRemoteFolder(targetPath);

      // Step 2: Optimization - Perform batch existence check (Go rclone style)
      // This prevents thousands of individual resolvePath calls
      if (debugMode)
        print("🔍 [DEBUG] Pre-scanning target folder for existing items...");
      // (Implementation note: In a full sync, you'd collect source names first and send them to checkFilesExistence)

      try {
        await client.upload(
          sources,
          targetPath,
          recursive: recursive,
          onConflict: onConflict,
          preserveTimestamps: preserveTimestamps,
          include: include,
          exclude: exclude,
          bridgeUser: bridgeUser,
          userIdForAuth: userIdForAuth,
          batchId: batchId,
          initialBatchState: batchState,
          saveStateCallback: (state) async {
            await config.saveBatchState(batchId, state);
            if (debugMode) {
              print("💾 TRACE: Progress saved for Batch $batchId");
            }
          },
          workers: workers,
          cancellationToken: cancellationToken,
        );
      } finally {
        await sigintSub.cancel();
      }

      if (cancellationToken.isCancelled) {
        // State file is preserved so the user can resume with the
        // same arguments. Exit 130 (POSIX SIGINT convention).
        print('🛑 Aborted; state preserved for resume. Run the same '
            'command to continue.');
        io.exit(130);
      }

      await config.deleteBatchState(batchId);
      print("\n✅ Batch completed successfully.");
    } catch (e, stack) {
      io.stderr.writeln('\n❌ Upload failed: $e');
      if (debugMode) print('🔥 STACK TRACE:\n$stack');
      io.exit(1);
    }
  }

  Future<void> handleDownloadPath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      io.stderr.writeln('❌ Usage: dart cli.dart download-path <path>');
      io.exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds);

      final remotePath = args[0];
      final localDestination = argResults['target'] as String?;
      final recursive = argResults['recursive'] as bool;
      final onConflict = argResults['on-conflict'] as String;
      final preserveTimestamps = argResults['preserve-timestamps'] as bool;
      final include = argResults['include'] as List<String>;
      final exclude = argResults['exclude'] as List<String>;
      // Step B — parallel ranged downloads for large files (opt-in).
      inxt_download.rangedDownload = argResults['ranged'] as bool;
      inxt_download.downloadChunkWorkers =
          (int.tryParse(argResults['chunk-workers'] as String? ?? '4') ?? 4)
              .clamp(1, 1 << 30);

      final bridgeUser = creds['bridgeUser']?.toString();
      final userIdForAuth = creds['userId']?.toString();
      if (bridgeUser == null || userIdForAuth == null) {
        throw Exception(
            'Credentials file is missing bridgeUser or userId. Please login again.');
      }

      final batchId = config.generateBatchId(
          'download', [remotePath], localDestination ?? '.');
      print("🔄 Batch ID: $batchId");

      var batchState = await config.loadBatchState(batchId);

      print('⬇️  Downloading from path: $remotePath');

      await client.downloadPath(
        remotePath,
        localDestination: localDestination,
        recursive: recursive,
        onConflict: onConflict,
        preserveTimestamps: preserveTimestamps,
        include: include,
        exclude: exclude,
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
        batchId: batchId,
        initialBatchState: batchState,
        saveStateCallback: (state) => config.saveBatchState(batchId, state),
      );

      await config.deleteBatchState(batchId);
      print("✅ Batch completed.");
    } catch (e) {
      io.stderr.writeln('❌ Download failed: $e');
      io.exit(1);
    }
  }

  Future<void> handleDownload(List<String> args) async {
    if (args.isEmpty) {
      io.stderr.writeln('❌ Usage: dart cli.dart download <file-uuid>');
      io.exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }

      client.setAuth(creds);

      final fileUuid = args[0];
      final bridgeUser = creds['bridgeUser']?.toString();
      final userIdForAuth = creds['userId']?.toString();

      if (bridgeUser == null || userIdForAuth == null) {
        throw Exception(
            'Credentials file is missing bridgeUser or userId. Please login again.');
      }

      print('⬇️  Downloading file: $fileUuid\n');

      // Bounded-memory disk download: streams straight to the remote filename
      // in the CWD (parallel ranged when --ranged + large), so peak RAM is the
      // range/chunk size rather than the whole file.
      final result = await client.downloadFileToDisk(
          fileUuid, null, bridgeUser, userIdForAuth);
      final filename = result['filename'] as String;
      final size = result['size'] as int;

      print('\n✅ Downloaded successfully: $filename');
      print('📊 Size: ${formatSize(size)}');
    } catch (e) {
      io.stderr.writeln('❌ Error: $e');
      io.exit(1);
    }
  }

  Future<void> handleConfig() async {
    print('╔════════════════════════════════════════╗');
    print('║         Configuration                  ║');
    print('╚════════════════════════════════════════╝');
    print('📁 Config dir: ${config.configDir}');
    print('🔐 Credentials file: ${config.credentialsFile}');
    print('🔄 Batch states dir: ${config.batchStateDir}');
    print('');
    print('🌐 API Endpoints (from Python blueprint):');
    print('   NETWORK_URL: ${client.networkUrl}');
    print('     └─ Data: /buckets/{bucketId}/files/...');
    print('   DRIVE_API_URL: ${client.driveApiUrl}');
    print('     └─ Auth: /auth/login, /auth/security, /users/refresh');
    print('     └─ Meta: /folders/..., /files/..., /fuzzy/...');
    print('');
    print('🔒 Crypto:');
    print('   APP_CRYPTO_SECRET: ${InternxtClient.appCryptoSecret}');
  }

  Future<void> handleQuota() async {
    final creds = await config.readCredentials();
    if (creds == null) {
      io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
      io.exit(1);
    }
    client.setAuth(creds);

    final usage =
        await inxt_api.getStorageUsage(client.driveApiUrl, client.newToken);

    // Internxt has historically returned a few different shapes
    // (`{usage, limit}` is the current one; older versions used
    // `{used, available}`). Probe a couple of common keys and
    // dump the raw JSON if we can't recognize any.
    final used = usage['usage'] ?? usage['used'];
    final limit = usage['limit'] ?? usage['available'];

    print('╔════════════════════════════════════════╗');
    print('║         Storage Usage                  ║');
    print('╚════════════════════════════════════════╝');
    if (used != null && used is num) {
      print('📊 Used:  ${formatSize(used.toInt())}');
    }
    if (limit != null && limit is num) {
      print('📊 Limit: ${formatSize(limit.toInt())}');
    }
    if (used is num && limit is num && limit > 0) {
      final pct = (used / limit * 100).toStringAsFixed(1);
      print('📈 Used:  $pct%');
    }
    if (used == null && limit == null) {
      print('⚠️  Unrecognized usage shape; raw response:');
      print(usage);
    }
  }

  Future<void> handleTest() async {
    print('🧪 Running crypto tests...\n');

    print('Test 1: APP_CRYPTO_SECRET validation');
    print('   Expected: 6KYQBP847D4ATSFA');
    print('   Actual: ${InternxtClient.appCryptoSecret}');
    assert(InternxtClient.appCryptoSecret == '6KYQBP847D4ATSFA',
        'APP_CRYPTO_SECRET mismatch!');
    print('   ✅ PASS\n');

    print('Test 2: API URLs validation');
    print('   NETWORK_URL: ${client.networkUrl}');
    assert(
        InternxtClient.defaultNetworkUrl ==
            'https://gateway.internxt.com/network',
        'NETWORK_URL default mismatch! Expected gateway.internxt.com/network');
    print('   DRIVE_API_URL: ${client.driveApiUrl}');
    assert(
        InternxtClient.defaultDriveApiUrl ==
            'https://gateway.internxt.com/drive',
        'DRIVE_API_URL default mismatch! Expected gateway.internxt.com/drive');
    print('   ✅ PASS\n');

    print('Test 3: Encryption/Decryption (OpenSSL compat)');
    final testText = 'Hello Internxt';
    final encrypted =
        client.encryptTextWithKey(testText, InternxtClient.appCryptoSecret);
    print('   Encrypted: ${encrypted.substring(0, 32)}...');
    final decrypted =
        client.decryptTextWithKey(encrypted, InternxtClient.appCryptoSecret);
    print('   Decrypted: $decrypted');
    assert(decrypted == testText, 'Encryption/Decryption failed!');
    print('   ✅ PASS\n');

    print('Test 4: Password hashing (PBKDF2-SHA1)');
    final password = 'testpass123';
    final salt = '1234567890abcdef1234567890abcdef';
    final hashResult = client.passToHash(password, salt);
    print('   Salt: $salt');
    print('   Hash: ${hashResult['hash']!.substring(0, 32)}...');
    final expectedHash =
        'a329c2393e185f403c03b11e2f18f1f771960205b38d3adaf6861a5c681d1112';
    assert(hashResult['hash']! == expectedHash, 'PBKDF2-SHA1 hash mismatch!');
    print('   ✅ PASS\n');

    print('Test 5: Mnemonic validation');
    final validMnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    final isValid = bip39.validateMnemonic(validMnemonic);
    print('   Mnemonic: ${validMnemonic.substring(0, 40)}...');
    print('   Valid: $isValid');
    assert(isValid, 'Valid mnemonic should pass validation');
    print('   ✅ PASS\n');

    print('Test 6: File Key Derivation (SHA512)');
    final key = Uint8List.fromList(utf8.encode('test-key'));
    final data = Uint8List.fromList(utf8.encode('test-data'));
    final derived = client.getFileDeterministicKey(key, data);
    print(
        '   SHA512 derived key (hex): ${HEX.encode(derived).substring(0, 32)}...');
    final expectedDerived =
        '5b3318451d655f050b46b04e6c196cfb6b716e288e7343c484795b5e73e97fce6f65832a8f307328b1853b05b38f3b7c251dadbf1893c52a32c2865c6c0b387c';
    assert(HEX.encode(derived) == expectedDerived,
        'SHA512 key derivation mismatch!');
    print('   ✅ PASS\n');

    print('✅ All tests passed!');
  }

  Future<void> handleSearch(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      io.stderr.writeln('❌ Usage: dart cli.dart search <query>');
      io.exit(1);
    }
    final query = args[0];
    final detailed = argResults['uuids'] as bool; // re-using --uuids flag

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds); // FIX: Cast to correct type

      print("🔍 Searching for '$query' across your drive...");
      if (detailed) {
        print("   (Fetching full paths, this may take a moment...)");
      }

      final results = await client.search(query, detailed: detailed);
      final folders = results['folders']!;
      final files = results['files']!;

      if (folders.isEmpty && files.isEmpty) {
        print("\n📭 No results found.");
        return;
      }

      print("\n" + "=" * 60);
      if (folders.isNotEmpty) {
        print("📂 Folders (${folders.length}):");
        for (var folder in folders) {
          final displayName = folder['fullPath'] ?? folder['name'];
          print("  📁 $displayName (UUID: ${folder['uuid']})");
        }
      }

      if (files.isNotEmpty) {
        print("\n📄 Files (${files.length}):");
        for (var file in files) {
          final displayName = (file['fullPath'] ?? file['name']) as String;
          final type = (file['type'] ?? '') as String;
          final fullName = (type.isNotEmpty && !displayName.endsWith(type))
              ? '$displayName.$type'
              : displayName;
          print("  📄 $fullName (UUID: ${file['uuid']})");
        }
      }
      print("=" * 60);
      print("\n💡 Use 'download-path' or 'list-path' with the full path.");
    } catch (e) {
      io.stderr.writeln('❌ Error during search: $e');
      io.exit(1);
    }
  }

  Future<void> handleFind(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.length < 2) {
      io.stderr.writeln('❌ Usage: dart cli.dart find <path> <pattern>');
      io.stderr.writeln('   Example: dart cli.dart find / "*.pdf"');
      io.exit(1);
    }
    final path = args[0];
    final pattern = args[1];
    final maxDepth =
        int.tryParse(argResults['maxdepth'] as String? ?? '-1') ?? -1;

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds); // FIX: Cast to correct type

      print("🔍 Finding files matching '$pattern' in '$path'...");
      if (maxDepth != -1) {
        print("   (Limiting search to $maxDepth levels deep)");
      }

      final results = await client.findFiles(
        path,
        pattern,
        maxDepth: maxDepth,
      );

      if (results.isEmpty) {
        print("\n📭 No results found.");
        return;
      }

      print("\n" + "=" * 60);
      print("📄 Found Files (${results.length}):");
      for (var file in results) {
        final size = formatSize(file['size'] ?? 0);
        print("  ${file['fullPath']}  ($size)");
      }
      print("=" * 60);
      print("\n💡 Use 'download-path' with the full path.");
    } catch (e) {
      io.stderr.writeln('❌ Error during find: $e');
      io.exit(1);
    }
  }

  Future<void> handleTree(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    final path = args.isNotEmpty ? args[0] : '/';
    final maxDepth = int.tryParse(argResults['depth'] as String? ?? '3') ?? 3;

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        io.stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        io.exit(1);
      }
      client.setAuth(creds); // FIX: Cast to correct type

      print("\n🌳 Folder tree starting from: $path");
      print("=" * 60);
      print(path == '/' ? '📁 /' : '📁 ${p.basename(path)}');

      await client.printTree(
        path,
        (line) => print(line),
        maxDepth: maxDepth,
      );

      print("\n(Showing maximum $maxDepth levels deep)");
    } catch (e) {
      io.stderr.writeln('❌ Error generating tree: $e');
      io.exit(1);
    }
  }
}

// ============================================================================
// INTERNXT CLIENT
// ============================================================================

class InternxtClient {
  // Defaults for the production gateway. Constructor-overridable so
  // Flutter consumers (cloud-dart's Web build) can route through a
  // proxy — e.g., `/api/internxt-network` served by Vercel — without
  // hitting the gateway directly from the browser.
  static const String defaultNetworkUrl =
      'https://gateway.internxt.com/network';
  static const String defaultDriveApiUrl = 'https://gateway.internxt.com/drive';
  static const String appCryptoSecret = '6KYQBP847D4ATSFA';

  final String networkUrl;
  final String driveApiUrl;

  bool debugMode = false;
  final ConfigService config;

  String? authToken;
  String? newToken;
  String? mnemonic;
  String? userEmail;
  String? userId;
  String? rootFolderId;
  String? bucketId;
  // Bridge auth pair, populated from credentials by setAuth.
  // bridgeUser is the network-API basic-auth username; userIdForAuth
  // is the userId variant the bridge expects (Phase 7.10: fresh
  // login lacks the explicit userIdForAuth field, so setAuth falls
  // back to userId — required for the path facade and any other
  // session-driven caller).
  String? bridgeUser;
  String? userIdForAuth;

  // Caching variables — see cache.dart for the entry shape, the TTL
  // constant (`cacheDuration`), and the invalidation helpers.
  final Map<String, CacheEntry> _folderCache = {};
  final Map<String, CacheEntry> _fileCache = {};

  // Token refresh lock
  bool _isRefreshingToken = false;

  InternxtClient({
    required this.config,
    String? networkUrl,
    String? driveApiUrl,
  })  : networkUrl = networkUrl ?? defaultNetworkUrl,
        driveApiUrl = driveApiUrl ?? defaultDriveApiUrl;

  void log(String message) {
    if (debugMode) {
      print('🔍 [DEBUG] $message');
    }
  }

  void setAuth(Map<String, dynamic> creds) {
    log("🔑 TRACE: Updating client session state from credentials");
    authToken = creds['token']?.toString();
    newToken = creds['newToken']?.toString();
    mnemonic = creds['mnemonic']?.toString();
    userEmail = creds['email']?.toString();
    userId = creds['userId']?.toString(); // Hydrated field
    rootFolderId = creds['rootFolderId']?.toString();
    bucketId = creds['bucketId']?.toString(); // Hydrated field
    bridgeUser = creds['bridgeUser']?.toString();
    // Phase 7.10: fresh-login responses don't include userIdForAuth
    // (only refresh responses do). Fall back to userId so callers
    // that depend on this field — including the path facade —
    // don't NPE on a fresh session.
    userIdForAuth = (creds['userIdForAuth'] ?? creds['userId'])?.toString();

    log("📊 TRACE: Session loaded for $userEmail (Bucket: $bucketId)");
  }
  // --- Token Refresh ---
  // Protocol calls live in auth.dart. The orchestrator below stays
  // here because it ties three concerns together: the
  // _isRefreshingToken lock, the ConfigService persistence layer,
  // and the InternxtClient setAuth state mutator.

  Future<Map<String, dynamic>> _apiRefreshToken(String currentNewToken) =>
      inxt_auth.apiRefreshToken(driveApiUrl, currentNewToken);

  /// Refreshes and saves auth tokens.
  Future<void> refreshToken() async {
    if (_isRefreshingToken) return;
    _isRefreshingToken = true;

    try {
      log("🔄 TRACE: Refreshing tokens and rotating Bridge Auth...");
      final currentCreds = await config.readCredentials();
      if (currentCreds == null || currentCreds['newToken'] == null) {
        throw Exception("No valid credentials found to refresh.");
      }

      final resp = await _apiRefreshToken(currentCreds['newToken'] as String);
      final user = resp['user'];

      final updatedCreds = {
        ...currentCreds,
        'token': resp['token'],
        'newToken': resp['newToken'],
        'bridgeUser': user['bridgeUser'],
        'userIdForAuth': user['userId'],
        'bridgePass': inxt_auth.computeBridgePass(user['userId']),
      };

      setAuth(updatedCreds);
      await config.saveCredentials(updatedCreds);
      log("✅ TRACE: Token rotation successful.");
    } catch (e) {
      log("❌ TRACE: Token rotation failed: $e");
      rethrow;
    } finally {
      _isRefreshingToken = false;
    }
  }

  // --- Auth ---
  // Protocol implementations live in auth.dart; these wrappers thread
  // the InternxtClient's static URL/secret constants through.

  Future<bool> is2faNeeded(String email) =>
      inxt_auth.is2faNeeded(driveApiUrl, email);

  Future<Map<String, dynamic>> login(
    String email,
    String password, {
    String? tfaCode,
  }) =>
      inxt_auth.login(
        driveApiUrl,
        appCryptoSecret,
        email,
        password,
        tfaCode: tfaCode,
      );

  Future<Map<String, dynamic>> getFileMetadata(String fileUuid) =>
      inxt_api.getFileMetadata(driveApiUrl, newToken, fileUuid);

  Future<Map<String, dynamic>> getFolderMetadata(String folderUuid) =>
      inxt_api.getFolderMetadata(driveApiUrl, newToken, folderUuid);

  // --- Crypto Helpers ---
  // Implementations live in crypto.dart. These thin wrappers keep the
  // existing test surface (`client.encryptTextWithKey(...)`) working
  // without forcing every test to switch to the top-level functions.

  Map<String, String> passToHash(String password, String salt) =>
      inxt_crypto.passToHash(password, salt);

  Map<String, dynamic> generateKeys(String password) =>
      inxt_crypto.generateKeys(password);

  String encryptTextWithKey(String textToEncrypt, String secret) =>
      inxt_crypto.encryptTextWithKey(textToEncrypt, secret);

  String decryptTextWithKey(String encryptedText, String secret) =>
      inxt_crypto.decryptTextWithKey(encryptedText, secret);

  Map<String, Uint8List> getKeyAndIvFrom(String secret, Uint8List salt) =>
      inxt_crypto.getKeyAndIvFrom(secret, salt);

  // --- List + path resolution ---
  // Implementations live in drive.dart. These wrappers thread the
  // (URL, token) snapshot and the relevant cache map through.

  Future<List<Map<String, dynamic>>> listFolders(String folderId,
          {bool detailed = false}) =>
      inxt_drive.listFolders(driveApiUrl, newToken, _folderCache, folderId,
          detailed: detailed);

  Future<List<Map<String, dynamic>>> listFolderFiles(String folderId,
          {bool detailed = false}) =>
      inxt_drive.listFolderFiles(driveApiUrl, newToken, _fileCache, folderId,
          detailed: detailed);

  Future<Map<String, dynamic>> resolvePath(String path) =>
      inxt_drive.resolvePath(
          driveApiUrl, newToken, rootFolderId, _folderCache, _fileCache, path);

  // --- Download Operations ---

  // --- Download pipeline ---
  // Implementations live in download.dart. These wrappers thread
  // session state through to the free functions.

  Future<Map<String, dynamic>> downloadFile(
    String fileUuid,
    String bridgeUser,
    String userIdForAuth, {
    bool preserveTimestamps = false,
  }) =>
      inxt_download.downloadFile(
        driveApiUrl,
        networkUrl,
        newToken,
        mnemonic!,
        fileUuid,
        bridgeUser,
        userIdForAuth,
        preserveTimestamps: preserveTimestamps,
      );

  /// In-memory download returning just the decrypted bytes. For
  /// consumers (image preview, Web download) that don't need the
  /// metadata-rich shape from [downloadFile]. Streams the network
  /// read so [onProgress] fires per HTTP chunk.
  Future<Uint8List> downloadFileBytes(
    String fileUuid,
    String bridgeUser,
    String userIdForAuth, {
    void Function(int bytesDownloaded, int totalBytes)? onProgress,
    http.Client? httpClient,
  }) =>
      inxt_download.downloadFileBytes(
        driveApiUrl,
        networkUrl,
        newToken,
        mnemonic!,
        fileUuid,
        bridgeUser,
        userIdForAuth,
        onProgress: onProgress,
        httpClient: httpClient,
      );

  Future<Map<String, dynamic>> downloadFileStreamed(
    String fileUuid,
    String destinationPath,
    String bridgeUser,
    String userIdForAuth,
  ) =>
      inxt_download.downloadFileStreamed(
        driveApiUrl,
        networkUrl,
        newToken,
        mnemonic!,
        fileUuid,
        destinationPath,
        bridgeUser,
        userIdForAuth,
      );

  /// Bounded-memory disk download (parallel ranged when enabled + large, else a
  /// single streaming GET). Writes to [destinationPath] (a dir, a file path, or
  /// null = remote name in CWD) and returns metadata — peak RAM is the
  /// range/chunk size, not the file size.
  Future<Map<String, dynamic>> downloadFileToDisk(
    String fileUuid,
    String? destinationPath,
    String bridgeUser,
    String userIdForAuth,
  ) =>
      inxt_download.downloadFileToDisk(
        driveApiUrl,
        networkUrl,
        newToken,
        mnemonic!,
        fileUuid,
        destinationPath,
        bridgeUser,
        userIdForAuth,
      );

  /// Thin delegate to `utils.shouldIncludeFile`. Kept as a method on
  /// InternxtClient so existing callers (`client.shouldIncludeFile(...)`)
  /// keep working; new code should call the top-level function directly.
  bool shouldIncludeFile(
    String fileName,
    List<String> include,
    List<String> exclude,
  ) =>
      inxt_utils.shouldIncludeFile(fileName, include, exclude);

  Future<void> downloadPath(
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
  }) =>
      inxt_download.downloadPath(
        driveApiUrl,
        networkUrl,
        newToken,
        rootFolderId,
        mnemonic!,
        _folderCache,
        _fileCache,
        remotePath,
        localDestination: localDestination,
        recursive: recursive,
        onConflict: onConflict,
        preserveTimestamps: preserveTimestamps,
        include: include,
        exclude: exclude,
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
        batchId: batchId,
        initialBatchState: initialBatchState,
        saveStateCallback: saveStateCallback,
      );

  // --- Upload Operations ---

  Future<Map<String, dynamic>> createFolderRecursive(String path,
          {String? creationTime, String? modificationTime}) =>
      inxt_drive.createFolderRecursive(
          driveApiUrl, newToken, rootFolderId, _folderCache, _fileCache, path,
          creationTime: creationTime, modificationTime: modificationTime);

  // --- Upload pipeline ---
  // Implementations live in upload.dart. These wrappers thread
  // session state (URLs, token, mnemonic, bucketId, root, caches)
  // through to the free functions.

  Future<Map<String, dynamic>> updateFile(
    String fileUuid,
    io.File localFile, {
    required String bridgeUser,
    required String userIdForAuth,
  }) =>
      inxt_upload.updateFile(
        driveApiUrl,
        networkUrl,
        newToken,
        mnemonic!,
        bucketId!,
        _folderCache,
        _fileCache,
        fileUuid,
        localFile,
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
      );

  Future<Map<String, dynamic>> copyItem(
    String itemUuid,
    String destinationFolderUuid, {
    required String bridgeUser,
    required String userIdForAuth,
  }) =>
      inxt_upload.copyItem(
        driveApiUrl,
        networkUrl,
        newToken,
        mnemonic!,
        bucketId!,
        _folderCache,
        _fileCache,
        itemUuid,
        destinationFolderUuid,
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
      );

  Future<String> uploadSingleItem(
    io.File localFile,
    String targetRemoteParentPath,
    String targetFolderUuid,
    String onConflict, {
    required String bridgeUser,
    required String userIdForAuth,
    required bool preserveTimestamps,
    String? remoteFileName,
  }) =>
      inxt_upload.uploadSingleItem(
        networkUrl,
        driveApiUrl,
        newToken,
        rootFolderId,
        mnemonic!,
        bucketId!,
        _folderCache,
        _fileCache,
        localFile,
        targetRemoteParentPath,
        targetFolderUuid,
        onConflict,
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
        preserveTimestamps: preserveTimestamps,
        remoteFileName: remoteFileName,
      );

  Future<void> upload(
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
    inxt_upload.CancellationToken? cancellationToken,
  }) =>
      inxt_upload.upload(
        networkUrl,
        driveApiUrl,
        newToken,
        rootFolderId,
        mnemonic!,
        bucketId!,
        _folderCache,
        _fileCache,
        sources,
        targetPath,
        recursive: recursive,
        onConflict: onConflict,
        preserveTimestamps: preserveTimestamps,
        include: include,
        exclude: exclude,
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
        batchId: batchId,
        initialBatchState: initialBatchState,
        saveStateCallback: saveStateCallback,
        workers: workers,
        cancellationToken: cancellationToken,
      );

  Future<Map<String, dynamic>> _resolveOrCreateRemoteFolder(
          String targetPath) =>
      inxt_drive.resolveOrCreateRemoteFolder(driveApiUrl, newToken,
          rootFolderId, _folderCache, _fileCache, targetPath);

  // --- File/Trash Operations ---
  // Implementations live in drive.dart. These wrappers thread the
  // gateway URL, the bearer token snapshot, and (where invalidation
  // is needed) the two cache maps through to the free functions.

  Future<List<Map<String, dynamic>>> getTrashContent(
          {int offset = 0, int limit = 50}) =>
      inxt_drive.getTrashContent(driveApiUrl, newToken,
          offset: offset, limit: limit);

  Future<void> moveFile(String fileUuid, String destinationFolderUuid) =>
      inxt_drive.moveFile(driveApiUrl, newToken, _folderCache, _fileCache,
          fileUuid, destinationFolderUuid);

  Future<void> moveFolder(String folderUuid, String destinationFolderUuid) =>
      inxt_drive.moveFolder(driveApiUrl, newToken, _folderCache, _fileCache,
          folderUuid, destinationFolderUuid);

  Future<void> renameFile(
          String fileUuid, String newPlainName, String? newType) =>
      inxt_drive.renameFile(driveApiUrl, newToken, _folderCache, _fileCache,
          fileUuid, newPlainName, newType);

  Future<void> renameFolder(String folderUuid, String newName) =>
      inxt_drive.renameFolder(
          driveApiUrl, newToken, _folderCache, _fileCache, folderUuid, newName);

  Future<void> setFileTimestamp(String fileUuid, DateTime mTime) =>
      inxt_drive.setFileTimestamp(
          driveApiUrl, newToken, _folderCache, _fileCache, fileUuid, mTime);

  Future<void> setFolderTimestamp(String folderUuid, DateTime mTime) =>
      inxt_drive.setFolderTimestamp(
          driveApiUrl, newToken, _folderCache, _fileCache, folderUuid, mTime);

  Future<void> trashItems(String uuid, String type) => inxt_drive.trashItems(
      driveApiUrl, newToken, _folderCache, _fileCache, uuid, type);

  Future<void> deletePermanently(String uuid, String type) =>
      inxt_drive.deletePermanently(driveApiUrl, newToken, uuid, type);

  Future<Map<String, dynamic>> restoreFromTrash(
    String itemUuid,
    String itemType, {
    String? destinationFolderUuid,
  }) =>
      inxt_drive.restoreFromTrash(
          driveApiUrl, newToken, _folderCache, _fileCache, itemUuid, itemType,
          destinationFolderUuid: destinationFolderUuid);

  Future<void> clearTrashAll() =>
      inxt_drive.clearTrashAll(driveApiUrl, newToken);

  // --- Search / Find / Tree ---
  // Implementations live in drive.dart. These wrappers thread the
  // session state through.

  Future<Map<String, List<Map<String, dynamic>>>> search(String query,
          {bool detailed = false}) =>
      inxt_drive.search(driveApiUrl, newToken, rootFolderId, query,
          detailed: detailed);

  Future<List<Map<String, dynamic>>> findFiles(
    String startPath,
    String pattern, {
    int maxDepth = -1,
  }) =>
      inxt_drive.findFiles(driveApiUrl, newToken, rootFolderId, _folderCache,
          _fileCache, startPath, pattern,
          maxDepth: maxDepth);

  Future<void> printTree(
    String path,
    void Function(String) printLine, {
    int maxDepth = 3,
    int currentDepth = 0,
    String prefix = '',
  }) =>
      inxt_drive.printTree(driveApiUrl, newToken, rootFolderId, _folderCache,
          _fileCache, path, printLine,
          maxDepth: maxDepth, currentDepth: currentDepth, prefix: prefix);

  // --- File Crypto ---
  // Implementations live in crypto.dart. See note above passToHash.

  Uint8List getFileDeterministicKey(Uint8List key, Uint8List data) =>
      inxt_crypto.getFileDeterministicKey(key, data);

  Uint8List generateFileBucketKey(String mnemonic, String bucketId) =>
      inxt_crypto.generateFileBucketKey(mnemonic, bucketId);

  Uint8List generateFileKey(
          String mnemonic, String bucketId, Uint8List index) =>
      inxt_crypto.generateFileKey(mnemonic, bucketId, index);

  Uint8List decryptStream(
    Uint8List encryptedData,
    String mnemonic,
    String bucketId,
    String fileIndexHex,
  ) =>
      inxt_crypto.decryptStream(
          encryptedData, mnemonic, bucketId, fileIndexHex);

  Map<String, dynamic> encryptStream(
    Uint8List data,
    String mnemonic,
    String bucketId,
  ) =>
      inxt_crypto.encryptStream(data, mnemonic, bucketId);
}

// ConfigService lives in config.dart; the export at the top of this
// file makes it visible to anyone who does `import 'cli.dart';`.

// formatSize lives in utils.dart; re-exported via the export at the
// top of this file.
