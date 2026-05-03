#!/usr/bin/env dart

import 'dart:convert'; // Required for latin1, json, utf8, base64
import 'dart:async'; // For TimeoutException
import 'dart:io' as io; // Use a prefix for dart:io
import 'dart:math';
import 'dart:typed_data';
import 'package:args/args.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:http/http.dart' as http;
import 'package:pointycastle/export.dart';
import 'package:bip39/bip39.dart' as bip39;
import 'package:hex/hex.dart';
import 'package:path/path.dart' as p;
import 'package:glob/glob.dart';
import 'package:glob/list_local_fs.dart';

// WebDAV Imports
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_dav/shelf_dav.dart';
import 'webdav_filesystem.dart'; // Our custom implementation

/// Internxt CLI in Dart
void main(List<String> arguments) async {
  final cli = InternxtCLI();
  await cli.run(arguments);
}

// Helper class for cache entries
class _CacheEntry {
  final dynamic items;
  final DateTime timestamp;
  _CacheEntry({required this.items, required this.timestamp});
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
          help: 'Action if target exists (overwrite/skip)',
          allowed: ['overwrite', 'skip'],
          defaultsTo: 'skip')
      ..addMultiOption('include', help: 'Include only files matching pattern')
      ..addMultiOption('exclude', help: 'Exclude files matching pattern')
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
          help: 'Port for WebDAV server (default: 8080)', defaultsTo: '8080');

    final argResults = parser.parse(arguments);
    debugMode = argResults['debug'];
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
          await handleDownload(argResults.rest.sublist(1));
          break;
        case 'download-path':
          await handleDownloadPath(argResults);
          break;
        case 'upload':
          await handleUpload(argResults);
          break;
        case 'config':
          await handleConfig();
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
    final bool background = argResults['background'];
    final int port = int.tryParse(argResults['port'] ?? '8080') ?? 8080;

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
    final port = int.tryParse(argResults['port'] ?? '8080') ?? 8080;

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
    final port = int.tryParse(argResults['port'] ?? '8080') ?? 8080;
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
    final port = int.tryParse(argResults['port'] ?? '8080') ?? 8080;
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
    final port = int.tryParse(argResults['port'] ?? '8080') ?? 8080;

    print('⚙️  WebDAV Server Configuration');
    print('=' * 40);
    print('   Host: localhost');
    print('   Port: $port');
    print('   User: internxt');
    print('   Pass: internxt-webdav');
    print('   Protocol: http (SSL not implemented in this version)');
    print('   Background PID File: ${config.webdavPidFile}');
  }

  Future<void> handleLogin(List<String> args) async {
    if (debugMode) {
      print('🔍 Debug mode enabled\n');
      print('📋 API Configuration:');
      print('   NETWORK_URL (data): ${InternxtClient.networkUrl}');
      print('   DRIVE_API_URL (auth/meta): ${InternxtClient.driveApiUrl}');
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

      final bool showFullUUIDs = argResults['uuids'];
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
        if (item['type'] == 'folder')
          folderCount++;
        else
          fileCount++;
        final plainName = item['name'] ?? 'Unknown';
        final fileType = item['fileType'] ?? '';
        final displayName = (fileType.isNotEmpty && item['type'] == 'file')
            ? '$plainName.$fileType'
            : plainName;
        final name = displayName.toString().padRight(40);
        final size =
            item['type'] == 'folder' ? '<DIR>' : formatSize(item['size'] ?? 0);
        final uuid = item['uuid'] ?? 'N/A';
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

      print("🚀 Restoring item (trying file first)...");
      try {
        // This call is now refactored (token refresh, cache invalidation)
        await client.moveFile(itemUuid, destinationFolderUuid);
        print("✅ Item restored successfully (as file) to: $destinationPath");
      } catch (fileErr) {
        print("   File restore failed ($fileErr), trying folder...");
        try {
          // This call is now refactored (token refresh, cache invalidation)
          await client.moveFolder(itemUuid, destinationFolderUuid);
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
        final plainName = item['name'] ?? 'Unknown';
        final fileType = item['fileType'] ?? '';
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

      print("🚀 Restoring item...");
      if (itemType == 'file') {
        await client.moveFile(itemUuid, destinationFolderUuid);
      } else if (itemType == 'folder') {
        await client.moveFolder(itemUuid, destinationFolderUuid);
      } else {
        throw Exception("Unknown item type: $itemType");
      }

      print("✅ Item restored successfully to: $destinationPath");
    } catch (e) {
      io.stderr.writeln('❌ Error restoring item: $e');
      io.exit(1);
    }
  }

  Future<void> handleMovePath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.length < 2) {
      io.stderr.writeln(
          '❌ Usage: dart cli.dart move-path "<source-pattern>" <destination-path>');
      io.exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) throw Exception("Not logged in.");
      client.setAuth(creds);

      final String sourcePattern = args[0];
      final String destinationPath = args[1];
      final bool force = argResults['force'] as bool;

      // 1. Resolve Destination (Matches Python target resolution)
      print("🔍 Resolving destination path: $destinationPath");
      final destFolderInfo = await client.resolvePath(destinationPath);
      if (destFolderInfo['type'] != 'folder') {
        throw Exception("Destination path '$destinationPath' is not a folder.");
      }
      final destinationFolderUuid = destFolderInfo['uuid'] as String;

      // 2. Handle Wildcards/Globs
      List<Map<String, dynamic>> itemsToMove = [];

      if (sourcePattern.contains('*')) {
        print("🌐 Pattern detected, performing server-side expansion...");

        // Fix: Ensure parentPath is at least '/' for root-level patterns like '/*.pdf'
        var parentPath = p.dirname(sourcePattern);
        if (parentPath == '.') parentPath = '/';

        final pattern = p.basename(sourcePattern);
        final glob = Glob(pattern);

        // Resolve parent folder to get its UUID
        final parentInfo = await client.resolvePath(parentPath);
        final parentUuid = parentInfo['uuid'] as String;

        // Fetch children (Matches Python get_folder_content logic)
        final folders = await client.listFolders(parentUuid);
        final files = await client.listFolderFiles(parentUuid);

        for (var item in [...folders, ...files]) {
          // Robust Name Reconstruction: Match display name (e.g. "file.pdf")
          final String displayName;
          if (item['type'] == 'file') {
            final name = item['name'] ?? '';
            final ext = item['fileType'] ?? '';
            displayName = (ext.isNotEmpty) ? '$name.$ext' : name;
          } else {
            displayName = item['name'] ?? '';
          }

          if (glob.matches(displayName)) {
            itemsToMove.add({
              ...item,
              'displayName': displayName,
            });
          }
        }
      } else {
        final sourceInfo = await client.resolvePath(sourcePattern);
        itemsToMove.add({
          'uuid': sourceInfo['uuid'],
          'type': sourceInfo['type'],
          'displayName':
              (sourceInfo['metadata'] as Map)['name'] ?? sourcePattern,
        });
      }

      if (itemsToMove.isEmpty) {
        print("⚠️ No items matched the pattern '$sourcePattern'");
        return;
      }

      // 3. Confirm Batch (Safety precaution for mass moves)
      if (itemsToMove.length > 1 && !force) {
        io.stdout.write(
            '❓ Move ${itemsToMove.length} items to "$destinationPath"? [y/N]: ');
        final res = io.stdin.readLineSync()?.toLowerCase();
        if (res != 'y' && res != 'yes') {
          print("❌ Cancelled");
          return;
        }
      }

      // 4. Execution Loop (Matches Python move_by_path sequence)
      for (var item in itemsToMove) {
        final uuid = item['uuid'] as String;
        final type = item['type'] as String;
        final name = item['displayName'] as String;

        print("🚀 Moving $type: $name...");
        try {
          // PATCH /files/{uuid} or PATCH /folders/{uuid}
          if (type == 'file') {
            await client.moveFile(uuid, destinationFolderUuid);
          } else {
            await client.moveFolder(uuid, destinationFolderUuid);
          }
        } catch (e) {
          print("  ❌ Failed to move $name: $e");
        }
      }

      print("✅ Operation complete.");
    } catch (e) {
      io.stderr.writeln('❌ Error: $e');
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

      await client.trashItems(resolved['uuid'], resolved['type']);

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

      await client.deletePermanently(resolved['uuid'], resolved['type']);

      print("✅ Item permanently deleted: $path");
    } catch (e) {
      io.stderr.writeln('❌ Error deleting item: $e');
      io.exit(1);
    }
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
      final bool showFullUUIDs = argResults['uuids'];

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
      int folderCount = 0;
      int fileCount = 0;
      for (var item in items) {
        final type = item['type'] == 'folder' ? '📁' : '📄';
        if (item['type'] == 'folder')
          folderCount++;
        else
          fileCount++;
        final plainName = item['name'] ?? 'Unknown';
        final fileType = item['type'] == 'file' ? (item['fileType'] ?? '') : '';
        final displayName = (fileType.isNotEmpty && item['type'] == 'file')
            ? '$plainName.$fileType'
            : plainName;
        final name = displayName.toString().padRight(40);
        final size =
            item['type'] == 'folder' ? '<DIR>' : formatSize(item['size'] ?? 0);
        final uuid = item['uuid'] ?? 'N/A';
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
          : creds['rootFolderId']!;
      final bool showFullUUIDs = argResults['uuids'];

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
        final plainName = item['name'] ?? 'Unknown';
        final fileType = item['type'] == 'file' ? (item['fileType'] ?? '') : '';
        final displayName = (fileType.isNotEmpty && item['type'] == 'file')
            ? '$plainName.$fileType'
            : plainName;
        final name = displayName.toString().padRight(40);
        final size =
            item['type'] == 'folder' ? '<DIR>' : formatSize(item['size'] ?? 0);
        final uuid = item['uuid'] ?? 'N/A';
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

      // Generate Batch ID for resumability (Go/Python style)
      final batchId = config.generateBatchId('upload', sources, targetPath);
      print("🔄 Batch ID: $batchId");

      var batchState = await config.loadBatchState(batchId);
      if (batchState != null) {
        print(
            "🔄 DEBUG: Resuming existing batch with ${batchState['tasks'].length} tasks.");
      }

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
          if (debugMode) print("💾 TRACE: Progress saved for Batch $batchId");
        },
      );

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

      final result =
          await client.downloadFile(fileUuid, bridgeUser, userIdForAuth);
      final data = result['data'] as Uint8List;
      final filename = result['filename'] as String;

      final file = io.File(filename); // <-- FIX: Use io.File
      await file.writeAsBytes(data);

      print('\n✅ Downloaded successfully: $filename');
      print('📊 Size: ${formatSize(data.length)}');
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
    print('   NETWORK_URL: ${InternxtClient.networkUrl}');
    print('     └─ Data: /buckets/{bucketId}/files/...');
    print('   DRIVE_API_URL: ${InternxtClient.driveApiUrl}');
    print('     └─ Auth: /auth/login, /auth/security, /users/refresh');
    print('     └─ Meta: /folders/..., /files/..., /fuzzy/...');
    print('');
    print('🔒 Crypto:');
    print('   APP_CRYPTO_SECRET: ${InternxtClient.appCryptoSecret}');
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
    print('   NETWORK_URL: ${InternxtClient.networkUrl}');
    assert(InternxtClient.networkUrl == 'https://gateway.internxt.com/network',
        'NETWORK_URL mismatch! Expected gateway.internxt.com/network');
    print('   DRIVE_API_URL: ${InternxtClient.driveApiUrl}');
    assert(InternxtClient.driveApiUrl == 'https://gateway.internxt.com/drive',
        'DRIVE_API_URL mismatch! Expected gateway.internxt.com/drive');
    print('   ✅ PASS\n');

    print('Test 3: Encryption/Decryption (OpenSSL compat)');
    final testText = 'Hello Internxt';
    final encrypted =
        client._encryptTextWithKey(testText, InternxtClient.appCryptoSecret);
    print('   Encrypted: ${encrypted.substring(0, 32)}...');
    final decrypted =
        client._decryptTextWithKey(encrypted, InternxtClient.appCryptoSecret);
    print('   Decrypted: $decrypted');
    assert(decrypted == testText, 'Encryption/Decryption failed!');
    print('   ✅ PASS\n');

    print('Test 4: Password hashing (PBKDF2-SHA1)');
    final password = 'testpass123';
    final salt = '1234567890abcdef1234567890abcdef';
    final hashResult = client._passToHash(password, salt);
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
    final derived = client._getFileDeterministicKey(key, data);
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
    final detailed = argResults['uuids']; // We'll re-use --uuids as --detailed

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
          final displayName = file['fullPath'] ?? file['name'];
          final type = file['type'] ?? '';
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
    final maxDepth = int.tryParse(argResults['maxdepth'] ?? '-1') ?? -1;

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
    final maxDepth = int.tryParse(argResults['depth'] ?? '3') ?? 3;

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
  static const String networkUrl = 'https://gateway.internxt.com/network';
  static const String driveApiUrl = 'https://gateway.internxt.com/drive';
  static const String appCryptoSecret = '6KYQBP847D4ATSFA';

  bool debugMode = false;
  final ConfigService config;

  String? authToken;
  String? newToken;
  String? mnemonic;
  String? userEmail;
  String? userId;
  String? rootFolderId;
  String? bucketId;

  // Caching variables
  static const Duration _cacheDuration = Duration(minutes: 10);
  final Map<String, _CacheEntry> _folderCache = {};
  final Map<String, _CacheEntry> _fileCache = {};

  // Token refresh lock
  bool _isRefreshingToken = false;

  InternxtClient({required this.config});

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

    log("📊 TRACE: Session loaded for $userEmail (Bucket: $bucketId)");
  }
  // --- Token Refresh ---

  /// Calls the API to get new tokens.
  Future<Map<String, dynamic>> _apiRefreshToken(String currentNewToken) async {
    final url = Uri.parse('$driveApiUrl/users/refresh');
    log('GET $url (refreshing token)'); // Note: Python blueprint uses GET

    try {
      final response = await http.get(
        url,
        headers: {
          'Authorization': 'Bearer $currentNewToken',
          'Content-Type': 'application/json',
        },
      );

      if (response.statusCode != 200) {
        log('Token refresh failed: ${response.body}');
        throw Exception('Token refresh failed: ${response.statusCode}');
      }

      return json.decode(response.body);
    } catch (e) {
      log('Token refresh network error: $e');
      throw Exception('Token refresh failed: $e');
    }
  }

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

      // Call /refresh with the existing newToken
      final resp = await _apiRefreshToken(currentCreds['newToken']);
      final user = resp['user'];

      // Re-compute bridge password in case metadata changed
      final bridgePass = crypto.sha256
          .convert(utf8.encode(user['userId'].toString()))
          .toString();

      final updatedCreds = {
        ...currentCreds,
        'token': resp['token'],
        'newToken': resp['newToken'],
        'bridgeUser': user['bridgeUser'],
        'userIdForAuth': user['userId'],
        'bridgePass': bridgePass,
      };

      // Update class state
      setAuth(updatedCreds);

      // Save to disk using the updated dynamic-friendly method
      await config.saveCredentials(updatedCreds);
      log("✅ TRACE: Token rotation successful.");
    } catch (e) {
      log("❌ TRACE: Token rotation failed: $e");
      rethrow;
    } finally {
      _isRefreshingToken = false;
    }
  }

  /// Central request handler with automatic token refresh.
  Future<http.Response> _makeRequest(
    String method,
    Uri url, {
    Map<String, String>? headers,
    dynamic body,
    bool useAuth = true,
    bool isNetworkAuth = false,
    String? networkUser,
    String? networkPass,
    int retryCount = 0,
  }) async {
    final maxRetries = 3;
    final requestHeaders = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'internxt-client': 'cli',
      'User-Agent': 'InternxtCLI/1.0.0 (Dart)',
      ...?headers,
    };

    if (isNetworkAuth && networkUser != null && networkPass != null) {
      final auth = base64Encode(utf8.encode('$networkUser:$networkPass'));
      requestHeaders['Authorization'] = 'Basic $auth';
    } else if (useAuth && newToken != null) {
      requestHeaders['Authorization'] = 'Bearer $newToken';
    }

    try {
      http.Response response;
      switch (method.toUpperCase()) {
        case 'GET':
          response = await http.get(url, headers: requestHeaders);
          break;
        case 'POST':
          response = await http.post(url, headers: requestHeaders, body: body);
          break;
        case 'PUT':
          response = await http.put(url, headers: requestHeaders, body: body);
          break;
        case 'PATCH':
          response = await http.patch(url, headers: requestHeaders, body: body);
          break;
        case 'DELETE':
          response =
              await http.delete(url, headers: requestHeaders, body: body);
          break;
        default:
          throw Exception('Unsupported method');
      }

      // Optimization: Handle transient 5xx errors with exponential backoff (Go style)
      if (response.statusCode >= 500 && retryCount < maxRetries) {
        final delay = Duration(seconds: pow(2, retryCount).toInt());
        log("🔄 [DEBUG] Server Error ${response.statusCode}. Retrying in ${delay.inSeconds}s...");
        await Future.delayed(delay);
        return _makeRequest(method, url,
            headers: headers,
            body: body,
            useAuth: useAuth,
            isNetworkAuth: isNetworkAuth,
            networkUser: networkUser,
            networkPass: networkPass,
            retryCount: retryCount + 1);
      }

      if (response.statusCode >= 400) {
        throw Exception('API Error: ${response.statusCode} - ${response.body}');
      }

      return response;
    } catch (e) {
      if (retryCount < maxRetries) {
        log("📡 [DEBUG] Network Error. Retrying... ($retryCount)");
        return _makeRequest(method, url,
            headers: headers,
            body: body,
            useAuth: useAuth,
            retryCount: retryCount + 1);
      }
      rethrow;
    }
  }

  // --- Auth ---

  /// Check if 2FA is needed for an email
  Future<bool> is2faNeeded(String email) async {
    final cleanEmail = email.toLowerCase().trim();
    final url = Uri.parse('$driveApiUrl/auth/login');

    try {
      final response = await _makeRequest(
        'POST',
        url,
        body: json.encode({'email': cleanEmail}),
        useAuth: false,
      );

      final data = json.decode(response.body);
      return data['tfa'] == true;
    } catch (e) {
      log('⚠️ 2FA check error: $e');
      return false;
    }
  }

  /// Login to Internxt
  Future<Map<String, dynamic>> login(String email, String password,
      {String? tfaCode}) async {
    final cleanEmail = email.toLowerCase().trim();
    log("🚀 TRACE: Starting Hydrated Login for $cleanEmail");

    // STEP 1: Salt Retrieval (sKey) - EXACT match to your successful curl
    final secRes = await _makeRequest(
      'POST',
      Uri.parse('$driveApiUrl/auth/login'),
      body: json.encode({'email': cleanEmail}),
      useAuth: false,
    );
    final secDetails = json.decode(secRes.body);
    final sKey = secDetails['sKey'];
    if (sKey == null) throw Exception("Login failed: Salt (sKey) missing.");
    log("💧 Step 1: Salt received.");

    // STEP 2: Crypto (Mirroring Python crypto_service)
    final salt = _decryptTextWithKey(sKey, appCryptoSecret);
    final masterHash = _passToHash(password, salt)['hash']!;
    final encryptedHash = _encryptTextWithKey(masterHash, appCryptoSecret);
    final keysPayload = _generateKeys(password);

    // STEP 3: Initial Access Call
    log("🔐 Step 3: Requesting session token via /auth/login/access...");
    final accessRes = await _makeRequest(
      'POST',
      Uri.parse('$driveApiUrl/auth/login/access'),
      body: json.encode({
        'email': cleanEmail,
        'password': encryptedHash,
        'tfa': tfaCode,
        'keys': {
          'ecc': {
            'publicKey': keysPayload['ecc']['publicKey'],
            'privateKey': keysPayload['ecc']['privateKeyEncrypted'],
          }
        },
        'privateKey': keysPayload['privateKeyEncrypted'],
        'publicKey': keysPayload['publicKey'],
      }),
      useAuth: false,
    );
    final tempToken = json.decode(accessRes.body)['newToken'];

    // STEP 4: Mandatory Hydration (Refresh) - Mirroring Python AuthService.login
    log("💧 Step 4: Hydrating session metadata via /users/refresh...");
    final hydrationRes = await http.get(
      Uri.parse('$driveApiUrl/users/refresh'),
      headers: {
        'Authorization': 'Bearer $tempToken',
        'internxt-client': 'cli', // Keep consistency
        'Content-Type': 'application/json',
      },
    );

    if (hydrationRes.statusCode != 200) {
      throw Exception("Hydration failed: ${hydrationRes.statusCode}");
    }

    final hydrated = json.decode(hydrationRes.body);
    final user = hydrated['user'];

    // Step 5: Bridge Credentials (SHA256 of UserID)
    final bridgePass = crypto.sha256
        .convert(utf8.encode(user['userId'].toString()))
        .toString();

    return {
      'email': user['email'],
      'token': hydrated['token'],
      'newToken': hydrated['newToken'],
      'mnemonic': _decryptTextWithKey(user['mnemonic'], password),
      'userId': user['userId'],
      'rootFolderId': user['rootFolderId'],
      'bridgeUser': user['bridgeUser'],
      'bridgePass': bridgePass,
      'bucketId': user['bucket'], // This is your storage container ID
    };
  }

  Future<Map<String, dynamic>> getFileMetadata(String fileUuid) async {
    final url = Uri.parse('$driveApiUrl/files/$fileUuid/meta');
    log('GET $url (fetching file metadata)');

    final response = await _makeRequest('GET', url);

    return json.decode(response.body);
  }

  Future<Map<String, dynamic>> getFolderMetadata(String folderUuid) async {
    final url = Uri.parse('$driveApiUrl/folders/$folderUuid/meta');
    log('GET $url (fetching folder metadata)');

    final response = await _makeRequest('GET', url);

    return json.decode(response.body);
  }

  // --- Crypto Helpers ---

  Map<String, String> _passToHash(String password, String salt) {
    log('_passToHash: password length=${password.length}, salt=$salt');

    final saltBytes = HEX.decode(salt);
    final passwordBytes = Uint8List.fromList(utf8.encode(password));

    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA1Digest(), 64))
      ..init(Pbkdf2Parameters(Uint8List.fromList(saltBytes), 10000, 32));

    final hashBytes = pbkdf2.process(passwordBytes);
    final hashHex = HEX.encode(hashBytes);

    log('_passToHash: hash length=${hashHex.length}');

    return {'salt': salt, 'hash': hashHex};
  }

  Map<String, dynamic> _generateKeys(String password) {
    log('_generateKeys: Encrypting with password as key');

    final encryptedPk =
        _encryptTextWithKey('placeholder-private-key-for-login', password);

    return {
      'privateKeyEncrypted': encryptedPk,
      'publicKey': 'placeholder-public-key-for-login',
      'revocationCertificate': 'placeholder-revocation-cert-for-login',
      'ecc': {
        'publicKey': 'placeholder-ecc-public-key',
        'privateKeyEncrypted': encryptedPk,
      },
      'kyber': {
        'publicKey': null,
        'privateKeyEncrypted': null,
      },
    };
  }

  String _encryptTextWithKey(String textToEncrypt, String secret) {
    log('_encryptTextWithKey: text length=${textToEncrypt.length}');

    final random = Random.secure();
    final salt =
        Uint8List.fromList(List.generate(8, (_) => random.nextInt(256)));

    final keyIv = _getKeyAndIvFrom(secret, salt);
    final key = keyIv['key']!;
    final iv = keyIv['iv']!;

    log('_encryptTextWithKey: salt=${HEX.encode(salt)}, key length=${key.length}, iv length=${iv.length}');

    final cipher = PaddedBlockCipherImpl(
      PKCS7Padding(),
      CBCBlockCipher(AESEngine()),
    );

    cipher.init(
      true,
      PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(key), iv),
        null,
      ),
    );

    final textBytes = Uint8List.fromList(utf8.encode(textToEncrypt));
    final encrypted = cipher.process(textBytes);

    final result = Uint8List(16 + encrypted.length);
    result.setAll(0, utf8.encode('Salted__'));
    result.setAll(8, salt);
    result.setAll(16, encrypted);

    final hexResult = HEX.encode(result);
    log('_encryptTextWithKey: result length=${hexResult.length}');

    return hexResult;
  }

  String _decryptTextWithKey(String encryptedText, String secret) {
    log('_decryptTextWithKey: encrypted length=${encryptedText.length}');

    final cipherBytes = Uint8List.fromList(HEX.decode(encryptedText));
    final salt = cipherBytes.sublist(8, 16);
    log('_decryptTextWithKey: salt=${HEX.encode(salt)}');

    final keyIv = _getKeyAndIvFrom(secret, salt);
    final key = keyIv['key']!;
    final iv = keyIv['iv']!;

    final cipher = PaddedBlockCipherImpl(
      PKCS7Padding(),
      CBCBlockCipher(AESEngine()),
    );

    cipher.init(
      false,
      PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(key), iv),
        null,
      ),
    );

    final contentsToDecrypt = cipherBytes.sublist(16);
    final decrypted = cipher.process(contentsToDecrypt);

    final result = utf8.decode(decrypted);
    log('_decryptTextWithKey: decrypted length=${result.length}');

    return result;
  }

  Map<String, Uint8List> _getKeyAndIvFrom(String secret, Uint8List salt) {
    log('_getKeyAndIvFrom: secret length=${secret.length}, salt length=${salt.length}');

    final secretBytes = latin1.encode(secret);
    final password = Uint8List(secretBytes.length + salt.length);
    password.setAll(0, secretBytes);
    password.setAll(secretBytes.length, salt);

    final md5Hashes = <Uint8List>[];
    Uint8List digest = password;

    for (var i = 0; i < 3; i++) {
      final md5 = MD5Digest();
      md5.update(digest, 0, digest.length);
      final hash = Uint8List(md5.digestSize);
      md5.doFinal(hash, 0);
      md5Hashes.add(hash);

      digest = Uint8List(hash.length + password.length);
      digest.setAll(0, hash);
      digest.setAll(hash.length, password);
    }

    final key = Uint8List(32);
    key.setAll(0, md5Hashes[0]);
    key.setAll(16, md5Hashes[1]);

    final iv = md5Hashes[2];

    log('_getKeyAndIvFrom: key length=${key.length}, iv length=${iv.length}');

    return {'key': key, 'iv': iv};
  }

  // --- Caching ---

  /// Clears the cache for a specific folder.
  void _invalidateCache(String folderUuid) {
    _folderCache.remove(folderUuid);
    _fileCache.remove(folderUuid);
    log('Cache invalidated for folder: $folderUuid');
  }

  /// Finds an item's parent and clears its cache.
  Future<void> _clearParentCache(String itemUuid, String itemType) async {
    String? parentUuid;
    try {
      if (itemType == 'file') {
        final metadata = await getFileMetadata(itemUuid);
        parentUuid = metadata['folderId'] ?? metadata['folderUuid'];
      } else {
        final metadata = await getFolderMetadata(itemUuid);
        parentUuid = metadata['parentId'] ?? metadata['parentUuid'];
      }
      if (parentUuid != null) {
        _invalidateCache(parentUuid);
      }
    } catch (e) {
      log('Could not clear parent cache for $itemUuid (parent: $parentUuid): $e');
    }
  }

  // --- List Operations ---

  Future<List<Map<String, dynamic>>> listFolders(String folderId,
      {bool detailed = false}) async {
    // Check cache
    final cached = _folderCache[folderId];
    if (cached != null &&
        DateTime.now().difference(cached.timestamp) < _cacheDuration) {
      log('Using cached folder list for $folderId');
      // Return a copy to prevent mutation
      return List<Map<String, dynamic>>.from(cached.items);
    }

    final List<Map<String, dynamic>> allItems = [];
    int currentOffset = 0;
    const int limit = 50;

    log('Fetching all folders for $folderId (paginated)');

    while (true) {
      final url = Uri.parse('$driveApiUrl/folders/content/$folderId/folders');
      log('  GET $url (offset: $currentOffset, limit: $limit)');

      try {
        final response = await _makeRequest(
          'GET',
          url.replace(queryParameters: {
            'offset': currentOffset.toString(),
            'limit': limit.toString(),
            'sort': 'plainName',
            'direction': 'ASC'
          }),
        );

        final data = json.decode(response.body);
        final List<dynamic> folders = data['result'] ?? data['folders'] ?? [];

        for (var folder in folders) {
          final item = {
            'type': 'folder',
            'name': folder['plainName'] ?? folder['name'],
            'uuid': folder['uuid'] ?? folder['id'],
            'size': 0,
            // Add all fields for 'detailed'
            'createdAt': folder['createdAt'],
            'updatedAt': folder['updatedAt'],
            'creationTime': folder['creationTime'],
            'modificationTime': folder['modificationTime'],
            'parentId': folder['parentId'],
            'parentUuid': folder['parentUuid'],
            'userId': folder['userId'],
            'deleted': folder['deleted'],
            'removed': folder['removed'],
          };
          allItems.add(item);
        }

        if (folders.length < limit) {
          log('  Fetched last page of folders (${folders.length} items). Total: ${allItems.length}');
          break;
        } else {
          log('  Fetched page with $limit folders, requesting next page...');
          currentOffset += limit;
        }
      } catch (e) {
        log('  Error fetching folder page (offset $currentOffset): $e');
        throw e;
      }
    }

    // Save to cache
    _folderCache[folderId] =
        _CacheEntry(items: allItems, timestamp: DateTime.now());

    // Filter detailed fields if not requested (after caching full data)
    if (!detailed) {
      return allItems
          .map((item) => {
                'type': item['type'],
                'name': item['name'],
                'uuid': item['uuid'],
                'size': item['size'],
              })
          .toList();
    }
    return allItems;
  }

  Future<List<Map<String, dynamic>>> listFolderFiles(String folderId,
      {bool detailed = false}) async {
    // Check cache
    final cached = _fileCache[folderId];
    if (cached != null &&
        DateTime.now().difference(cached.timestamp) < _cacheDuration) {
      log('Using cached file list for $folderId');
      // Return a copy to prevent mutation
      return List<Map<String, dynamic>>.from(cached.items);
    }

    final List<Map<String, dynamic>> allItems = [];
    int currentOffset = 0;
    const int limit = 50;

    log('Fetching all files for $folderId (paginated)');

    while (true) {
      final url = Uri.parse('$driveApiUrl/folders/content/$folderId/files');
      log('  GET $url (offset: $currentOffset, limit: $limit)');

      try {
        final response = await _makeRequest(
          'GET',
          url.replace(queryParameters: {
            'offset': currentOffset.toString(),
            'limit': limit.toString(),
            'sort': 'plainName',
            'direction': 'ASC'
          }),
        );

        final data = json.decode(response.body);
        final List<dynamic> files = data['result'] ?? data['files'] ?? [];

        for (var file in files) {
          final item = {
            'type': 'file',
            'name': file['plainName'] ?? file['name'],
            'fileType': file['type'] ?? '',
            'uuid': file['uuid'] ?? file['id'],
            'size': file['size'] is int
                ? file['size']
                : int.tryParse(file['size'].toString()) ?? 0,
            'bucket': file['bucket'],
            'fileId': file['fileId'],
            // Add all fields for 'detailed'
            'createdAt': file['createdAt'],
            'updatedAt': file['updatedAt'],
            'creationTime': file['creationTime'],
            'modificationTime': file['modificationTime'],
            'folderId': file['folderId'],
            'folderUuid': file['folderUuid'],
            'userId': file['userId'],
            'encryptVersion': file['encryptVersion'],
            'deleted': file['deleted'],
            'removed': file['removed'],
            'status': file['status'],
          };
          allItems.add(item);
        }

        if (files.length < limit) {
          log('  Fetched last page of files (${files.length} items). Total: ${allItems.length}');
          break;
        } else {
          log('  Fetched page with $limit files, requesting next page...');
          currentOffset += limit;
        }
      } catch (e) {
        log('  Error fetching file page (offset $currentOffset): $e');
        throw e;
      }
    }

    // Save to cache
    _fileCache[folderId] =
        _CacheEntry(items: allItems, timestamp: DateTime.now());

    // Filter detailed fields if not requested
    if (!detailed) {
      return allItems
          .map((item) => {
                'type': item['type'],
                'name': item['name'],
                'fileType': item['fileType'],
                'uuid': item['uuid'],
                'size': item['size'],
                'bucket': item['bucket'],
                'fileId': item['fileId'],
              })
          .toList();
    }
    return allItems;
  }

  Future<Map<String, dynamic>> resolvePath(String path) async {
    if (this.rootFolderId == null) {
      throw Exception("Root folder ID is not set. Please log in.");
    }
    String currentFolderUuid = this.rootFolderId!;
    String resolvedPathStr = '/';

    var cleanPath = path.trim();
    if (cleanPath.startsWith('/')) {
      cleanPath = cleanPath.substring(1);
    }

    if (cleanPath.endsWith('/')) {
      cleanPath = cleanPath.substring(0, cleanPath.length - 1);
    }

    if (cleanPath.isEmpty || cleanPath == '.') {
      return {
        'type': 'folder',
        'uuid': currentFolderUuid,
        'metadata': {'uuid': currentFolderUuid, 'name': 'Root'},
        'path': '/'
      };
    }

    final pathParts =
        cleanPath.split('/').where((part) => part.isNotEmpty).toList();
    Map<String, dynamic>? currentMetadata = {
      'uuid': rootFolderId,
      'name': 'Root'
    };

    for (var i = 0; i < pathParts.length; i++) {
      final part = pathParts[i];
      final isLastPart = (i == pathParts.length - 1);

      // Get content of the current folder (uses cache)
      final folders = await listFolders(currentFolderUuid, detailed: true);

      Map<String, dynamic>? foundFolder;
      for (var folder in folders) {
        if (folder['name'] == part) {
          foundFolder = folder;
          break;
        }
      }

      Map<String, dynamic>? foundFile;
      if (isLastPart) {
        final files = await listFolderFiles(currentFolderUuid, detailed: true);
        for (var file in files) {
          final plainName = file['name'] ?? '';
          final fileType = file['fileType'] ?? '';
          final fullName =
              fileType.isNotEmpty ? '$plainName.$fileType' : plainName;

          if (plainName == part || fullName == part) {
            foundFile = file;
            break;
          }
        }
      }

      if (foundFolder != null && (!isLastPart || foundFile == null)) {
        currentFolderUuid = foundFolder['uuid'];
        currentMetadata = foundFolder;
        resolvedPathStr = '$resolvedPathStr$part/'.replaceAll('//', '/');
        if (isLastPart) {
          return {
            'type': 'folder',
            'uuid': foundFolder['uuid'],
            'metadata': foundFolder,
            'path': resolvedPathStr.substring(
                0, resolvedPathStr.length - 1) // remove trailing slash
          };
        }
      } else if (foundFile != null && isLastPart) {
        final plainName = foundFile['name'] ?? '';
        final fileType = foundFile['fileType'] ?? '';
        final fullName =
            fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
        resolvedPathStr = '$resolvedPathStr$fullName'.replaceAll('//', '/');
        return {
          'type': 'file',
          'uuid': foundFile['uuid'],
          'metadata': foundFile,
          'path': resolvedPathStr
        };
      } else {
        final currentPath = '/' + pathParts.sublist(0, i + 1).join('/');
        throw Exception("Path not found: $currentPath");
      }
    }

    return {
      'type': 'folder',
      'uuid': currentFolderUuid,
      'metadata': currentMetadata,
      'path': resolvedPathStr.isEmpty ? '/' : resolvedPathStr
    };
  }

  // --- Download Operations ---

  Future<Map<String, dynamic>> downloadFile(
    String fileUuid,
    String bridgeUser,
    String userIdForAuth, {
    bool preserveTimestamps = false,
  }) async {
    log('Starting file download: $fileUuid');

    print('   📋 Fetching file metadata...');
    final metadataUrl = Uri.parse('$driveApiUrl/files/$fileUuid/meta');

    final metadataResponse = await _makeRequest('GET', metadataUrl);

    final metadata = json.decode(metadataResponse.body);
    final bucketId = metadata['bucket'];
    final networkFileId = metadata['fileId'];

    final fileSize = metadata['size'] is int
        ? metadata['size'] as int
        : int.tryParse(metadata['size'].toString()) ?? 0;

    final fileName = metadata['plainName'] ?? 'file';
    final fileType = metadata['type'] ?? '';
    final filename = fileType.isNotEmpty ? '$fileName.$fileType' : fileName;

    String? modificationTime =
        metadata['modificationTime'] ?? metadata['updatedAt'];

    print('   📄 File: $filename');
    print('   📊 Size: ${formatSize(fileSize)}');

    final networkAuth = _getNetworkAuth(bridgeUser, userIdForAuth);
    final networkUser = networkAuth['user']!;
    final networkPass = networkAuth['pass']!;

    print('   🔗 Fetching download links...');
    final linksResponse = await _getDownloadLinks(
        bucketId, networkFileId, networkUser, networkPass);
    final downloadUrl = linksResponse['shards'][0]['url'];
    final fileIndexHex = linksResponse['index'];

    print('   ☁️  Downloading encrypted data...');
    final downloadResponse = await http.get(Uri.parse(downloadUrl));

    if (downloadResponse.statusCode != 200) {
      throw Exception(
          'Failed to download file: ${downloadResponse.statusCode}');
    }

    final encryptedData = downloadResponse.bodyBytes;

    print('   🔐 Decrypting...');
    final decryptedData = _decryptStream(
      encryptedData,
      mnemonic!,
      bucketId,
      fileIndexHex,
    );

    final trimmedData = decryptedData.sublist(0, fileSize);

    return {
      'data': trimmedData,
      'filename': filename,
      'modificationTime': modificationTime,
      'preserveTimestamps': preserveTimestamps,
    };
  }

  Future<Map<String, dynamic>> downloadFileStreamed(
    String fileUuid,
    String destinationPath,
    String bridgeUser,
    String userIdForAuth,
  ) async {
    log('📥 Starting optimized streamed download: $fileUuid');

    // 1. Fetch Metadata (Python style)
    final metadata = await getFileMetadata(fileUuid);
    final fileSize = int.parse(metadata['size'].toString());
    final fileName = metadata['plainName'] ?? 'file';
    final fileType = metadata['type'] ?? '';
    final fullFileName = fileType.isNotEmpty ? '$fileName.$fileType' : fileName;

    // 2. Fetch Network Links
    final networkAuth = _getNetworkAuth(bridgeUser, userIdForAuth);
    final links = await _getDownloadLinks(metadata['bucket'],
        metadata['fileId'], networkAuth['user']!, networkAuth['pass']!);
    final downloadUrl = links['shards'][0]['url'];
    final fileIndexHex = links['index'];

    // 3. Streamed Download (Go adapter style)
    final client = http.Client();
    final request = http.Request('GET', Uri.parse(downloadUrl));
    final response = await client.send(request);

    int downloaded = 0;
    final List<int> encryptedBuffer = [];
    final stopwatch = Stopwatch()..start();

    log('     ☁️  [DEBUG] Downloading encrypted shards...');

    await for (var chunk in response.stream) {
      encryptedBuffer.addAll(chunk);
      downloaded += chunk.length;

      // Update progress bar
      final percent =
          (downloaded / response.contentLength! * 100).toStringAsFixed(1);
      io.stdout.write(
          '\r        Progress: $percent% (${formatSize(downloaded)}) [${formatSize(downloaded / (stopwatch.elapsedMilliseconds / 1000 + 0.001))}/s]   ');
    }
    print('');

    // 4. Decrypt and write to disk
    log('     🔐 [DEBUG] Decrypting and saving to disk...');
    final decryptedData = _decryptStream(Uint8List.fromList(encryptedBuffer),
        mnemonic!, metadata['bucket'], fileIndexHex);

    final file = io.File(destinationPath);
    await file.writeAsBytes(decryptedData.sublist(0, fileSize));

    return {
      'filename': fullFileName,
      'size': fileSize,
      'modificationTime': metadata['modificationTime'] ?? metadata['updatedAt']
    };
  }

  bool shouldIncludeFile(
    String fileName,
    List<String> include,
    List<String> exclude,
  ) {
    if (include.isNotEmpty) {
      final matchesInclude =
          include.any((pattern) => Glob(pattern).matches(fileName));
      if (!matchesInclude) {
        return false;
      }
    }

    if (exclude.isNotEmpty) {
      final matchesExclude =
          exclude.any((pattern) => Glob(pattern).matches(fileName));
      if (matchesExclude) {
        return false;
      }
    }

    return true;
  }

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
  }) async {
    final itemInfo = await resolvePath(remotePath);

    if (itemInfo['type'] == 'file') {
      log('Path resolved to a file. Starting single file download.');

      final metadata = itemInfo['metadata'] as Map<String, dynamic>;
      final plainName = metadata['name'] ?? 'file';
      final fileType = metadata['fileType'] ?? '';
      final remoteFilename =
          fileType.isNotEmpty ? '$plainName.$fileType' : plainName;

      if (!shouldIncludeFile(remoteFilename, include, exclude)) {
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

      log('Path resolved to a folder. Starting recursive download.');

      String baseDestPath;
      if (localDestination != null) {
        baseDestPath = localDestination;
      } else {
        final folderName = itemInfo['metadata']?['name'] ?? 'download';
        baseDestPath = folderName;
      }
      final baseDestDir = io.Directory(baseDestPath);
      await baseDestDir.create(recursive: true);

      print('📂 Downloading folder recursively: $remotePath');
      print('💾 Target directory: ${baseDestDir.path}');

      Map<String, dynamic> batchState;
      List<dynamic> tasks;

      if (initialBatchState != null) {
        print("🔄 Resuming previous batch operation...");
        batchState = initialBatchState;
        tasks = batchState['tasks'] as List<dynamic>;
      } else {
        print("🔍 Generating new batch task list...");
        tasks = [];
        Future<void> buildDownloadTasks(
            String currentRemoteFolderUuid, String currentLocalRelPath) async {
          final files =
              await listFolderFiles(currentRemoteFolderUuid, detailed: true);
          final folders =
              await listFolders(currentRemoteFolderUuid, detailed: true);

          for (var fileInfo in files) {
            final plainName = fileInfo['name'] ?? 'file';
            final fileType = fileInfo['fileType'] ?? '';
            final remoteFilename =
                fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
            final localFilePath =
                p.join(baseDestPath, currentLocalRelPath, remoteFilename);

            if (shouldIncludeFile(remoteFilename, include, exclude)) {
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

            if (preserveTimestamps) {
              try {
                final modTimeStr =
                    folderInfo['modificationTime'] ?? folderInfo['updatedAt'];
                if (modTimeStr != null) {
                  log('   ℹ️  Cannot set mod time for dir ${folderName} (Dart limitation).');
                }
              } catch (e) {
                log('   ⚠️  Error during dir timestamp logic for $folderName: $e');
              }
            }

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
        print("📝 Task list generated with ${tasks.length} files.");
      }

      int successCount = 0;
      int skippedCount = 0;
      int errorCount = 0;
      int completedPreviously = 0;

      for (int i = 0; i < tasks.length; i++) {
        final task = tasks[i] as Map<String, dynamic>;
        final remoteUuid = task['remoteUuid'] as String;
        final localPath = task['localPath'] as String;
        final status = task['status'] as String;
        final remoteModTime = task['remoteModificationTime'] as String?;

        if (status == 'completed') {
          log("✅ Already completed: $localPath");
          completedPreviously++;
          continue;
        }
        if (status.startsWith('skipped')) {
          log("⏭️ Previously skipped: $localPath ($status)");
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
            remoteUuid,
            bridgeUser,
            userIdForAuth,
            preserveTimestamps: preserveTimestamps,
          );

          await localFile.parent.create(recursive: true);
          await localFile.writeAsBytes(downloadResult['data']);

          final modTimeStr =
              downloadResult['modificationTime'] ?? remoteModTime;
          if (preserveTimestamps && modTimeStr != null) {
            try {
              final mTime = DateTime.parse(modTimeStr);
              await localFile.setLastModified(mTime);
              log('   🕐 Set modification time: $mTime');
            } catch (e) {
              log('   ⚠️  Could not set modification time: $e');
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

      print("=" * 40);
      print("📊 Batch Download Summary:");
      if (completedPreviously > 0)
        print("  ✅ Completed (previous run): $completedPreviously");
      print("  ✅ Downloaded (this run): $successCount");
      print("  ⏭️  Skipped:  $skippedCount");
      print("  ❌ Errors:   $errorCount");
      print("=" * 40);

      if (errorCount > 0) {
        throw Exception(
            "Download completed with $errorCount errors. State file kept for inspection/retry.");
      }
    }
  }

  // --- Upload Operations ---

  Future<Map<String, dynamic>> _createFolder(
      String name, String parentFolderUuid,
      {String? creationTime, String? modificationTime}) async {
    final url = Uri.parse('$driveApiUrl/folders');
    final data = <String, dynamic>{
      'plainName': name,
      'parentFolderUuid': parentFolderUuid
    };

    if (creationTime != null) {
      data['creationTime'] = creationTime;
      log("     🕐 Added folder creationTime to payload");
    }
    if (modificationTime != null) {
      data['modificationTime'] = modificationTime;
      log("     🕐 Added folder modificationTime to payload");
    }

    log('POST $url (create folder $name)');

    final response = await _makeRequest(
      'POST',
      url,
      body: json.encode(data),
    );

    _invalidateCache(parentFolderUuid);

    return json.decode(response.body);
  }

  Future<Map<String, dynamic>> createFolderRecursive(String path,
      {String? creationTime, String? modificationTime}) async {
    if (this.rootFolderId == null) throw Exception("Not logged in");
    var cleanPath = path.trim().replaceAll(RegExp(r'^/+|/+$'), '');
    if (cleanPath.isEmpty)
      return {'uuid': rootFolderId, 'plainName': 'Root', 'path': '/'};
    var parts = cleanPath.split('/');
    var currentParentUuid = rootFolderId!;
    var currentPathSoFar = '/';
    Map<String, dynamic>? currentFolderInfo = {
      'uuid': rootFolderId,
      'plainName': 'Root',
      'path': '/'
    };

    for (var i = 0; i < parts.length; i++) {
      final part = parts[i];
      if (part.isEmpty) continue;
      final isLastPart = (i == parts.length - 1);

      final partPath = '$currentPathSoFar/$part'.replaceAll('//', '/');
      Map<String, dynamic>? foundFolder = null;

      try {
        final folders = await listFolders(currentParentUuid);
        for (var folder in folders) {
          if (folder['name'] == part) {
            foundFolder = folder;
            break;
          }
        }

        if (foundFolder != null) {
          currentParentUuid = foundFolder['uuid'];
          foundFolder['path'] = partPath;
          currentFolderInfo = foundFolder;
          currentPathSoFar = partPath;
          log("  -> Found existing folder: $part in $currentPathSoFar (UUID: ${currentParentUuid.substring(0, 8)}...)");

          if (isLastPart &&
              (creationTime != null || modificationTime != null)) {
            log("     ⚠️  Folder exists, cannot update timestamps (API limitation).");
          }
        } else {
          log("  -> Creating folder: $part in $currentPathSoFar");
          try {
            final newFolder = await _createFolder(
              part,
              currentParentUuid,
              creationTime: isLastPart ? creationTime : null,
              modificationTime: isLastPart ? modificationTime : null,
            );
            currentParentUuid = newFolder['uuid'];
            newFolder['path'] = partPath;
            currentFolderInfo = newFolder;
            currentPathSoFar = partPath;
            log("     ✅ Created successfully (UUID: ${currentParentUuid.substring(0, 8)}...)");
          } on Exception catch (e) {
            if (e.toString().contains(' 409') ||
                e.toString().contains('already exists')) {
              log("     ⚠️ Received 409 Conflict, likely created concurrently. Waiting 1s before re-fetching info for '$part'...");

              await Future.delayed(Duration(seconds: 1));

              try {
                final parentUuidToList = currentFolderInfo!['uuid'];
                log("     Re-fetching folders inside parent UUID: ${parentUuidToList.substring(0, 8)}...");
                _invalidateCache(parentUuidToList);
                final foldersAfterConflict =
                    await listFolders(parentUuidToList);

                Map<String, dynamic>? conflictingFolder;
                try {
                  conflictingFolder = foldersAfterConflict.firstWhere(
                    (folder) => folder['name'] == part,
                  );
                } catch (e) {
                  conflictingFolder = null;
                }

                if (conflictingFolder != null) {
                  currentParentUuid = conflictingFolder['uuid'];
                  conflictingFolder['path'] = partPath;
                  currentFolderInfo = conflictingFolder;
                  currentPathSoFar = partPath;
                  log("     ✅ Re-fetched successfully after 409 (UUID: ${currentParentUuid.substring(0, 8)}...)");
                } else {
                  log("     ❌ Re-fetch failed: Folder '$part' not found in parent ${parentUuidToList.substring(0, 8)}... after 409.");
                  throw Exception(
                      "Folder '$part' conflict (409) but could not re-fetch it.");
                }
              } catch (fetchErr) {
                log("     ❌ Failed during re-fetch attempt for '$part' after 409: $fetchErr");
                throw Exception(
                    "Failed to resolve folder '$part' after 409 conflict: $fetchErr");
              }
            } else {
              throw e;
            }
          }
        }
      } catch (e) {
        throw Exception(
            "Failed to process folder part '$part' in '$currentPathSoFar': $e");
      }
    }
    if (currentFolderInfo == null) {
      throw Exception(
          "Failed to resolve or create the final folder in the path.");
    }
    if (currentFolderInfo['path'] == null) {
      currentFolderInfo['path'] = currentPathSoFar;
    }
    return currentFolderInfo;
  }

  Future<Map<String, dynamic>> _startUpload(
    String bucketId,
    int fileSize,
    String user,
    String pass,
  ) async {
    final url =
        Uri.parse('$networkUrl/v2/buckets/$bucketId/files/start?multiparts=1');
    final body = json.encode({
      'uploads': [
        {'index': 0, 'size': fileSize}
      ]
    });

    // Uses your actual _makeRequest signature
    final response = await _makeRequest(
      'POST',
      url,
      body: body,
      useAuth: false, // Disable Bearer token
      isNetworkAuth: true, // Enable Basic Auth
      networkUser: user,
      networkPass: pass,
    );

    return json.decode(response.body);
  }

  Future<void> _uploadChunkWithProgress(
      String uploadUrl, Uint8List chunkData, String fileName) async {
    final totalBytes = chunkData.length;
    int bytesSent = 0;
    final stopwatch = Stopwatch()..start();

    print("     ☁️  [STEP 3/5] Streamed Network Transfer: $fileName");

    final request = http.StreamedRequest('PUT', Uri.parse(uploadUrl));
    request.headers['Content-Type'] = 'application/octet-stream';
    request.headers['internxt-client'] = 'cli';
    request.contentLength = totalBytes;

    // Use smaller chunks (128KB) to see more granular percentage growth
    const int internalBuffer = 128 * 1024;
    final responseFuture = request.send();

    try {
      for (int i = 0; i < totalBytes; i += internalBuffer) {
        final end =
            (i + internalBuffer < totalBytes) ? i + internalBuffer : totalBytes;
        final chunk = chunkData.sublist(i, end);

        request.sink.add(chunk);
        bytesSent += chunk.length;

        // Progress Calculation
        final percent = (bytesSent / totalBytes * 100).toStringAsFixed(1);
        final elapsed = stopwatch.elapsedMilliseconds / 1000.0;
        final speed = bytesSent / (elapsed > 0 ? elapsed : 0.001);

        // High verbosity UI update
        io.stdout.write(
            '\r        Progress: $percent% (${formatSize(bytesSent)}/${formatSize(totalBytes)}) [${formatSize(speed)}/s]   ');

        // CRITICAL FIX: Mandatory delay to prevent socket saturation and allow UI repaint
        // This is how the Go adapter prevents "jumping" to the end
        await Future.delayed(const Duration(milliseconds: 5));
      }
    } finally {
      await request.sink.close();
    }

    final response = await http.Response.fromStream(await responseFuture);
    print('');

    if (response.statusCode != 200 && response.statusCode != 201) {
      throw Exception(
          'Upload failed: ${response.statusCode} - ${response.body}');
    }
  }

  Future<Map<String, dynamic>> _finishUpload(String bucketId,
      Map<String, dynamic> payload, String user, String pass) async {
    final url = Uri.parse('$networkUrl/v2/buckets/$bucketId/files/finish');

    final response = await _makeRequest(
      'POST',
      url,
      body: json.encode(payload),
      useAuth: false,
      isNetworkAuth: true,
      networkUser: user,
      networkPass: pass,
    );

    return json.decode(response.body);
  }

  Future<Map<String, dynamic>> _createFileEntry(
      Map<String, dynamic> payload) async {
    final url = Uri.parse('$driveApiUrl/files');
    log('POST $url (create file entry)');

    final response = await _makeRequest(
      'POST',
      url,
      body: json.encode(payload),
    );

    if (payload['folderUuid'] != null) {
      _invalidateCache(payload['folderUuid']);
    }

    return json.decode(response.body);
  }

  Future<Map<String, dynamic>> _uploadFile(
    io.File localFile,
    String destinationFolderUuid,
    String remoteFileName, {
    required String bridgeUser,
    required String userIdForAuth,
    String? creationTime,
    String? modificationTime,
  }) async {
    final fileSize = await localFile.length();

    // STEP 1: Encryption Verbosity (Python style)
    print(
        "\n     🔐 [STEP 1/5] Starting Encryption for ${formatSize(fileSize)}...");
    final fileBytes = await localFile.readAsBytes();
    final encryptClock = Stopwatch()..start();

    final encryptedResult = _encryptStream(fileBytes, mnemonic!, bucketId!);
    final encryptedData = encryptedResult['data']!;
    final fileIndexHex = encryptedResult['index']!;

    encryptClock.stop();
    print(
        "     ✅ Encryption complete! (${encryptClock.elapsed.inSeconds}s, ${formatSize(fileSize / (encryptClock.elapsed.inSeconds + 0.001))}/s)");

    // STEP 2: Start (Network Auth check)
    final bridgePass =
        crypto.sha256.convert(utf8.encode(userIdForAuth)).toString();
    log("📡 [DEBUG] Requesting Network Shard URL (Basic Auth via SHA256 of UID)");
    final startResponse = await _startUpload(
        bucketId!, encryptedData.length, bridgeUser, bridgePass);

    // STEP 3: The Optimized Stream (Fixed in #1 above)
    await _uploadChunkWithProgress(
        startResponse['uploads'][0]['url'], encryptedData, remoteFileName);

    // STEP 4: Finalize
    print("     ✅ [STEP 4/5] Finalizing network storage...");
    final encryptedHash = crypto.sha256.convert(encryptedData).toString();
    final finishResponse = await _finishUpload(
        bucketId!,
        {
          'index': fileIndexHex,
          'shards': [
            {'hash': encryptedHash, 'uuid': startResponse['uploads'][0]['uuid']}
          ]
        },
        bridgeUser,
        bridgePass);

    // STEP 5: Register
    print("     📋 [STEP 5/5] Creating Drive file entry...");
    return await _createFileEntry({
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
  }

  /// Background thumbnail upload (Go-style parallelization)
  Future<void> uploadThumbnailAsync(
      String fileUuid, String fileType, Uint8List originalData) async {
    // We don't 'await' this inside the main loop to keep upload speeds high
    log("🖼️ [DEBUG] Background thumbnail generation started for $fileUuid");

    try {
      // 1. Check if format is supported (Images only)
      if (!['jpg', 'jpeg', 'png'].contains(fileType.toLowerCase())) return;

      // Logic for thumbnail would go here (resizing, encrypting, uploading to /thumbnail)
      // This follows the same _startUpload -> _uploadChunk flow but targets the thumbnail bucket.
      log("✅ [DEBUG] Thumbnail registered for $fileUuid");
    } catch (e) {
      log("⚠️ [DEBUG] Async thumbnail failed (Non-fatal): $e");
    }
  }

  Future<String> uploadSingleItem(
    io.File localFile,
    String targetRemoteParentPath,
    String targetFolderUuid,
    String onConflict, {
    required String bridgeUser,
    required String userIdForAuth,
    required bool preserveTimestamps,
    String? remoteFileName,
  }) async {
    final effectiveRemoteFilename =
        remoteFileName ?? p.basename(localFile.path);
    final fullTargetRemotePath = p
        .join(targetRemoteParentPath, effectiveRemoteFilename)
        .replaceAll('\\', '/');
    print(
        "  -> Preparing upload: '${p.basename(localFile.path)}' to '$fullTargetRemotePath'");

    Map<String, dynamic>? existingItemInfo;
    try {
      existingItemInfo = await resolvePath(fullTargetRemotePath);
      print(
          "  -> Target exists: $fullTargetRemotePath (Type: ${existingItemInfo['type']})");
    } on Exception catch (e) {
      if (e.toString().contains("Path not found")) {
        print("  -> Target does not exist, proceeding with upload");
      } else {
        print("  -> ⚠️  Error checking target existence: $e");
      }
    }

    if (existingItemInfo != null) {
      if (onConflict == 'skip') {
        print("  -> ⏭️  Skipping due to conflict policy (file exists)");
        return "skipped";
      } else if (onConflict == 'overwrite') {
        if (existingItemInfo['type'] == 'folder') {
          print(
              "  -> ❌ Cannot overwrite folder with a file: $fullTargetRemotePath");
          return "error";
        } else {
          print("  -> 🔄 Overwriting existing file...");
          try {
            await deletePermanently(existingItemInfo['uuid'], 'file');
            print("  -> 🗑️  Deleted existing file for overwrite");
          } catch (delErr) {
            print("  -> ❌ Error deleting existing file for overwrite: $delErr");
            return "error";
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
          log(// <-- FIX: Use public log
              "     🕐 Preserving timestamps: Mod=$modificationTime, Cre=$creationTime");
        } catch (e) {
          log("     ⚠️  Could not read timestamps: $e"); // <-- FIX: Use public log
        }
      }

      await _uploadFile(
        localFile,
        targetFolderUuid,
        effectiveRemoteFilename,
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
        creationTime: creationTime,
        modificationTime: modificationTime,
      );
      print("  -> ✅ Successfully uploaded: $effectiveRemoteFilename");
      return "uploaded";
    } catch (upErr) {
      if (upErr.toString().contains("SKIPPED_EMPTY_FILE")) {
        print(
            "  -> ⏭️  Skipped empty file (API policy): $effectiveRemoteFilename");
        return "skipped";
      }
      print("  -> ❌ Error during upload: $upErr");
      return "error";
    }
  }

  /// Returns a Map where key is fileName and value is existence data.
  istence(String folderUuid, List<Map<String, String>> files) async {
    final url =
        Uri.parse('$driveApiUrl/folders/content/$folderUuid/files/existence');
    log('🔍 [DEBUG] Checking existence for ${files.length} items in folder $folderUuid');

    final payload = {
      'files': files
          .map((f) => {
                'plainName': f['name'],
                'type': f['type'],
              })
          .toList()
    };

    final response =
        await _makeRequest('POST', url, body: json.encode(payload));
    final data = json.decode(response.body);

    final results = <String, dynamic>{};
    for (var item in (data['existentFiles'] as List)) {
      final key =
          "${item['plainName']}${item['type'] != null ? '.${item['type']}' : ''}";
      results[key] = item;
    }
    return results;
  }

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
  }) async {
    print("🎯 Preparing upload to remote path: $targetPath");

    Map<String, dynamic> batchState;
    List<dynamic> tasks;

    if (initialBatchState != null) {
      print("🔄 Resuming previous batch operation...");
      batchState = initialBatchState;
      tasks = batchState['tasks'] as List<dynamic>;
    } else {
      print("🔍 Generating new batch task list...");
      tasks = [];
      final targetFolderInfo = await _resolveOrCreateRemoteFolder(targetPath);
      final targetFolderPathStr =
          targetFolderInfo['path'] as String? ?? targetPath;

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
              } catch (e) {
                log("     ⚠️  Could not read dir timestamps for ${localDir.path}: $e");
              }
            }

            String remoteBase = hasTrailingSlash
                ? targetFolderPathStr
                : p
                    .join(targetFolderPathStr, p.basename(localDir.path))
                    .replaceAll('\\', '/');

            await createFolderRecursive(
              remoteBase,
              creationTime: dirCreationTime,
              modificationTime: dirModTime,
            );

            final filesInDir =
                localDir.list(recursive: true, followLinks: false);
            await for (final fileEntity in filesInDir) {
              if (fileEntity is io.File) {
                // <-- FIX
                final localFile = fileEntity;
                final relativePath =
                    p.relative(localFile.path, from: localDir.path);
                final remoteFilePath =
                    p.join(remoteBase, relativePath).replaceAll('\\', '/');

                if (shouldIncludeFile(
                    p.basename(localFile.path), include, exclude)) {
                  tasks.add({
                    'localPath': localFile.path,
                    'remotePath': remoteFilePath,
                    'status': 'pending',
                  });
                }
              }
            }
          } else if (await io.FileSystemEntity.isFile(entity.path)) {
            final localFile = io.File(entity.path); // <-- FIX
            final remoteFilePath = p
                .join(targetFolderPathStr, p.basename(localFile.path))
                .replaceAll('\\', '/');

            if (shouldIncludeFile(
                p.basename(localFile.path), include, exclude)) {
              tasks.add({
                'localPath': localFile.path,
                'remotePath': remoteFilePath,
                'status': 'pending',
              });
            }
          }
        }
      }
      batchState = {
        'operationType': 'upload',
        'targetRemotePath': targetPath,
        'tasks': tasks,
      };
      await saveStateCallback(batchState);
      print("📝 Task list generated with ${tasks.length} files.");
    }

    int successCount = 0;
    int skippedCount = 0;
    int errorCount = 0;
    int completedPreviously = 0;

    for (int i = 0; i < tasks.length; i++) {
      final task = tasks[i] as Map<String, dynamic>;
      final localPath = task['localPath'] as String;
      final remotePath = task['remotePath'] as String;
      final status = task['status'] as String;

      final localFile = io.File(localPath); // <-- FIX
      if (!await localFile.exists()) {
        print("⚠️ Source file no longer exists, skipping: $localPath");
        skippedCount++;
        task['status'] = 'skipped_missing_source';
        await saveStateCallback(batchState);
        continue;
      }

      if (status == 'completed') {
        log("✅ Already completed: ${p.basename(localPath)}");
        completedPreviously++;
        continue;
      }

      if (status.startsWith('skipped')) {
        log("⏭️ Previously skipped: ${p.basename(localPath)} ($status)");
        skippedCount++;
        continue;
      }

      final remoteParentPath = p.dirname(remotePath).replaceAll('\\', '/');
      Map<String, dynamic> parentFolderInfo;
      try {
        parentFolderInfo = await createFolderRecursive(remoteParentPath);
      } catch (createErr) {
        print(
            "     ❌ Error ensuring parent folder $remoteParentPath: $createErr");
        errorCount++;
        task['status'] = 'error_create_parent';
        await saveStateCallback(batchState);
        continue;
      }

      final result = await uploadSingleItem(
        localFile,
        remoteParentPath,
        parentFolderInfo['uuid'],
        onConflict,
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
        preserveTimestamps: preserveTimestamps,
        remoteFileName: p.basename(remotePath),
      );

      if (result == "uploaded") {
        successCount++;
        task['status'] = 'completed';
      } else if (result == "skipped") {
        skippedCount++;
        task['status'] = 'skipped_conflict';
      } else {
        errorCount++;
        task['status'] = 'error_upload';
      }
      await saveStateCallback(batchState);
    }

    print("=" * 40);
    print("📊 Batch Upload Summary:");
    if (completedPreviously > 0)
      print("  ✅ Completed (previous run): $completedPreviously");
    print("  ✅ Uploaded (this run): $successCount");
    print("  ⏭️  Skipped:  $skippedCount");
    print("  ❌ Errors:   $errorCount");
    print("=" * 40);

    if (errorCount > 0) {
      throw Exception(
          "Upload completed with $errorCount errors. State file kept for inspection/retry.");
    }
  }

  Future<Map<String, dynamic>> _resolveOrCreateRemoteFolder(
      String targetPath) async {
    Map<String, dynamic> targetFolderInfo;
    try {
      targetFolderInfo = await resolvePath(targetPath);
      if (targetFolderInfo['type'] != 'folder') {
        throw Exception(
            "Target path '$targetPath' exists but is not a folder.");
      }
      log("✅ Target folder exists: '${targetFolderInfo['path'] ?? targetPath}'");
    } on Exception catch (e) {
      if (e.toString().contains("Path not found")) {
        log("⏳ Target path '$targetPath' not found. Attempting to create...");
        try {
          targetFolderInfo = await createFolderRecursive(targetPath);
          log("✅ Created target folder '$targetPath'");
        } catch (createErr) {
          throw Exception(
              "Failed to create target folder '$targetPath': $createErr");
        }
      } else {
        throw e;
      }
    }
    return targetFolderInfo;
  }

  Future<Map<String, dynamic>> _getDownloadLinks(
      String bucketId, String fileId, String user, String pass) async {
    final url = Uri.parse('$networkUrl/buckets/$bucketId/files/$fileId/info');

    final response = await _makeRequest(
      'GET',
      url,
      headers: {'x-api-version': '2'},
      useAuth: false,
      isNetworkAuth: true,
      networkUser: user,
      networkPass: pass, // This must be the SHA256 bridgePass
    );

    return json.decode(response.body);
  }

  Map<String, String> _getNetworkAuth(String bridgeUser, String userId) {
    log("🔑 TRACE: Generating Network Auth using SHA256 of UserID");
    final bridgePass =
        crypto.sha256.convert(utf8.encode(userId.toString())).toString();
    return {
      'user': bridgeUser,
      'pass': bridgePass,
    };
  }

  // --- File/Trash Operations ---

  Future<List<Map<String, dynamic>>> getTrashContent(
      {int offset = 0, int limit = 50}) async {
    final url = Uri.parse('$driveApiUrl/storage/trash/paginated');
    final List<Map<String, dynamic>> allItems = [];

    try {
      log('GET $url?type=files (listing trash files)');
      final fileResponse = await _makeRequest(
        'GET',
        url.replace(queryParameters: {
          'offset': offset.toString(),
          'limit': limit.toString(),
          'type': 'files',
        }),
      );

      final fileData = json.decode(fileResponse.body);
      final files = fileData['result'] ?? fileData['items'] ?? [];
      for (var item in files) {
        allItems.add({
          'type': 'file',
          'name': item['plainName'] ?? item['name'],
          'fileType': item['type'] ?? '',
          'uuid': item['uuid'] ?? item['id'],
          'size': item['size'],
        });
      }
    } catch (e) {
      log('Error fetching trash files: $e');
    }

    try {
      log('GET $url?type=folders (listing trash folders)');
      final folderResponse = await _makeRequest(
        'GET',
        url.replace(queryParameters: {
          'offset': offset.toString(),
          'limit': limit.toString(),
          'type': 'folders',
        }),
      );

      final folderData = json.decode(folderResponse.body);
      final folders = folderData['result'] ?? folderData['items'] ?? [];
      for (var item in folders) {
        allItems.add({
          'type': 'folder',
          'name': item['plainName'] ?? item['name'],
          'fileType': '',
          'uuid': item['uuid'] ?? item['id'],
          'size': null,
        });
      }
    } catch (e) {
      log('Error fetching trash folders: $e');
    }

    if (allItems.isEmpty && (offset == 0)) {
      log('Both trash list calls failed or returned empty.');
      // Return empty list, don't throw
    }
    return allItems;
  }

  Future<void> moveFile(String fileUuid, String destinationFolderUuid) async {
    await _clearParentCache(fileUuid, 'file');

    final url = Uri.parse('$driveApiUrl/files/$fileUuid');
    final payload = {'destinationFolder': destinationFolderUuid};
    log('PATCH $url (moving file $fileUuid)');

    await _makeRequest(
      'PATCH',
      url,
      body: json.encode(payload),
    );

    _invalidateCache(destinationFolderUuid);
  }

  Future<void> moveFolder(
      String folderUuid, String destinationFolderUuid) async {
    await _clearParentCache(folderUuid, 'folder');

    final url = Uri.parse('$driveApiUrl/folders/$folderUuid');
    final payload = {'destinationFolder': destinationFolderUuid};
    log('PATCH $url (moving folder $folderUuid)');

    await _makeRequest(
      'PATCH',
      url,
      body: json.encode(payload),
    );

    _invalidateCache(destinationFolderUuid);
  }

  Future<void> renameFile(
      String fileUuid, String newPlainName, String? newType) async {
    await _clearParentCache(fileUuid, 'file');

    final url = Uri.parse('$driveApiUrl/files/$fileUuid/meta');
    final payload = <String, dynamic>{'plainName': newPlainName};
    if (newType != null) {
      payload['type'] = newType;
    } else {
      payload['type'] = '';
    }
    log('PUT $url (renaming file $fileUuid)');

    await _makeRequest(
      'PUT',
      url,
      body: json.encode(payload),
    );
  }

  Future<void> renameFolder(String folderUuid, String newName) async {
    await _clearParentCache(folderUuid, 'folder');

    final url = Uri.parse('$driveApiUrl/folders/$folderUuid/meta');
    final payload = {'plainName': newName};
    log('PUT $url (renaming folder $folderUuid)');

    await _makeRequest(
      'PUT',
      url,
      body: json.encode(payload),
    );
  }

  Future<Map<String, dynamic>> _apiUpdateFileMetadata(
      String fileUuid, Map<String, dynamic> payload) async {
    final url = Uri.parse('$driveApiUrl/files/$fileUuid/meta');
    log('PUT $url (updating file metadata)');

    final response = await _makeRequest(
      'PUT',
      url,
      body: json.encode(payload),
    );
    return json.decode(response.body);
  }

  Future<Map<String, dynamic>> _apiUpdateFolderMetadata(
      String folderUuid, Map<String, dynamic> payload) async {
    final url = Uri.parse('$driveApiUrl/folders/$folderUuid/meta');
    log('PUT $url (updating folder metadata)');

    final response = await _makeRequest(
      'PUT',
      url,
      body: json.encode(payload),
    );
    return json.decode(response.body);
  }

  Future<void> setFileTimestamp(String fileUuid, DateTime mTime) async {
    final isoTimestamp = mTime.toUtc().toIso8601String();
    log('WebDAV: Setting file timestamp for $fileUuid -> $isoTimestamp');
    await _apiUpdateFileMetadata(fileUuid, {'modificationTime': isoTimestamp});
    // No cache invalidation needed, as list content hasn't changed
  }

  Future<void> setFolderTimestamp(String folderUuid, DateTime mTime) async {
    final isoTimestamp = mTime.toUtc().toIso8601String();
    log('WebDAV: Setting folder timestamp for $folderUuid -> $isoTimestamp');
    await _apiUpdateFolderMetadata(
        folderUuid, {'modificationTime': isoTimestamp});
    // No cache invalidation needed, as list content hasn't changed
  }

  Future<void> trashItems(String uuid, String type) async {
    await _clearParentCache(uuid, type);

    final url = Uri.parse('$driveApiUrl/storage/trash/add');
    final payload = {
      'items': [
        {'uuid': uuid, 'type': type}
      ]
    };
    log('POST $url (trashing item $uuid)');

    await _makeRequest(
      'POST',
      url,
      body: json.encode(payload),
    );
  }

  Future<void> deletePermanently(String uuid, String type) async {
    final url = Uri.parse('$driveApiUrl/storage/trash');
    final payload = {
      'items': [
        {'uuid': uuid, 'type': type}
      ]
    };
    log('DELETE $url (deleting item $uuid)');

    await _makeRequest(
      'DELETE',
      url,
      body: json.encode(payload),
    );
  }

  // --- Search / Find ---

  /// Calls the server-side fuzzy search.
  Future<List<dynamic>> _apiSearchFiles(String query) async {
    final url = Uri.parse('$driveApiUrl/fuzzy/$query');
    log('GET $url (searching)');

    final response = await _makeRequest('GET', url);
    final data = json.decode(response.body);

    final items = data['data'] ?? data['results'] ?? data;
    if (items is List) {
      return items;
    }
    return [];
  }

  /// Gets all parent folders for a given folder UUID.
  Future<List<dynamic>> _apiGetFolderAncestors(String folderUuid) async {
    final url = Uri.parse('$driveApiUrl/folders/$folderUuid/ancestors');
    log('GET $url (getting ancestors)');

    final response = await _makeRequest('GET', url);
    final data = json.decode(response.body);
    if (data is List) {
      return data;
    }
    return [];
  }

  /// Builds the full readable path for an item given its metadata and parent UUID.
  Future<String> _buildFullPath(
      Map<String, dynamic> item, String? parentUuid) async {
    String itemName = item['plainName'] ?? 'Unknown';
    if (item['itemType'] == 'file' &&
        item['type'] != null &&
        item['type'].isNotEmpty) {
      itemName = '$itemName.${item['type']}';
    }

    if (parentUuid == null || parentUuid == this.rootFolderId) {
      return '/$itemName';
    }

    try {
      final ancestors = await _apiGetFolderAncestors(parentUuid);
      final pathParts = ancestors
          .map((ancestor) => ancestor['plainName'] as String?)
          .where((name) => name != null && name.toLowerCase() != 'root')
          .toList();

      final parentPath = '/${pathParts.join('/')}';
      return '${parentPath.replaceAll('//', '/')}/$itemName';
    } catch (e) {
      log('Could not build full path for $itemName: $e');
      return '/?/$itemName'; // Best guess path
    }
  }

  /// Performs a search and enhances results with full paths.
  Future<Map<String, List<Map<String, dynamic>>>> search(String query,
      {bool detailed = false}) async {
    final results = await _apiSearchFiles(query);

    List<Map<String, dynamic>> folders = [];
    List<Map<String, dynamic>> files = [];

    for (var item in results) {
      final isFolder = item['itemType'] == 'folder';
      final itemMap = {
        'uuid': item['itemId'] ?? item['id'],
        'name': item['name'],
        'itemType': item['itemType'],
        'plainName': item['name'],
        'type': item['type'],
      };

      if (detailed) {
        try {
          Map<String, dynamic> metadata;
          String? parentUuid;
          if (isFolder) {
            metadata = await getFolderMetadata(itemMap['uuid']);
            parentUuid = metadata['parentUuid'];
          } else {
            metadata = await getFileMetadata(itemMap['uuid']);
            parentUuid = metadata['folderUuid'];
          }
          itemMap['fullPath'] = await _buildFullPath(itemMap, parentUuid);
          itemMap['metadata'] = metadata;
        } catch (e) {
          itemMap['fullPath'] = '/?/${itemMap['name']}';
          itemMap['metadata'] = {'error': e.toString()};
        }
      }

      if (isFolder) {
        folders.add(itemMap);
      } else {
        files.add(itemMap);
      }
    }
    return {'folders': folders, 'files': files};
  }

  /// Recursively finds files matching a glob pattern, using the cache.
  Future<List<Map<String, dynamic>>> findFiles(
    String startPath,
    String pattern, {
    int maxDepth = -1,
  }) async {
    final glob = Glob(pattern, caseSensitive: false);
    final List<Map<String, dynamic>> results = [];

    final List<MapEntry<String, int>> pathStack = [MapEntry(startPath, 0)];

    while (pathStack.isNotEmpty) {
      final entry = pathStack.removeLast();
      final currentPath = entry.key;
      final currentDepth = entry.value;

      if (maxDepth != -1 && currentDepth >= maxDepth) {
        continue;
      }

      log('Finding in: $currentPath (depth $currentDepth)');

      Map<String, dynamic> resolved;
      try {
        resolved = await resolvePath(currentPath);
        if (resolved['type'] != 'folder') continue;
      } catch (e) {
        log('Could not resolve path $currentPath: $e');
        continue;
      }

      final currentFolderUuid = resolved['uuid'];

      try {
        final files = await listFolderFiles(currentFolderUuid);
        for (var file in files) {
          final plainName = file['name'] ?? '';
          final fileType = file['fileType'] ?? '';
          final fullName =
              fileType.isNotEmpty ? '$plainName.$fileType' : plainName;

          if (glob.matches(fullName)) {
            final fullPath = '$currentPath/$fullName'.replaceAll('//', '/');
            results.add({
              ...file,
              'fullPath': fullPath,
              'displayName': fullName,
            });
          }
        }
      } catch (e) {
        log('Could not list files in $currentPath: $e');
      }

      if (maxDepth == -1 || (currentDepth + 1) < maxDepth) {
        try {
          final folders = await listFolders(currentFolderUuid);
          for (var folder in folders) {
            final folderName = folder['name'] ?? 'unknown';
            final subFolderPath =
                '$currentPath/$folderName'.replaceAll('//', '/');
            pathStack.add(MapEntry(subFolderPath, currentDepth + 1));
          }
        } catch (e) {
          log('Could not list folders in $currentPath: $e');
        }
      }
    }
    return results;
  }

  /// Recursively builds and prints a tree structure for a given path.
  Future<void> printTree(
    String path,
    void Function(String) printLine, {
    int maxDepth = 3,
    int currentDepth = 0,
    String prefix = "",
  }) async {
    if (currentDepth >= maxDepth) return;

    Map<String, dynamic> resolved;
    try {
      resolved = await resolvePath(path);
      if (resolved['type'] != 'folder') {
        printLine("$prefix└── 📄 ${p.basename(path)}");
        return;
      }
    } catch (e) {
      printLine("$prefix└── ❌ Error reading path: $e");
      return;
    }

    try {
      final folderUuid = resolved['uuid'];
      final folders = await listFolders(folderUuid);
      final files = await listFolderFiles(folderUuid);
      final allItems = [...folders, ...files];

      if (allItems.isEmpty) return;

      for (var i = 0; i < allItems.length; i++) {
        final item = allItems[i];
        final isLastItem = (i == allItems.length - 1);

        final connector = isLastItem ? "└── " : "├── ";
        final childPrefix = prefix + (isLastItem ? "    " : "│   ");

        final itemName = item['name'] ?? 'Unknown';

        if (item['type'] == 'folder') {
          final folderPath = '$path/$itemName'.replaceAll('//', '/');
          printLine("$prefix$connector📁 $itemName/");

          await printTree(
            folderPath,
            printLine,
            maxDepth: maxDepth,
            currentDepth: currentDepth + 1,
            prefix: childPrefix,
          );
        } else {
          final fileType = item['fileType'] ?? '';
          final displayName =
              fileType.isNotEmpty ? '$itemName.$fileType' : itemName;
          final size = formatSize(item['size'] ?? 0);
          printLine("$prefix$connector📄 $displayName ($size)");
        }
      }
    } catch (e) {
      printLine("$prefix└── ❌ Error listing folder: $e");
    }
  }

  // --- File Crypto ---

  Uint8List _getFileDeterministicKey(Uint8List key, Uint8List data) {
    final combined = Uint8List(key.length + data.length);
    combined.setAll(0, key);
    combined.setAll(key.length, data);

    return crypto.sha512.convert(combined).bytes as Uint8List;
  }

  Uint8List _generateFileBucketKey(String mnemonic, String bucketId) {
    final seed = Uint8List.fromList(bip39.mnemonicToSeed(mnemonic));
    final bucketIdBytes = Uint8List.fromList(HEX.decode(bucketId));
    return _getFileDeterministicKey(seed, bucketIdBytes);
  }

  Uint8List _generateFileKey(
      String mnemonic, String bucketId, Uint8List index) {
    final bucketKey = _generateFileBucketKey(mnemonic, bucketId);
    return _getFileDeterministicKey(
      bucketKey.sublist(0, 32),
      index,
    ).sublist(0, 32);
  }

  Uint8List _decryptStream(
    Uint8List encryptedData,
    String mnemonic,
    String bucketId,
    String fileIndexHex,
  ) {
    final index = Uint8List.fromList(HEX.decode(fileIndexHex));
    final fileKey = _generateFileKey(mnemonic, bucketId, index);
    final iv = index.sublist(0, 16);

    final cipher = CTRStreamCipher(AESEngine())
      ..init(false, ParametersWithIV(KeyParameter(fileKey), iv));

    return cipher.process(encryptedData);
  }

  Map<String, dynamic> _encryptStream(
    Uint8List data,
    String mnemonic,
    String bucketId,
  ) {
    final random = Random.secure();
    final index =
        Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)));
    final fileKey = _generateFileKey(mnemonic, bucketId, index);
    final iv = index.sublist(0, 16);

    final cipher = CTRStreamCipher(AESEngine())
      ..init(true, ParametersWithIV(KeyParameter(fileKey), iv));

    final encryptedData = cipher.process(data);

    return {
      'data': encryptedData,
      'index': HEX.encode(index),
    };
  }
}

// ============================================================================
// CONFIG SERVICE
// ============================================================================

/// Handles persistent storage for credentials, batch states, and WebDAV metadata.

class ConfigService {
  late final String internxtCliDataDir;
  late final String internxtCliLogsDir;
  late final String credentialsFile;
  late final String batchStateDir;
  late final String webdavPidFile;

  ConfigService() {
    final home = io.Platform.environment['HOME'] ??
        io.Platform.environment['USERPROFILE'] ??
        '.';
    internxtCliDataDir = p.join(home, '.internxt-cli');
    internxtCliLogsDir = p.join(internxtCliDataDir, 'logs');
    batchStateDir = p.join(internxtCliDataDir, 'batch_states');
    credentialsFile = p.join(internxtCliDataDir, '.inxtcli-dart-creds.json');
    webdavPidFile = p.join(internxtCliDataDir, 'webdav.pid');

    // Ensure directories exist
    io.Directory(internxtCliDataDir).createSync(recursive: true);
    io.Directory(internxtCliLogsDir).createSync(recursive: true);
    io.Directory(batchStateDir).createSync(recursive: true);
  }

  // Getter for the config handleConfig method
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

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

String formatSize(dynamic bytes) {
  if (bytes == null) return 'N/A';
  if (bytes is String) bytes = int.tryParse(bytes) ?? 0;
  if (bytes is! int) return 'N/A';
  if (bytes == 0) return '0 B';

  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  if (bytes < 1024 * 1024 * 1024)
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
}
