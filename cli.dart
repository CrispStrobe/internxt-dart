#!/usr/bin/env dart
import 'dart:convert'; // Required for latin1
import 'dart:io';
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
import 'package:http_parser/http_parser.dart' show MediaType;

/// Internxt CLI in Dart
void main(List<String> arguments) async {
  final cli = InternxtCLI();
  await cli.run(arguments);
}

class InternxtCLI {
  final InternxtClient client = InternxtClient();
  final ConfigService config = ConfigService();
  bool debugMode = false;

  Future<void> run(List<String> arguments) async {
    final parser = ArgParser()
      ..addFlag('debug', abbr: 'd', help: 'Enable debug output')
      ..addFlag('uuids', help: 'Show full UUIDs in list command')
      ..addFlag('recursive', abbr: 'r', help: 'Recursive operation')
      ..addFlag('preserve-timestamps', abbr: 'p', help: 'Preserve file modification times')
      ..addOption('target', abbr: 't', help: 'Destination path on Internxt Drive')
      ..addOption('on-conflict',
          help: 'Action if target exists (overwrite/skip)',
          allowed: ['overwrite', 'skip'],
          defaultsTo: 'skip')
      ..addMultiOption('include', help: 'Include only files matching pattern')
      ..addMultiOption('exclude', help: 'Exclude files matching pattern')
      // --force flag for trash/delete
      ..addFlag('force', abbr: 'f', help: 'Skip confirmation for destructive actions');

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
          // simple UUID downloader
          await handleDownload(argResults.rest.sublist(1));
          break;
        case 'download-path':
          // more feature-rich path downloader
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
        case 'help':
        case '--help':
        case '-h':
          printHelp();
          break;
        default:
          stderr.writeln('❌ Unknown command: $command');
          stderr.writeln('💡 Use "dart cli.dart help" for available commands');
          exit(1);
      }
    } catch (e, stackTrace) {
      stderr.writeln('❌ Error: $e');
      if (debugMode) {
        stderr.writeln('\nStack trace:');
        stderr.writeln(stackTrace);
      }
      exit(1);
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
    print('  list [path-id]     List files and folders (default: root)');
    print('  download <file-uuid> Download a file by its UUID');
    print('  download-path <path> Download a file/folder by its path');
    print('  upload <sources...>  Upload files/folders to Internxt');

    print('  mkdir-path <path>  Create a new folder (and subfolders) by path');
    print('  resolve <path>     Show what a path points to (debugging)');
    print('  trash-path <path>  Move a file or folder to trash by path');
    print('  delete-path <path> Permanently delete a file or folder by path');

    print('  config             Show configuration');
    print('  test               Run crypto tests');
    print('  help               Show this help message');
    print('');
    print('Options:');
    print('  --debug, -d        Enable debug output');
    print('  --uuids            Show full UUIDs in "list" command');
    print('  -f, --force        Skip confirmation for "trash-path" and "delete-path"');
    print('');
    print('Upload/Download Options:');
    print('  -t, --target <path>  Remote destination path (default: /)');
    print('  -r, --recursive    Recursive operation for directories');
    print('  -p, --preserve-timestamps');
    print('                     Preserve file modification times');
    print('  --on-conflict <mode> Action on conflict (overwrite/skip) (default: skip)');
    print('  --include <pattern>  Include files matching pattern');
    print('  --exclude <pattern>  Exclude files matching pattern');
    print('');
    print('Examples:');
    print('  dart cli.dart login --debug');
    print('  dart cli.dart list');
    print('  dart cli.dart upload file.txt -t /Documents');
    print('  dart cli.dart upload "assets/*.png" -t /Images');
    print('  dart cli.dart upload my_folder/ -t /Backup -r');
    print('  dart cli.dart download-path /Documents/file.txt');
    print('  dart cli.dart download-path /Backup -r');
    print('  dart cli.dart mkdir-path /New/SubFolder');
    print('  dart cli.dart trash-path /OldFile.txt');
  }
  
  void printHelp() {
    printWelcome();
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
    
    // Prompt for email
    stdout.write('What is your email? ');
    final email = stdin.readLineSync()?.trim() ?? '';
    if (email.isEmpty) {
      stderr.writeln('❌ Email is required');
      exit(1);
    }
    
    // Prompt for password
    stdout.write('What is your password? ');
    stdin.echoMode = false;
    final password = stdin.readLineSync()?.trim() ?? '';
    stdin.echoMode = true;
    print('');
    
    if (password.isEmpty) {
      stderr.writeln('❌ Password is required');
      exit(1);
    }
    
    // Check 2FA requirements
    print('🔍 Checking 2FA requirements...');
    final needs2fa = await client.is2faNeeded(email);
    
    String? tfaCode;
    if (needs2fa) {
      print('🔐 Two-factor authentication is enabled');
      stdout.write('Enter your 2FA code (6 digits): ');
      tfaCode = stdin.readLineSync()?.trim();
      if (tfaCode == null || tfaCode.isEmpty) {
        stderr.writeln('❌ 2FA code is required');
        exit(1);
      }
    }
    
    // Perform login
    print('🔐 Logging in...');
    try {
      final credentials = await client.login(email, password, tfaCode: tfaCode);
      
      // Save credentials
      await config.saveCredentials(credentials);
      
      print('✅ Login successful!');
      print('👤 User: ${credentials['email']}');
      print('🆔 User ID: ${credentials['userId']}');
      print('📁 Root Folder ID: ${credentials['rootFolderId']}');
    } catch (e) {
      stderr.writeln('❌ Login failed: $e');
      exit(1);
    }
  }
  
  Future<void> handleWhoami() async {
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        exit(1);
      }
      
      print('╔════════════════════════════════════════╗');
      print('║         Current User Info              ║');
      print('╚════════════════════════════════════════╝');
      print('📧 Email: ${creds['email']}');
      print('🆔 User ID: ${creds['userId']}');
      print('📁 Root Folder: ${creds['rootFolderId']}');
    } catch (e) {
      stderr.writeln('❌ Error: $e');
      exit(1);
    }
  }
  
  Future<void> handleLogout() async {
    try {
      await config.clearCredentials();
      print('✅ Logged out successfully');
    } catch (e) {
      stderr.writeln('❌ Error: $e');
      exit(1);
    }
  }

  Future<void> handleMkdirPath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      stderr.writeln('❌ Usage: dart cli.dart mkdir-path <path>');
      exit(1);
    }
    
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        exit(1);
      }
      client.setAuth(creds);
      
      final path = args[0];
      print("📁 Creating folder(s): $path");
      
      final createdFolder = await client.createFolderRecursive(path);
      
      print("✅ Folder created successfully!");
      print("   Name: ${createdFolder['plainName']}");
      print("   UUID: ${createdFolder['uuid']}");
      
    } catch (e) {
      stderr.writeln('❌ Error creating folder: $e');
      exit(1);
    }
  }

  Future<void> handleResolve(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      stderr.writeln('❌ Usage: dart cli.dart resolve <path>');
      exit(1);
    }
    
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        exit(1);
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
      // Simple pretty print of the metadata map
      (resolved['metadata'] as Map<String, dynamic>).forEach((key, value) {
        print("    $key: $value");
      });
      print("=" * 40);

    } catch (e) {
      stderr.writeln('❌ Error resolving path: $e');
      exit(1);
    }
  }

  // Helper for confirmation
  bool _confirmAction(String prompt, bool force) {
    if (force) {
      return true;
    }
    stdout.write('$prompt [y/N]: ');
    final response = stdin.readLineSync()?.toLowerCase().trim();
    return response == 'y' || response == 'yes';
  }

  Future<void> handleTrashPath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      stderr.writeln('❌ Usage: dart cli.dart trash-path <path> [--force]');
      exit(1);
    }
    
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        exit(1);
      }
      client.setAuth(creds);
      
      final path = args[0];
      final force = argResults['force'] as bool;
      
      print("🔍 Resolving path: $path");
      final resolved = await client.resolvePath(path);
      
      final prompt = '❓ Move ${resolved['type']} "$path" to trash?';
      if (!_confirmAction(prompt, force)) {
        print("❌ Cancelled");
        exit(0);
      }
      
      await client.trashItems(resolved['uuid'], resolved['type']);
      
      print("✅ Item moved to trash: $path");

    } catch (e) {
      stderr.writeln('❌ Error trashing item: $e');
      exit(1);
    }
  }

  Future<void> handleDeletePath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      stderr.writeln('❌ Usage: dart cli.dart delete-path <path> [--force]');
      exit(1);
    }
    
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        exit(1);
      }
      client.setAuth(creds);
      
      final path = args[0];
      final force = argResults['force'] as bool;
      
      print("🔍 Resolving path: $path");
      final resolved = await client.resolvePath(path);
      
      print("⚠️  WARNING: This will PERMANENTLY delete the item. This action cannot be undone!");
      final prompt = '❓ Permanently delete ${resolved['type']} "$path"?';
      if (!_confirmAction(prompt, force)) {
        print("❌ Cancelled");
        exit(0);
      }
      
      await client.deletePermanently(resolved['uuid'], resolved['type']);
      
      print("✅ Item permanently deleted: $path");

    } catch (e) {
      stderr.writeln('❌ Error deleting item: $e');
      exit(1);
    }
  }
  
  Future<void> handleList(ArgResults argResults) async {
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        exit(1);
      }
      
      client.setAuth(creds);
      
      final commandRestArgs = argResults.rest.sublist(1); 
      
      // Get folderId from remaining arguments
      final folderId = commandRestArgs.isNotEmpty ? commandRestArgs[0] : creds['rootFolderId']!;
      // Check if the --uuids flag was passed
      final bool showFullUUIDs = argResults['uuids'];

      print('📂 Listing folder: $folderId\n');
      
      // Get folders
      final folders = await client.listFolders(folderId);
      // Get files
      final files = await client.listFolderFiles(folderId);
      
      final items = [...folders, ...files];
      
      if (items.isEmpty) {
        print('📭 Folder is empty');
        return;
      }
      
      // Adjust table layout based on whether full UUIDs are shown
      if (showFullUUIDs) {
        print('╔════════════════════════════════════════════════════════════════════════════════════════════════════╗');
        print('║  Type    Name                                    Size            UUID                                 ║');
        print('╠════════════════════════════════════════════════════════════════════════════════════════════════════╣');
      } else {
        print('╔═══════════════════════════════════════════════════════════════════════════════╗');
        print('║  Type    Name                                    Size            UUID        ║');
        print('╠═══════════════════════════════════════════════════════════════════════════════╣');
      }
      
      for (var item in items) {
        final type = item['type'] == 'folder' ? '📁' : '📄';
        
        // Re-create the full name for display
        final plainName = item['name'] ?? 'Unknown';
        final fileType = item['type'] == 'file' ? (item['fileType'] ?? '') : '';
        final displayName = (fileType.isNotEmpty && item['type'] == 'file') ? '$plainName.$fileType' : plainName;

        final name = displayName.toString().padRight(40);
        final size = item['type'] == 'folder' ? '<DIR>' : formatSize(item['size'] ?? 0);
        final uuid = item['uuid'] ?? 'N/A';

        // Print either the full UUID or the truncated one
        if (showFullUUIDs) {
          print('║  $type  ${name.substring(0, min(name.length, 40))}  ${size.padLeft(12)}  $uuid ║');
        } else {
          print('║  $type  ${name.substring(0, min(name.length, 40))}  ${size.padLeft(12)}  ${uuid.substring(0, 8)}... ║');
        }
      }
      
      if (showFullUUIDs) {
        print('╚════════════════════════════════════════════════════════════════════════════════════════════════════╝');
      } else {
        print('╚═══════════════════════════════════════════════════════════════════════════════╝');
      }
      
      print('\n📊 Total: ${items.length} items (${folders.length} folders, ${files.length} files)');
    } catch (e) {
      stderr.writeln('❌ Error: $e');
      exit(1);
    }
  }

  Future<void> handleUpload(ArgResults argResults) async {
    final sources = argResults.rest.sublist(1);
    if (sources.isEmpty) {
      stderr.writeln('❌ No source files or directories specified.');
      exit(1);
    }

    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        exit(1);
      }
      client.setAuth(creds);
      
      // Get credentials to pass to the client
      final bridgeUser = creds['bridgeUser'];
      final userIdForAuth = creds['userIdForAuth'];
      if (bridgeUser == null || userIdForAuth == null) {
         throw Exception('Credentials file is missing bridgeUser or userId. Please login again.');
      }

      final targetPath = argResults['target'] as String? ?? '/';
      final recursive = argResults['recursive'] as bool;
      final onConflict = argResults['on-conflict'] as String;
      final preserveTimestamps = argResults['preserve-timestamps'] as bool;
      final include = argResults['include'] as List<String>;
      final exclude = argResults['exclude'] as List<String>;

      await client.upload(
        sources,
        targetPath,
        recursive: recursive,
        onConflict: onConflict,
        preserveTimestamps: preserveTimestamps,
        include: include,
        exclude: exclude,
        // FIXED: Pass credentials down
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
      );
    } catch (e) {
      stderr.writeln('❌ Upload failed: $e');
      exit(1);
    }
  }

  Future<void> handleDownloadPath(ArgResults argResults) async {
    final args = argResults.rest.sublist(1);
    if (args.isEmpty) {
      stderr.writeln('❌ Usage: dart cli.dart download-path <path>');
      exit(1);
    }
    
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        exit(1);
      }
      client.setAuth(creds);

      // Get all options
      final remotePath = args[0];
      final localDestination = argResults['target'] as String?;
      final recursive = argResults['recursive'] as bool;
      final onConflict = argResults['on-conflict'] as String;
      final preserveTimestamps = argResults['preserve-timestamps'] as bool;
      final include = argResults['include'] as List<String>;
      final exclude = argResults['exclude'] as List<String>;
      
      // Get credentials needed for download
      final bridgeUser = creds['bridgeUser'];
      final userIdForAuth = creds['userIdForAuth'];
      if (bridgeUser == null || userIdForAuth == null) {
         throw Exception('Credentials file is missing bridgeUser or userId. Please login again.');
      }

      print('⬇️  Downloading from path: $remotePath');

      // Call the more feature-rich downloadPath method
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
      );

    } catch (e) {
      stderr.writeln('❌ Download failed: $e');
      exit(1);
    }
  }
  
  Future<void> handleDownload(List<String> args) async {
    if (args.isEmpty) {
      stderr.writeln('❌ Usage: dart cli.dart download <file-uuid>');
      exit(1);
    }
    
    try {
      final creds = await config.readCredentials();
      if (creds == null) {
        stderr.writeln('❌ Not logged in. Use "dart cli.dart login" first.');
        exit(1);
      }
      
      client.setAuth(creds);
      
      // pass credentials to client.downloadFile. They are required for _getNetworkAuth.
      final fileUuid = args[0];
      final bridgeUser = creds['bridgeUser'];
      final userIdForAuth = creds['userIdForAuth'];

      if (bridgeUser == null || userIdForAuth == null) {
         throw Exception('Credentials file is missing bridgeUser or userId. Please login again.');
      }

      print('⬇️  Downloading file: $fileUuid\n');
      
      final result = await client.downloadFile(fileUuid, bridgeUser, userIdForAuth);
      final data = result['data'] as Uint8List;
      final filename = result['filename'] as String;
      
      final file = File(filename);
      await file.writeAsBytes(data);
      
      print('\n✅ Downloaded successfully: $filename');
      print('📊 Size: ${formatSize(data.length)}');
    } catch (e) {
      stderr.writeln('❌ Error: $e');
      exit(1);
    }
  }
  
  Future<void> handleConfig() async {
    print('╔════════════════════════════════════════╗');
    print('║         Configuration                  ║');
    print('╚════════════════════════════════════════╝');
    print('📁 Config dir: ${config.configDir}');
    print('🔐 Credentials file: ${config.credentialsFile}');
    print('');
    print('🌐 API Endpoints (from Python blueprint):');
    print('   NETWORK_URL: ${InternxtClient.networkUrl}');
    print('     └─ Data: /buckets/{bucketId}/files/...');
    print('   DRIVE_API_URL: ${InternxtClient.driveApiUrl}');
    print('     └─ Auth: /auth/login, /auth/security');
    print('     └─ Meta: /storage/v2/folders/..., /storage/file/...');
    print('');
    print('🔒 Crypto:');
    print('   APP_CRYPTO_SECRET: ${InternxtClient.appCryptoSecret}');
  }
  
  Future<void> handleTest() async {
    print('🧪 Running crypto tests...\n');
    
    print('Test 1: APP_CRYPTO_SECRET validation');
    print('   Expected: 6KYQBP847D4ATSFA');
    print('   Actual: ${InternxtClient.appCryptoSecret}');
    assert(InternxtClient.appCryptoSecret == '6KYQBP847D4ATSFA', 'APP_CRYPTO_SECRET mismatch!');
    print('   ✅ PASS\n');
    
    print('Test 2: API URLs validation');
    print('   NETWORK_URL: ${InternxtClient.networkUrl}');
    assert(InternxtClient.networkUrl == 'https://api.internxt.com', 'NETWORK_URL mismatch!');
    print('   DRIVE_API_URL: ${InternxtClient.driveApiUrl}');
    assert(InternxtClient.driveApiUrl == 'https://api.internxt.com/drive', 'DRIVE_API_URL mismatch!');
    print('   ✅ PASS\n');
    
    print('Test 3: Encryption/Decryption (OpenSSL compat)');
    final testText = 'Hello Internxt';
    final encrypted = client._encryptTextWithKey(testText, InternxtClient.appCryptoSecret);
    print('   Encrypted: ${encrypted.substring(0, 32)}...');
    final decrypted = client._decryptTextWithKey(encrypted, InternxtClient.appCryptoSecret);
    print('   Decrypted: $decrypted');
    assert(decrypted == testText, 'Encryption/Decryption failed!');
    print('   ✅ PASS\n');
    
    print('Test 4: Password hashing (PBKDF2-SHA1)');
    final password = 'testpass123';
    final salt = '1234567890abcdef1234567890abcdef';
    final hashResult = client._passToHash(password, salt);
    print('   Salt: $salt');
    print('   Hash: ${hashResult['hash']!.substring(0, 32)}...');
    final expectedHash = 'a329c2393e185f403c03b11e2f18f1f771960205b38d3adaf6861a5c681d1112';
    assert(hashResult['hash']! == expectedHash, 'PBKDF2-SHA1 hash mismatch!');
    print('   ✅ PASS\n');
    
    print('Test 5: Mnemonic validation');
    final validMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    final isValid = bip39.validateMnemonic(validMnemonic);
    print('   Mnemonic: ${validMnemonic.substring(0, 40)}...');
    print('   Valid: $isValid');
    assert(isValid, 'Valid mnemonic should pass validation');
    print('   ✅ PASS\n');
    
    print('Test 6: File Key Derivation (SHA512)');
    final key = Uint8List.fromList(utf8.encode('test-key'));
    final data = Uint8List.fromList(utf8.encode('test-data'));
    final derived = client._getFileDeterministicKey(key, data);
    print('   SHA512 derived key (hex): ${HEX.encode(derived).substring(0, 32)}...');
    final expectedDerived = '5b3318451d655f050b46b04e6c196cfb6b716e288e7343c484795b5e73e97fce6f65832a8f307328b1853b05b38f3b7c251dadbf1893c52a32c2865c6c0b387c';
    assert(HEX.encode(derived) == expectedDerived, 'SHA512 key derivation mismatch!');
    print('   ✅ PASS\n');
    
    print('✅ All tests passed!');
  }
}

// ============================================================================
// INTERNXT CLIENT
// ============================================================================

class InternxtClient {
  static const String driveWebUrl = 'https://drive.internxt.com';
  static const String networkUrl = 'https://api.internxt.com';
  static const String driveApiUrl = 'https://api.internxt.com/drive';
  
  static const String appCryptoSecret = '6KYQBP847D4ATSFA';
  
  bool debugMode = false;
  
  String? authToken;
  String? newToken;
  String? mnemonic;
  String? userEmail;
  String? userId;
  String? rootFolderId;
  String? bucketId;
  
  void _log(String message) {
    if (debugMode) {
      print('🔍 [DEBUG] $message');
    }
  }

  void setAuth(Map<String, String?> creds) { // <-- Allow String?
    authToken = creds['token'];
    newToken = creds['newToken'];
    mnemonic = creds['mnemonic'];
    userEmail = creds['email'];
    userId = creds['userId'];
    rootFolderId = creds['rootFolderId'];
    bucketId = creds['bucketId'];
  }
  
  /// Check if 2FA is needed for an email
  Future<bool> is2faNeeded(String email) async {
    try {
      final url = Uri.parse('$driveApiUrl/auth/login');
      _log('Checking 2FA at: POST $url');
      
      final response = await http.post(
        url,
        headers: {'Content-Type': 'application/json'},
        body: json.encode({'email': email}),
      );
      
      _log('2FA check response code: ${response.statusCode}');
      
      if (response.statusCode != 200) {
        _log('2FA check failed with status ${response.statusCode}');
        _log('2FA check response body: ${response.body}');
        // If the user doesn't exist, it's not 2FA enabled.
        return false; 
      }
      
      final data = json.decode(response.body);
      final tfa = data['tfa'] == true;
      _log('2FA enabled: $tfa');
      return tfa;
    } catch (e) {
      _log('2FA check error: $e');
      return false;
    }
  }
  
  /// Login to Internxt
  Future<Map<String, String?>> login(String email, String password, {String? tfaCode}) async {
    _log('========================================');
    _log('Starting login process');
    _log('Email: $email');
    _log('Has TFA code: ${tfaCode != null}');
    _log('========================================');
    
    // Step 1: Get security details
    _log('STEP 1: Getting security details');
    final securityDetails = await _getSecurityDetails(email);
    _log('Security details received: ${securityDetails.keys}');
    
    final encryptedSalt = securityDetails['sKey'];
    if (encryptedSalt == null) {
      throw Exception('Did not receive encryptedSalt (sKey) from security details');
    }
    _log('Encrypted salt (sKey) received: ${encryptedSalt.substring(0, 20)}...');
    
    // Step 2: Perform client-side crypto operations
    _log('');
    _log('STEP 2: Performing client-side crypto operations');
    _log('   2.1: Decrypting salt...');
    final salt = _decryptTextWithKey(encryptedSalt, appCryptoSecret);
    _log('   Salt decrypted: $salt');
    
    _log('   2.2: Hashing password with PBKDF2-SHA1...');
    final hashObj = _passToHash(password, salt);
    _log('   Password hash: ${hashObj['hash']!.substring(0, 32)}...');
    
    _log('   2.3: Encrypting password hash...');
    final encryptedPasswordHash = _encryptTextWithKey(hashObj['hash']!, appCryptoSecret);
    _log('   Encrypted password hash: ${encryptedPasswordHash.substring(0, 32)}...');
    
    _log('   2.4: Generating placeholder PGP keys...');
    final keysPayload = _generateKeys(password);
    _log('   Keys generated successfully');
    
    // Step 3: Construct login payload
    _log('');
    _log('STEP 3: Constructing login payload');
    final loginPayload = {
      'email': email.toLowerCase(),
      'password': encryptedPasswordHash,
      'tfa': tfaCode,
      'keys': {
        'ecc': {
          'publicKey': keysPayload['ecc']['publicKey'],
          'privateKey': keysPayload['ecc']['privateKeyEncrypted'],
        },
        'kyber': keysPayload['kyber'],
      },
      'privateKey': keysPayload['privateKeyEncrypted'],
      'publicKey': keysPayload['publicKey'],
      'revocationKey': keysPayload['revocationCertificate'],
    };
    
    // Step 4: Make login request
    _log('');
    _log('STEP 4: Making login request');
    final loginUrl = Uri.parse('$driveApiUrl/auth/login/access');
    _log('Login URL: POST $loginUrl');
    
    final response = await http.post(
      loginUrl,
      headers: {'Content-Type': 'application/json'},
      body: json.encode(loginPayload),
    );
    
    _log('Login response status: ${response.statusCode}');
    
    if (response.statusCode != 200) {
      _log('Login failed!');
      _log('Response body: ${response.body}');
      throw Exception('Login failed: ${response.statusCode} - ${response.body}');
    }
    
    _log('Login response received successfully');
    final data = json.decode(response.body);
    _log('Response data keys: ${data.keys}');
    
    final authToken = data['token'];
    final newToken = data['newToken'];
    _log('Tokens extracted: token=${authToken != null}, newToken=${newToken != null}');
    
    // Step 5: Extract and decrypt user data
    _log('');
    _log('STEP 5: Processing user data');
    final user = data['user'];
    final userEmail = user['email'];
    final userId = user['userId'] ?? user['uuid'];
    final rootFolderId = user['rootFolderId'];
    final bucketId = user['bucket'];
    
    _log('User info extracted:');
    _log('   Email: $userEmail');
    _log('   User ID: $userId');
    _log('   Root Folder ID: $rootFolderId');
    _log('   Bucket ID: $bucketId');
    
    final encryptedMnemonic = user['mnemonic'];
    if (encryptedMnemonic == null) {
      throw Exception('Mnemonic not found in user data');
    }
    
    // Step 6: Decrypt mnemonic
    _log('');
    _log('STEP 6: Decrypting mnemonic');
    final mnemonic = _decryptTextWithKey(encryptedMnemonic, password);
    
    // Step 7: Validate mnemonic
    _log('');
    _log('STEP 7: Validating mnemonic');
    if (!bip39.validateMnemonic(mnemonic)) {
      throw Exception('Decrypted mnemonic is invalid');
    }
    _log('Mnemonic validated successfully');
    
    _log('');
    _log('========================================');
    _log('Login completed successfully!');
    _log('========================================');

    return {
      'email': userEmail,
      'token': authToken,
      'newToken': newToken,
      'mnemonic': mnemonic,
      'userId': userId,
      'rootFolderId': rootFolderId,
      // We must save bridgeUser and userId for downloads
      'bridgeUser': user['bridgeUser'],
      'userIdForAuth': user['userId'],
      'bucketId': bucketId,
    };
  }
  
  Future<Map<String, dynamic>> _getSecurityDetails(String email) async {
    final url = Uri.parse('$driveApiUrl/auth/login');
    _log('POST $url (for security details)');
    
    final response = await http.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: json.encode({'email': email}),
    );
    
    _log('Security details response: ${response.statusCode}');
    
    if (response.statusCode != 200) {
      _log('Security details body: ${response.body}');
      throw Exception('Failed to get security details: ${response.statusCode} - ${response.body}');
    }
    
    return json.decode(response.body);
  }
  
  /// Pass to hash
  Map<String, String> _passToHash(String password, String salt) {
    _log('_passToHash: password length=${password.length}, salt=$salt');
    
    final saltBytes = HEX.decode(salt);
    final passwordBytes = Uint8List.fromList(utf8.encode(password));
    
    // PBKDF2-HMAC-SHA1, 10000 iterations, 32 bytes output
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA1Digest(), 64))
      ..init(Pbkdf2Parameters(Uint8List.fromList(saltBytes), 10000, 32));
    
    final hashBytes = pbkdf2.process(passwordBytes);
    final hashHex = HEX.encode(hashBytes);
    
    _log('_passToHash: hash length=${hashHex.length}');
    
    return {'salt': salt, 'hash': hashHex};
  }
  
  /// Generate placeholder keys
  Map<String, dynamic> _generateKeys(String password) {
    _log('_generateKeys: Encrypting with password as key');
    
    // Use PASSWORD as the key
    final encryptedPk = _encryptTextWithKey('placeholder-private-key-for-login', password);
    
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
  
  /// Encrypt text with key
  /// OpenSSL-compatible format: Salted__ + salt + encrypted
  /// Uses MD5-based key derivation (3 rounds)
  String _encryptTextWithKey(String textToEncrypt, String secret) {
    _log('_encryptTextWithKey: text length=${textToEncrypt.length}');
    
    // Generate random 8-byte salt
    final random = Random.secure();
    final salt = Uint8List.fromList(List.generate(8, (_) => random.nextInt(256)));
    
    // Get key and IV using MD5-based derivation (OpenSSL format)
    final keyIv = _getKeyAndIvFrom(secret, salt);
    final key = keyIv['key']!;
    final iv = keyIv['iv']!;
    
    _log('_encryptTextWithKey: salt=${HEX.encode(salt)}, key length=${key.length}, iv length=${iv.length}');
    
    // Encrypt using AES-256-CBC
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
    
    // Create OpenSSL format: Salted__ + salt + encrypted
    final result = Uint8List(16 + encrypted.length);
    result.setAll(0, utf8.encode('Salted__'));  // 8 bytes
    result.setAll(8, salt);  // 8 bytes
    result.setAll(16, encrypted);
    
    final hexResult = HEX.encode(result);
    _log('_encryptTextWithKey: result length=${hexResult.length}');
    
    return hexResult;
  }
  
  /// Decrypt text with key
  String _decryptTextWithKey(String encryptedText, String secret) {
    _log('_decryptTextWithKey: encrypted length=${encryptedText.length}');
    
    // Decode from hex
    final cipherBytes = Uint8List.fromList(HEX.decode(encryptedText));
    
    // Extract salt (bytes 8-16)
    final salt = cipherBytes.sublist(8, 16);
    
    _log('_decryptTextWithKey: salt=${HEX.encode(salt)}');
    
    // Get key and IV using MD5-based derivation (OpenSSL format)
    final keyIv = _getKeyAndIvFrom(secret, salt);
    final key = keyIv['key']!;
    final iv = keyIv['iv']!;
    
    // Decrypt using AES-256-CBC
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
    _log('_decryptTextWithKey: decrypted length=${result.length}');
    
    return result;
  }
  
  /// Get key and IV from secret and salt
  /// Uses MD5-based key derivation (3 rounds) - OpenSSL compatible
  Map<String, Uint8List> _getKeyAndIvFrom(String secret, Uint8List salt) {
    _log('_getKeyAndIvFrom: secret length=${secret.length}, salt length=${salt.length}');
    
    // Convert secret to Latin-1 bytes
    final secretBytes = latin1.encode(secret);
    final password = Uint8List(secretBytes.length + salt.length);
    password.setAll(0, secretBytes);
    password.setAll(secretBytes.length, salt);
    
    final md5Hashes = <Uint8List>[];
    Uint8List digest = password;
    
    // MD5 three times
    for (var i = 0; i < 3; i++) {
      final md5 = MD5Digest();
      md5.update(digest, 0, digest.length);
      final hash = Uint8List(md5.digestSize);
      md5.doFinal(hash, 0);
      md5Hashes.add(hash);
      
      // For next iteration: hash + password
      digest = Uint8List(hash.length + password.length);
      digest.setAll(0, hash);
      digest.setAll(hash.length, password);
    }
    
    // key = md5Hashes[0] + md5Hashes[1] (32 bytes)
    final key = Uint8List(32);
    key.setAll(0, md5Hashes[0]);
    key.setAll(16, md5Hashes[1]);
    
    // iv = md5Hashes[2] (16 bytes)
    final iv = md5Hashes[2];
    
    _log('_getKeyAndIvFrom: key length=${key.length}, iv length=${iv.length}');
    
    return {'key': key, 'iv': iv};
  }

  // --- List Operations ---
  
  Future<List<Map<String, dynamic>>> listFolders(String folderId) async {
    final url = Uri.parse('$driveApiUrl/folders/content/$folderId/folders');
    
    final response = await http.get(
      url.replace(queryParameters: {
        'offset': '0',
        'limit': '50',
        'sort': 'plainName',
        'direction': 'ASC'
      }),
      headers: {'Authorization': 'Bearer $newToken'},
    );
    
    if (response.statusCode != 200) {
      _log('List folders response: ${response.statusCode}');
      _log('List folders body: ${response.body}');
      throw Exception('Failed to list folders: ${response.statusCode}');
    }
    
    final data = json.decode(response.body);
    final List<Map<String, dynamic>> items = [];
    
    final folders = data['result'] ?? data['folders'] ?? [];
    for (var folder in folders) {
      items.add({
        'type': 'folder',
        'name': folder['plainName'] ?? folder['name'],
        'uuid': folder['uuid'] ?? folder['id'],
        'size': 0, // Folders don't have size
      });
    }
    return items;
  }

  Future<List<Map<String, dynamic>>> listFolderFiles(String folderId) async {
    final url = Uri.parse('$driveApiUrl/folders/content/$folderId/files');
    
    final response = await http.get(
      url.replace(queryParameters: {
        'offset': '0',
        'limit': '50',
        'sort': 'plainName',
        'direction': 'ASC'
      }),
      headers: {'Authorization': 'Bearer $newToken'},
    );
    
    if (response.statusCode != 200) {
      _log('List files response: ${response.statusCode}');
      _log('List files body: ${response.body}');
      throw Exception('Failed to list files: ${response.statusCode}');
    }
    
    final data = json.decode(response.body);
    final List<Map<String, dynamic>> items = [];
    
    final files = data['result'] ?? data['files'] ?? [];
    for (var file in files) {
      // Return the raw metadata fields, we need this for resolvePath to work correctly
      items.add({
        'type': 'file',
        'name': file['plainName'] ?? file['name'], // 'name' holds plainName
        'fileType': file['type'] ?? '', // 'fileType' holds the extension
        'uuid': file['uuid'] ?? file['id'],
        'size': file['size'],
        'bucket': file['bucket'],
        'fileId': file['fileId'],
      });
    }
    return items;
  }

  Future<Map<String, dynamic>> resolvePath(String path) async {
    if (this.rootFolderId == null) {
      throw Exception("Root folder ID is not set. Please log in.");
    }
    String currentFolderUuid = this.rootFolderId!;
    
    // Clean up path
    var cleanPath = path.trim();
    if (cleanPath.startsWith('/')) {
      cleanPath = cleanPath.substring(1);
    }
    
    // Handle root path
    if (cleanPath.isEmpty) {
      return {
        'type': 'folder',
        'uuid': currentFolderUuid,
        'metadata': {'uuid': currentFolderUuid, 'name': 'Root'},
        'path': '/'
      };
    }
    
    final pathParts = cleanPath.split('/').where((part) => part.isNotEmpty).toList();
    
    for (var i = 0; i < pathParts.length; i++) {
      final part = pathParts[i];
      final isLastPart = (i == pathParts.length - 1);
      
      // Get content of the current folder
      final folders = await listFolders(currentFolderUuid);
      
      Map<String, dynamic>? foundFolder;
      for (var folder in folders) {
        if (folder['name'] == part) {
          foundFolder = folder;
          break;
        }
      }
      
      Map<String, dynamic>? foundFile;
      if (isLastPart) {
        final files = await listFolderFiles(currentFolderUuid);
        for (var file in files) {
          final plainName = file['name'] ?? '';
          final fileType = file['fileType'] ?? '';
          final fullName = fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
          
          if (plainName == part || fullName == part) {
            foundFile = file;
            break;
          }
        }
      }
      
      if (foundFolder != null && (!isLastPart || foundFile == null)) {
        // It's a folder, and we descend
        currentFolderUuid = foundFolder['uuid'];
        if (isLastPart) {
          return {
            'type': 'folder',
            'uuid': foundFolder['uuid'],
            'metadata': foundFolder,
          };
        }
      } else if (foundFile != null && isLastPart) {
        // It's a file, and it's the last part
        return {
          'type': 'file',
          'uuid': foundFile['uuid'],
          'metadata': foundFile,
        };
      } else {
        // Not found
        final currentPath = '/' + pathParts.sublist(0, i + 1).join('/');
        throw Exception("Path not found: $currentPath");
      }
    }
    
    // This should only be reached if the path was empty, but we handled that.
    // Return root just in case.
    return {
      'type': 'folder',
      'uuid': this.rootFolderId!,
      'metadata': {'uuid': this.rootFolderId!, 'name': 'Root'},
      'path': '/'
    };
  }
  
  // --- Download Operations ---

  Future<Map<String, dynamic>> downloadFile(
    String fileUuid,
    String bridgeUser,
    String userIdForAuth, {
    bool preserveTimestamps = false, // ADDED
  }) async {
    _log('Starting file download: $fileUuid');
    
    print('   📋 Fetching file metadata...');
    final metadataUrl = Uri.parse('$driveApiUrl/files/$fileUuid/meta');
    
    final metadataResponse = await http.get(
      metadataUrl,
      headers: {'Authorization': 'Bearer $newToken'},
    );
    
    if (metadataResponse.statusCode != 200) {
      _log('Metadata body: ${metadataResponse.body}');
      throw Exception('Failed to get metadata: ${metadataResponse.statusCode}');
    }
    
    final metadata = json.decode(metadataResponse.body);
    final bucketId = metadata['bucket'];
    final networkFileId = metadata['fileId'];
    
    final fileSize = metadata['size'] is int 
        ? metadata['size'] as int
        : int.tryParse(metadata['size'].toString()) ?? 0;
        
    final fileName = metadata['plainName'] ?? 'file';
    final fileType = metadata['type'] ?? '';
    final filename = fileType.isNotEmpty ? '$fileName.$fileType' : fileName;

    // ADDED: Get timestamps from metadata
    String? modificationTime = metadata['modificationTime'] ?? metadata['updatedAt'];

    print('   📄 File: $filename');
    print('   📊 Size: ${formatSize(fileSize)}');
    
    final networkAuth = _getNetworkAuth(bridgeUser, userIdForAuth);
    final networkUser = networkAuth['user']!;
    final networkPass = networkAuth['pass']!;
    
    print('   🔗 Fetching download links...');
    final linksResponse = await _getDownloadLinks(bucketId, networkFileId, networkUser, networkPass);
    final downloadUrl = linksResponse['shards'][0]['url'];
    final fileIndexHex = linksResponse['index'];
    
    print('   ☁️  Downloading encrypted data...');
    final downloadResponse = await http.get(Uri.parse(downloadUrl));
    
    if (downloadResponse.statusCode != 200) {
      throw Exception('Failed to download file: ${downloadResponse.statusCode}');
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

    // Return all info needed
    return {
      'data': trimmedData,
      'filename': filename,
      'modificationTime': modificationTime, // ADDED
      'preserveTimestamps': preserveTimestamps, // ADDED
    };
  }

  // NEW: Add shouldIncludeFile (port of drive.py)
  bool shouldIncludeFile(
    String fileName,
    List<String> include,
    List<String> exclude,
  ) {
    // If include patterns specified, file must match at least one
    if (include.isNotEmpty) {
      final matchesInclude = include.any((pattern) => Glob(pattern).matches(fileName));
      if (!matchesInclude) {
        return false;
      }
    }
    
    // If exclude patterns specified, file must not match any
    if (exclude.isNotEmpty) {
      final matchesExclude = exclude.any((pattern) => Glob(pattern).matches(fileName));
      if (matchesExclude) {
        return false;
      }
    }
    
    return true;
  }

  // NEW: Add downloadPath (port of Python's download_path)
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
  }) async {
    // 1. Resolve remote path
    final itemInfo = await resolvePath(remotePath);
    
    // 2. Handle FILE download
    if (itemInfo['type'] == 'file') {
      _log('Path resolved to a file. Starting single file download.');
      
      final metadata = itemInfo['metadata'] as Map<String, dynamic>;
      final plainName = metadata['name'] ?? 'file';
      final fileType = metadata['fileType'] ?? '';
      final remoteFilename = fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
      
      // Check filters
      if (!shouldIncludeFile(remoteFilename, include, exclude)) {
        print('🚫 File filtered out by include/exclude patterns: $remoteFilename');
        return;
      }
      
      // Determine local path
      String localPath;
      if (localDestination != null) {
        final destFile = File(localDestination);
        if (await destFile.parent.exists()) {
          localPath = localDestination; // Assume it's a full file path
        } else {
          localPath = p.join(localDestination, remoteFilename);
        }
      } else {
        localPath = remoteFilename;
      }
      
      final localFile = File(localPath);

      // Check conflict
      if (await localFile.exists() && onConflict == 'skip') {
        print('⏭️  File exists, skipping: $localPath');
        return;
      }
      
      // Download
      final downloadResult = await downloadFile(
        itemInfo['uuid'],
        bridgeUser,
        userIdForAuth,
        preserveTimestamps: preserveTimestamps,
      );
      
      // Save file
      await localFile.parent.create(recursive: true);
      await localFile.writeAsBytes(downloadResult['data']);
      
      // Preserve timestamps if requested
      if (downloadResult['preserveTimestamps'] == true &&
          downloadResult['modificationTime'] != null) {
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
    
    // 3. Handle FOLDER download
    if (itemInfo['type'] == 'folder') {
      if (!recursive) {
        throw Exception("'$remotePath' is a folder. Use -r to download recursively.");
      }
      
      _log('Path resolved to a folder. Starting recursive download.');
      
      // Determine base destination
      String baseDestPath;
      if (localDestination != null) {
        baseDestPath = localDestination;
      } else {
        final folderName = itemInfo['metadata']['name'] ?? 'download';
        baseDestPath = folderName;
      }
      
      final baseDestDir = Directory(baseDestPath);
      await baseDestDir.create(recursive: true);
      
      print('📂 Downloading folder recursively: $remotePath');
      print('💾 Target directory: ${baseDestDir.path}');

      // Call recursive helper
      await _downloadFolderRecursive(
        itemInfo['uuid'],
        baseDestDir,
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
        onConflict: onConflict,
        preserveTimestamps: preserveTimestamps,
        include: include,
        exclude: exclude,
      );
      
      print('\n🎉 Folder download complete!');
    }
  }

  // NEW: Add _downloadFolderRecursive (port of drive.py)
  Future<void> _downloadFolderRecursive(
    String folderUuid,
    Directory currentDest, {
    required String bridgeUser,
    required String userIdForAuth,
    required String onConflict,
    required bool preserveTimestamps,
    required List<String> include,
    required List<String> exclude,
  }) async {
    // 1. Get folder contents
    final files = await listFolderFiles(folderUuid);
    final folders = await listFolders(folderUuid);
    
    // 2. Download files in this folder
    for (var fileInfo in files) {
      final plainName = fileInfo['name'] ?? 'file';
      final fileType = fileInfo['fileType'] ?? '';
      final fileName = fileType.isNotEmpty ? '$plainName.$fileType' : plainName;
      
      // Apply filters
      if (!shouldIncludeFile(fileName, include, exclude)) {
        _log('   🚫 Filtered: $fileName');
        continue;
      }
      
      final fileDest = File(p.join(currentDest.path, fileName));
      
      // Check conflict
      if (await fileDest.exists() && onConflict == 'skip') {
        print('   ⏭️  Skipping existing: $fileName');
        continue;
      }
      
      try {
        print('   -> Downloading: $fileName');
        final downloadResult = await downloadFile(
          fileInfo['uuid'],
          bridgeUser,
          userIdForAuth,
          preserveTimestamps: preserveTimestamps,
        );
        
        await fileDest.writeAsBytes(downloadResult['data']);
        
        // Preserve timestamps if requested
        if (downloadResult['preserveTimestamps'] == true &&
            downloadResult['modificationTime'] != null) {
          try {
            final mTime = DateTime.parse(downloadResult['modificationTime']);
            await fileDest.setLastModified(mTime);
            _log('   🕐 Set modification time: $mTime');
          } catch (e) {
            _log('   ⚠️  Could not set modification time: $e');
          }
        }
      } catch (e) {
        print('   -> ❌ Error downloading $fileName: $e');
      }
    }
    
    // 3. Recurse into subfolders
    for (var folderInfo in folders) {
      final folderName = folderInfo['name'] ?? 'subfolder';
      final subfolderDest = Directory(p.join(currentDest.path, folderName));
      await subfolderDest.create(recursive: true);
      
      print('📂 Entering folder: $folderName');
      
      await _downloadFolderRecursive(
        folderInfo['uuid'],
        subfolderDest,
        bridgeUser: bridgeUser,
        userIdForAuth: userIdForAuth,
        onConflict: onConflict,
        preserveTimestamps: preserveTimestamps,
        include: include,
        exclude: exclude,
      );
    }
  }


  // --- UPLOAD / REMOVE LOGIC ---

  Future<Map<String, dynamic>> _createFolder(String name, String parentFolderUuid) async {
    final url = Uri.parse('$driveApiUrl/folders');
    final data = {'plainName': name, 'parentFolderUuid': parentFolderUuid};
    _log('POST $url (create folder $name)');
    
    final response = await http.post(
      url,
      headers: {
        'Authorization': 'Bearer $newToken',
        'Content-Type': 'application/json',
      },
      body: json.encode(data),
    );
    
    if (response.statusCode != 200 && response.statusCode != 201) {
      _log('Create folder failed: ${response.body}');
      throw Exception('Failed to create folder: ${response.statusCode}');
    }
    return json.decode(response.body);
  }

  Future<Map<String, dynamic>> createFolderRecursive(String path) async {
    if (this.rootFolderId == null) {
      throw Exception("Not logged in");
    }
    
    var cleanPath = path.trim().replaceAll(RegExp(r'^/+|/+$'), '');
    if (cleanPath.isEmpty) {
      return {'uuid': rootFolderId, 'plainName': 'Root'};
    }
    
    var parts = cleanPath.split('/');
    var currentParentUuid = rootFolderId!;
    var currentPathSoFar = '/';
    Map<String, dynamic>? foundFolder;
    
    for (var part in parts) {
      if (part.isEmpty) continue;
      
      foundFolder = null;
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
          currentPathSoFar = '$currentPathSoFar/$part'.replaceAll('//', '/');
        } else {
          print('  -> Creating intermediate folder: $part in $currentPathSoFar');
          final newFolder = await _createFolder(part, currentParentUuid);
          currentParentUuid = newFolder['uuid'];
          currentPathSoFar = '$currentPathSoFar/$part'.replaceAll('//', '/');
          foundFolder = newFolder;
        }
      } catch (e) {
        throw Exception("Failed to resolve or create folder part '$part' in '$currentPathSoFar': $e");
      }
    }
    return foundFolder!; // Will be the last folder found or created
  }

  Future<void> _deleteFilePermanently(String fileUuid) async {
    final url = Uri.parse('$driveApiUrl/files/$fileUuid');
    _log('DELETE $url');
    final response = await http.delete(
      url,
      headers: {'Authorization': 'Bearer $newToken'},
    );
    if (response.statusCode != 200) {
      _log('Delete file failed: ${response.body}');
      // Don't throw, just log. Overwrite should proceed.
    }
  }

  Future<void> _deleteFolderPermanently(String folderUuid) async {
    final url = Uri.parse('$driveApiUrl/folders/$folderUuid');
    _log('DELETE $url');
    final response = await http.delete(
      url,
      headers: {'Authorization': 'Bearer $newToken'},
    );
    if (response.statusCode != 200) {
      _log('Delete folder failed: ${response.body}');
    }
  }

  Future<Map<String, dynamic>> _startUpload(String bucketId, int fileSize, String user, String pass) async {
    final url = Uri.parse('$networkUrl/v2/buckets/$bucketId/files/start?multiparts=1');
    final data = {'uploads': [{'index': 0, 'size': fileSize}]};
    _log('POST $url (start upload)');
    
    final response = await http.post(
      url,
      headers: {
        'Authorization': 'Basic ${base64Encode(utf8.encode('$user:$pass'))}',
        'Content-Type': 'application/json',
      },
      body: json.encode(data),
    );
    
    if (response.statusCode != 200) {
      _log('Start upload failed: ${response.body}');
      throw Exception('Failed to start upload: ${response.statusCode}');
    }
    return json.decode(response.body);
  }

  Future<void> _uploadChunk(String uploadUrl, Uint8List chunkData) async {
    _log('PUT $uploadUrl (uploading chunk)');
    final response = await http.put(
      Uri.parse(uploadUrl),
      headers: {'Content-Type': 'application/octet-stream'},
      body: chunkData,
    );
    
    if (response.statusCode != 200) {
      _log('Upload chunk failed: ${response.body}');
      throw Exception('Failed to upload chunk: ${response.statusCode}');
    }
  }

  Future<Map<String, dynamic>> _finishUpload(String bucketId, Map<String, dynamic> payload, String user, String pass) async {
    final url = Uri.parse('$networkUrl/v2/buckets/$bucketId/files/finish');
    _log('POST $url (finish upload)');
    
    final response = await http.post(
      url,
      headers: {
        'Authorization': 'Basic ${base64Encode(utf8.encode('$user:$pass'))}',
        'Content-Type': 'application/json',
      },
      body: json.encode(payload),
    );
    
    if (response.statusCode != 200) {
      _log('Finish upload failed: ${response.body}');
      throw Exception('Failed to finish upload: ${response.statusCode}');
    }
    return json.decode(response.body);
  }

  Future<Map<String, dynamic>> _createFileEntry(Map<String, dynamic> payload) async {
    final url = Uri.parse('$driveApiUrl/files');
    _log('POST $url (create file entry)');
    
    final response = await http.post(
      url,
      headers: {
        'Authorization': 'Bearer $newToken',
        'Content-Type': 'application/json',
      },
      body: json.encode(payload),
    );
    
    if (response.statusCode != 200 && response.statusCode != 201) {
      _log('Create file entry failed: ${response.body}');
      throw Exception('Failed to create file entry: ${response.statusCode}');
    }
    return json.decode(response.body);
  }

  Future<void> trashItems(String uuid, String type) async {
    final url = Uri.parse('$driveApiUrl/storage/trash/add');
    final payload = {
      'items': [
        {'uuid': uuid, 'type': type}
      ]
    };
    _log('POST $url (trashing item $uuid)');
    
    final response = await http.post(
      url,
      headers: {
        'Authorization': 'Bearer $newToken',
        'Content-Type': 'application/json',
      },
      body: json.encode(payload),
    );
    
    if (response.statusCode != 200 && response.statusCode != 201) {
      _log('Trash item failed: ${response.body}');
      throw Exception('Failed to trash item: ${response.statusCode}');
    }
  }

  Future<void> deletePermanently(String uuid, String type) async {
    final url = Uri.parse('$driveApiUrl/storage/trash');
    final payload = {
      'items': [
        {'uuid': uuid, 'type': type}
      ]
    };
    _log('DELETE $url (deleting item $uuid)');
    
    // http.delete does not natively support a body.
    // We must build the request manually.
    final request = http.Request('DELETE', url)
      ..headers.addAll({
        'Authorization': 'Bearer $newToken',
        'Content-Type': 'application/json',
      })
      ..body = json.encode(payload);
      
    final response = await request.send();
    
    if (response.statusCode != 200) {
      final responseBody = await response.stream.bytesToString();
      _log('Delete item failed: $responseBody');
      throw Exception('Failed to delete item: ${response.statusCode}');
    }
  }

  Future<Map<String, dynamic>> _uploadFile(
      File localFile,
      String destinationFolderUuid,
      String remoteFileName, {
        required String bridgeUser,
        required String userIdForAuth,
        String? creationTime,
        String? modificationTime,
      }) async {
      // We use the bucketId from credentials
      if (this.bucketId == null) {
        throw Exception("Bucket ID not found in credentials. Please login again.");
      }
      final bucketId = this.bucketId!;

      if (this.mnemonic == null) throw Exception("Not logged in");

      final networkAuth = _getNetworkAuth(bridgeUser, userIdForAuth);
      // ... (rest of the function is correct) ...
      final networkUser = networkAuth['user']!;
      final networkPass = networkAuth['pass']!;
      
      final fileBytes = await localFile.readAsBytes();
      final fileSize = fileBytes.length;
      
      print("     📤 Uploading '$remoteFileName' (${formatSize(fileSize)})...");
      
      // 1. Encrypt
      _log("     🔐 Encrypting with exact protocol");
      // This call will now use the correct bucketId
      final encryptedResult = _encryptStream(fileBytes, mnemonic!, bucketId);
      final encryptedData = encryptedResult['data']!;
      final fileIndexHex = encryptedResult['index']!;
      
      // 2. Start
      _log("     🚀 Initializing network upload");
      final startResponse = await _startUpload(bucketId, encryptedData.length, networkUser, networkPass);
      final uploadUrl = startResponse['uploads'][0]['url'];
      final fileNetworkUuid = startResponse['uploads'][0]['uuid'];
      
      // 3. Upload
      _log("     ☁️  Uploading encrypted data");
      await _uploadChunk(uploadUrl, encryptedData);
      
      // 4. Finish
      _log("     ✅ Finalizing network upload");
      final encryptedHash = crypto.sha256.convert(encryptedData).toString();
      final finishPayload = {
        'index': fileIndexHex,
        'shards': [{'hash': encryptedHash, 'uuid': fileNetworkUuid}]
      };
      final finishResponse = await _finishUpload(bucketId, finishPayload, networkUser, networkPass);
      final networkFileId = finishResponse['id'];
      
      // 5. Create Entry
      _log("     📋 Creating file metadata");
      final plainName = p.basenameWithoutExtension(remoteFileName);
      final fileType = p.extension(remoteFileName).replaceAll('.', '');
      
      final fileEntryPayload = <String, dynamic>{
        'folderUuid': destinationFolderUuid,
        'plainName': plainName,
        'type': fileType,
        'size': fileSize,
        'bucket': bucketId, 
        'fileId': networkFileId,
        'encryptVersion': 'Aes03', 
        'name': '', 
      };
      
      if (creationTime != null) {
        fileEntryPayload['creationTime'] = creationTime;
        _log("     🕐 Added creationTime to payload");
      }
      if (modificationTime != null) {
        fileEntryPayload['modificationTime'] = modificationTime;
        _log("     🕐 Added modificationTime to payload");
      }
      
      return await _createFileEntry(fileEntryPayload);
    }

  Future<String> _uploadSingleItem(
    File localFile,
    String targetRemoteParentPath,
    String targetFolderUuid,
    String onConflict, {
    required String bridgeUser,
    required String userIdForAuth,
    required bool preserveTimestamps,
    String? remoteFileName, 
  }) async {
    final effectiveRemoteFilename = remoteFileName ?? p.basename(localFile.path);
    final fullTargetRemotePath = p.join(targetRemoteParentPath, effectiveRemoteFilename).replaceAll('\\', '/');
    print("  -> Preparing upload: '${p.basename(localFile.path)}' to '$fullTargetRemotePath'");
    
    Map<String, dynamic>? existingItemInfo;
    try {
      existingItemInfo = await resolvePath(fullTargetRemotePath);
      print("  -> Target exists: $fullTargetRemotePath (Type: ${existingItemInfo['type']})");
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
          print("  -> ❌ Cannot overwrite folder with a file: $fullTargetRemotePath");
          return "error";
        } else {
          print("  -> 🔄 Overwriting existing file...");
          try {
            await _deleteFilePermanently(existingItemInfo['uuid']);
            print("  -> 🗑️  Deleted existing file for overwrite");
          } catch (delErr) {
            print("  -> ❌ Error deleting existing file for overwrite: $delErr");
            return "error";
          }
        }
      }
    }
    
    // --- Proceed with upload ---
    try {
      String? creationTime;
      String? modificationTime;
      
      if (preserveTimestamps) {
        try {
          final stat = await localFile.stat();
          modificationTime = stat.modified.toUtc().toIso8601String();
          creationTime = stat.changed.toUtc().toIso8601String(); // 'changed' is closest to 'creation'
          _log("     🕐 Preserving timestamps: Mod=$modificationTime, Cre=$creationTime");
        } catch (e) {
          _log("     ⚠️  Could not read timestamps: $e");
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
      print("  -> ❌ Error during upload: $upErr");
      return "error";
    }
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
  }) async {
    print("🎯 Preparing upload to remote path: $targetPath");

    // 1. Resolve or Create Target Folder
    Map<String, dynamic> targetFolderInfo;
    try {
      targetFolderInfo = await resolvePath(targetPath);
      if (targetFolderInfo['type'] != 'folder') {
        throw Exception("Target path '$targetPath' exists but is not a folder.");
      }
      print("✅ Target folder exists: '${targetFolderInfo['path'] ?? targetPath}'");
    } on Exception catch (e) {
      if (e.toString().contains("Path not found")) {
        print("⏳ Target path '$targetPath' not found. Attempting to create...");
        try {
          targetFolderInfo = await createFolderRecursive(targetPath);
          print("✅ Created target folder '$targetPath'");
        } catch (createErr) {
          throw Exception("Failed to create target folder '$targetPath': $createErr");
        }
      } else {
        throw e; // Re-throw other errors
      }
    }
    
    final targetFolderUuid = targetFolderInfo['uuid'] as String;
    final targetFolderPathStr = targetFolderInfo['path'] as String? ?? targetPath;
    
    // 2. Process Sources
    int successCount = 0;
    int skippedCount = 0;
    int errorCount = 0;
    
    for (final sourceArg in sources) {
      final hasTrailingSlash = sourceArg.endsWith('/') || sourceArg.endsWith('\\');
      
      // Expand wildcards
      final glob = Glob(sourceArg.replaceAll('\\', '/'));
      await for (final entity in glob.list()) {
        final localPath = File(entity.path);
        
        if (await localPath.exists()) {
          // It's a file
          
          // Apply filters
          if (!shouldIncludeFile(p.basename(localPath.path), include, exclude)) {
            print("🚫 Filtered out: ${localPath.path}");
            continue;
          }
          
          final result = await _uploadSingleItem(
            localPath,
            targetFolderPathStr,
            targetFolderUuid,
            onConflict,
            bridgeUser: bridgeUser,
            userIdForAuth: userIdForAuth,
            preserveTimestamps: preserveTimestamps,
            // remoteFilename is optional, so it's fine not to pass it here
          );
          if (result == "uploaded") successCount++;
          if (result == "skipped") skippedCount++;
          if (result == "error") errorCount++;
          
        } else if (await Directory(entity.path).exists()) {
          // It's a directory
          final localDir = Directory(entity.path);
          if (!recursive) {
            print("⚠️ Skipping directory (use -r to upload recursively): ${localDir.path}");
            skippedCount++;
            continue;
          }
          
          print("📂 Processing directory recursively: ${localDir.path}");
          
          // Determine remote base path for children
          String dirRemoteBasePath;
          if (hasTrailingSlash) {
            print("  ✨ Copying contents directly to target (trailing slash detected)");
            dirRemoteBasePath = targetFolderPathStr;
          } else {
            print("  📁 Creating folder '${p.basename(localDir.path)}' in target");
            dirRemoteBasePath = p.join(targetFolderPathStr, p.basename(localDir.path)).replaceAll('\\', '/');
          }
          
          final files = localDir.list(recursive: true, followLinks: false);
          await for (final fileEntity in files) {
            if (fileEntity is File) {
              final localFile = fileEntity;
              
              // Apply filters
              if (!shouldIncludeFile(p.basename(localFile.path), include, exclude)) {
                print("  -> 🚫 Filtered: ${localFile.path}");
                continue;
              }
              
              // Find relative path
              final relativePath = p.relative(localFile.path, from: localDir.path);
              final itemTargetParentPath = p.join(dirRemoteBasePath, p.dirname(relativePath)).replaceAll('\\', '/');
              final remoteFileName = p.basename(localFile.path);
              
              _log("  -> Found file: ${localFile.path}");
              _log("     Target parent path: $itemTargetParentPath");
              
              // Ensure parent folder exists
              Map<String, dynamic> parentFolderInfo;
              try {
                parentFolderInfo = await createFolderRecursive(itemTargetParentPath);
              } catch (createErr) {
                print("     ❌ Error ensuring parent folder $itemTargetParentPath: $createErr");
                errorCount++;
                continue;
              }
              
              final result = await _uploadSingleItem(
                localFile,
                itemTargetParentPath,
                parentFolderInfo['uuid'],
                onConflict,
                bridgeUser: bridgeUser,
                userIdForAuth: userIdForAuth,
                preserveTimestamps: preserveTimestamps,
                remoteFileName: remoteFileName,
              );
              if (result == "uploaded") successCount++;
              if (result == "skipped") skippedCount++;
              if (result == "error") errorCount++;
            }
          }
        }
      }
    }
    
    // 3. Summary
    print("=" * 40);
    print("📊 Upload Summary:");
    print("  ✅ Uploaded: $successCount");
    print("  ⏭️  Skipped:  $skippedCount");
    print("  ❌ Errors:   $errorCount");
    print("=" * 40);
  }
  
  Future<Map<String, dynamic>> _getDownloadLinks(String bucketId, String fileId, String user, String pass) async {
    final url = Uri.parse('$networkUrl/buckets/$bucketId/files/$fileId/info');
    _log('GET $url');
    
    final response = await http.get(
      url,
      headers: {
        'Authorization': 'Basic ${base64Encode(utf8.encode('$user:$pass'))}',
        // add required header
        'x-api-version': '2',
      },
    );
    
    if (response.statusCode != 200) {
      _log('Download links response: ${response.statusCode}');
      _log('Download links body: ${response.body}');
      throw Exception('Failed to get download links: ${response.statusCode}');
    }
    
    return json.decode(response.body);
  }

  Map<String, String> _getNetworkAuth(String bridgeUser, String userId) {
        // Note it does not call an API, it uses credentials from login.
        
        _log('Generating network auth from bridgeUser and userId');
        
        final hashedPassword = crypto.sha256.convert(utf8.encode(userId)).toString();
        
        return {
        'user': bridgeUser,
        'pass': hashedPassword,
        };
    }

  // --- File Crypto ---
  
  /// Get deterministic key (SHA512)
  Uint8List _getFileDeterministicKey(Uint8List key, Uint8List data) {
    final combined = Uint8List(key.length + data.length);
    combined.setAll(0, key);
    combined.setAll(key.length, data);
    
    return crypto.sha512.convert(combined).bytes as Uint8List;
  }
  
  /// Generate file bucket key
  Uint8List _generateFileBucketKey(String mnemonic, String bucketId) {
    // Convert List<int> from mnemonicToSeed to Uint8List
    final seed = Uint8List.fromList(bip39.mnemonicToSeed(mnemonic));
    
    // This needs to be Uint8List as well, which HEX.decode returns
    final bucketIdBytes = Uint8List.fromList(HEX.decode(bucketId)); 
    
    return _getFileDeterministicKey(seed, bucketIdBytes);
  }
  
  /// Generate file key
  Uint8List _generateFileKey(String mnemonic, String bucketId, Uint8List index) {
    final bucketKey = _generateFileBucketKey(mnemonic, bucketId);
    return _getFileDeterministicKey(
      bucketKey.sublist(0, 32),
      index,
    ).sublist(0, 32);
  }
  
  /// Decrypts file stream (AES-256-CTR)
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
    // Generate 32-byte random index
    final random = Random.secure();
    final index = Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)));
    
    // Generate file key
    final fileKey = _generateFileKey(mnemonic, bucketId, index);
    
    // Use first 16 bytes of index as IV
    final iv = index.sublist(0, 16);
    
    // Encrypt using AES-256-CTR
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

class ConfigService {
  late final String configDir;
  late final String credentialsFile;
  
  ConfigService() {
    final home = Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'] ?? '.';
    configDir = p.join(home, '.internxt-cli');
    credentialsFile = p.join(configDir, '.inxtcli-dart-creds.json');
    
    // Ensure config directory exists
    Directory(configDir).createSync(recursive: true);
  }
  
  Future<void> saveCredentials(Map<String, String?> credentials) async {
    final file = File(credentialsFile);
    await file.writeAsString(json.encode(credentials));
  }
  
  Future<Map<String, String>?> readCredentials() async {
    final file = File(credentialsFile);
    if (!await file.exists()) {
      return null;
    }
    
    try {
      final contents = await file.readAsString();
      final data = json.decode(contents) as Map<String, dynamic>;
      return data.map((k, v) => MapEntry(k, v.toString()));
    } catch (e) {
      return null;
    }
  }
  
  Future<void> clearCredentials() async {
    final file = File(credentialsFile);
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

  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
}