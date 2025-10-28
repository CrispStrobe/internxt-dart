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
      ..addFlag('uuids', help: 'Show full UUIDs in list command');
    
    final argResults = parser.parse(arguments);
    debugMode = argResults['debug'];
    client.debugMode = debugMode;
    
    final commandArgs = argResults.rest;

    if (commandArgs.isEmpty) {
      printWelcome();
      return;
    }
    
    final command = commandArgs[0];
    final args = commandArgs.sublist(1);
    
    try {
      switch (command) {
        case 'login':
          await handleLogin(args);
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
          await handleDownload(args);
          break;
        case 'download-path':
          await handleDownloadPath(args);
          break;
        case 'config':
          await handleConfig();
          break;
        case 'test':
          await handleTest();
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
    print('  download-path <path> Download a file by its path (e.g., /readme.md)');
    print('  config             Show configuration');
    print('  test               Run crypto tests');
    print('  help               Show this help message');
    print('');
    print('Options:');
    print('  --debug, -d        Enable debug output');
    print('  --uuids            Show full UUIDs in "list" command');
    print('');
    print('Examples:');
    print('  dart cli.dart login --debug');
    print('  dart cli.dart list');
    print('  dart cli.dart list --uuids');
    print('  dart cli.dart download <file-uuid-from-list>');
    print('  dart cli.dart download-path /readme.md');
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

  Future<void> handleDownloadPath(List<String> args) async {
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
      
      final path = args[0];
      print('🔍 Resolving path: $path');

      // 1. Resolve the path to get the item info
      final itemInfo = await client.resolvePath(path);
      
      if (itemInfo['type'] != 'file') {
        throw Exception("Path '$path' is a folder, not a file.");
      }

      final fileUuid = itemInfo['uuid'] as String;
      print('✅ Path resolved to file UUID: $fileUuid');
      
      // 2. Now call the existing download logic
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
  
  void _log(String message) {
    if (debugMode) {
      print('🔍 [DEBUG] $message');
    }
  }

  void setAuth(Map<String, String?> creds) {
    authToken = creds['token'];
    newToken = creds['newToken'];
    mnemonic = creds['mnemonic'];
    userEmail = creds['email'];
    userId = creds['userId'];
    rootFolderId = creds['rootFolderId'];
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
  Future<Map<String, String>> login(String email, String password, {String? tfaCode}) async {
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
    
    _log('User info extracted:');
    _log('   Email: $userEmail');
    _log('   User ID: $userId');
    _log('   Root Folder ID: $rootFolderId');
    
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

  Future<Map<String, dynamic>> downloadFile(String fileUuid, String bridgeUser, String userIdForAuth) async {
    _log('Starting file download: $fileUuid');
    
    // Step 1: Get file metadata
    print('   📋 Fetching file metadata...');
    final metadataUrl = Uri.parse('$driveApiUrl/files/$fileUuid/meta');
    _log('GET $metadataUrl');
    
    final metadataResponse = await http.get(
      metadataUrl,
      headers: {'Authorization': 'Bearer $newToken'},
    );
    
    _log('Metadata response: ${metadataResponse.statusCode}');
    if (metadataResponse.statusCode != 200) {
      _log('Metadata body: ${metadataResponse.body}');
      throw Exception('Failed to get metadata: ${metadataResponse.statusCode}');
    }
    
    final metadata = json.decode(metadataResponse.body);
    final bucketId = metadata['bucket'];
    final networkFileId = metadata['fileId'];
    
    // parse size to int
    final fileSize = metadata['size'] is int 
        ? metadata['size'] as int
        : int.tryParse(metadata['size'].toString()) ?? 0;
        
    final fileName = metadata['plainName'] ?? 'file';
    final fileType = metadata['type'] ?? '';
    final filename = fileType.isNotEmpty ? '$fileName.$fileType' : fileName;
    
    print('   📄 File: $filename');
    print('   📊 Size: ${formatSize(fileSize)}');
    
    // Step 2: Get network credentials
    final networkAuth = _getNetworkAuth(bridgeUser, userIdForAuth);
    final networkUser = networkAuth['user']!;
    final networkPass = networkAuth['pass']!;
    _log('Network auth obtained for user: $networkUser');
    
    // Step 3: Get download links
    print('   🔗 Fetching download links...');
    final linksResponse = await _getDownloadLinks(bucketId, networkFileId, networkUser, networkPass);
    final downloadUrl = linksResponse['shards'][0]['url'];
    final fileIndexHex = linksResponse['index'];
    _log('   🔗 Download URL acquired');
    
    // Step 4: Download encrypted data
    print('   ☁️  Downloading encrypted data...');
    _log('Downloading from: $downloadUrl');
    
    final downloadResponse = await http.get(Uri.parse(downloadUrl));
    
    if (downloadResponse.statusCode != 200) {
      throw Exception('Failed to download file: ${downloadResponse.statusCode}');
    }
    
    final encryptedData = downloadResponse.bodyBytes;
    _log('   ☁️  Downloaded ${formatSize(encryptedData.length)} encrypted');
    
    // Step 5: Decrypt
    print('   🔐 Decrypting...');
    final decryptedData = _decryptStream(
      encryptedData,
      mnemonic!,
      bucketId,
      fileIndexHex,
    );
    _log('   🔐 Decrypted ${formatSize(decryptedData.length)}');
    
    // Step 6: Trim to exact size
    final trimmedData = decryptedData.sublist(0, fileSize);
    
    return {'data': trimmedData, 'filename': filename};
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

  // --- File Decryption ---
  
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
  
  Future<void> saveCredentials(Map<String, String> credentials) async {
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