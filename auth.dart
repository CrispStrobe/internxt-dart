// Auth protocol — login, 2FA check, token refresh, bridge auth.
//
// Extracted from cli.dart in Phase 4. This module owns the *protocol*
// for authentication (the multi-step crypto + HTTP dance against the
// gateway). The orchestration that glues protocol output to
// InternxtClient instance state and to ConfigService persistence
// (`refreshToken`, `setAuth`) stays on InternxtClient.
//
// State convention (matches cache.dart, api.dart): no instance state
// lives here — callers pass the gateway URL, the app crypto secret,
// and any tokens explicitly.
//
// The login dance and the bridge-pass computation are wire-protocol
// surface: the live smoke suite exercises both on every run, so any
// regression here surfaces immediately.

import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:http/http.dart' as http;

import 'api.dart' as inxt_api;
import 'crypto.dart' as inxt_crypto;

/// Returns `true` if the account at [email] requires a 2FA code.
///
/// Errors degrade to `false` so the caller can attempt login normally
/// and surface a real error if it actually fails. This matches the
/// monolith behavior — a 2FA check failure should not block the whole
/// login flow.
Future<bool> is2faNeeded(String driveApiUrl, String email) async {
  final cleanEmail = email.toLowerCase().trim();
  try {
    final response = await inxt_api.makeRequest(
      'POST',
      Uri.parse('$driveApiUrl/auth/login'),
      body: json.encode({'email': cleanEmail}),
      useAuth: false,
    );
    final data = json.decode(response.body);
    return data['tfa'] == true;
  } catch (_) {
    return false;
  }
}

/// SHA-256 hex of [userId] — the bridge-storage password.
///
/// Computed on every login and on every token refresh (in case the
/// userId metadata changes). Kept as its own function to dedupe what
/// were two identical inline computations in the monolith.
String computeBridgePass(dynamic userId) =>
    crypto.sha256.convert(utf8.encode(userId.toString())).toString();

/// Multi-step login dance:
///   1. POST /auth/login           -> encrypted salt (sKey)
///   2. Decrypt salt; PBKDF2 password hash; encrypt for transport
///   3. POST /auth/login/access    -> initial session token (newToken)
///   4. GET  /users/refresh        -> hydrated user record
///   5. SHA-256 userId             -> bridgePass
///
/// Returns the credentials map ready to hand to `setAuth` and to
/// persist via `ConfigService.saveCredentials`. The hydration step
/// (4) is a direct `http.get` rather than going through
/// `inxt_api.makeRequest` because retry-on-5xx during a half-completed
/// login is worse than failing fast.
Future<Map<String, dynamic>> login(
  String driveApiUrl,
  String appCryptoSecret,
  String email,
  String password, {
  String? tfaCode,
}) async {
  final cleanEmail = email.toLowerCase().trim();

  final secRes = await inxt_api.makeRequest(
    'POST',
    Uri.parse('$driveApiUrl/auth/login'),
    body: json.encode({'email': cleanEmail}),
    useAuth: false,
  );
  final sKey = json.decode(secRes.body)['sKey'] as String?;
  if (sKey == null) throw Exception('Login failed: Salt (sKey) missing.');

  final salt = inxt_crypto.decryptTextWithKey(sKey, appCryptoSecret);
  final masterHash = inxt_crypto.passToHash(password, salt)['hash']!;
  final encryptedHash =
      inxt_crypto.encryptTextWithKey(masterHash, appCryptoSecret);
  final keysPayload = inxt_crypto.generateKeys(password);

  final accessRes = await inxt_api.makeRequest(
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

  final hydrationRes = await http.get(
    Uri.parse('$driveApiUrl/users/refresh'),
    headers: {
      'Authorization': 'Bearer $tempToken',
      'internxt-client': 'cli',
      'Content-Type': 'application/json',
    },
  );
  if (hydrationRes.statusCode != 200) {
    throw Exception('Hydration failed: ${hydrationRes.statusCode}');
  }
  final hydrated = json.decode(hydrationRes.body);
  final user = hydrated['user'];

  return {
    'email': user['email'],
    'token': hydrated['token'],
    'newToken': hydrated['newToken'],
    'mnemonic':
        inxt_crypto.decryptTextWithKey(user['mnemonic'] as String, password),
    'userId': user['userId'],
    'rootFolderId': user['rootFolderId'],
    'bridgeUser': user['bridgeUser'],
    'bridgePass': computeBridgePass(user['userId']),
    'bucketId': user['bucket'],
  };
}

/// GET /users/refresh with [currentNewToken] — returns the parsed
/// response. Throws on non-200 (and rewraps the wrapped exception
/// once more, preserving the monolith's double-wrapped error message
/// shape so any caller doing string-matching keeps working).
///
/// Like the hydration step in [login], this is a direct `http.get`
/// rather than going through `inxt_api.makeRequest`: the central
/// transport is meant to be safe to retry, but retrying refresh on
/// a transient 5xx can collide with the caller's `_isRefreshingToken`
/// lock.
Future<Map<String, dynamic>> apiRefreshToken(
  String driveApiUrl,
  String currentNewToken,
) async {
  try {
    final response = await http.get(
      Uri.parse('$driveApiUrl/users/refresh'),
      headers: {
        'Authorization': 'Bearer $currentNewToken',
        'Content-Type': 'application/json',
      },
    );
    if (response.statusCode != 200) {
      throw Exception('Token refresh failed: ${response.statusCode}');
    }
    return json.decode(response.body) as Map<String, dynamic>;
  } catch (e) {
    throw Exception('Token refresh failed: $e');
  }
}
