// Internxt crypto primitives — the trust root.
//
// All functions here are pure (no I/O, no auth state). Extracted from
// cli.dart in Phase 4. Coverage is anchored by test/crypto_test.dart.
//
// IMPORTANT: any change here is a wire-protocol change. Encrypted
// data already in production has to remain decryptable. The
// regression markers in test/crypto_test.dart pin:
//   - the OpenSSL "Salted__" envelope on credential text
//   - the deterministic SHA-512 derivation of bucket / file keys
//   - the AES-256-CTR length invariant
//   - the pointycastle empty-string limitation
//
// Don't add `log()` or other side effects to these functions. The
// log statements that lived here in the monolith were debug noise
// from development and were dropped during the extraction.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;
import 'package:crypto/crypto.dart' as crypto;
import 'package:dart_pg/dart_pg.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';

// Fixed IV + salt used to AES-256-GCM encrypt the OpenPGP private key in the
// login payload. These are public constants from the official Internxt CLI
// (.env.template -> CryptoUtils.getAesInit()); they MUST match for the server
// to accept the encrypted key.
const String appMagicIv = 'd139cb9a2cd17092e79e1861cf9d7023';
const String appMagicSalt =
    '38dce0391b49efba88dbc8c39ebf868f0267eb110bb0012ab27dc52a528'
    'd61b1d1ed9d76f400ff58e3240028442b1eab9bb84e111d9dadd997982dbde9dbd25e';

// --- Password / text crypto (AES-256-CBC + OpenSSL EVP_BytesToKey + MD5) ---

Map<String, String> passToHash(String password, String salt) {
  final saltBytes = HEX.decode(salt);
  final passwordBytes = Uint8List.fromList(utf8.encode(password));

  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA1Digest(), 64))
    ..init(Pbkdf2Parameters(Uint8List.fromList(saltBytes), 10000, 32));

  final hashBytes = pbkdf2.process(passwordBytes);
  return {'salt': salt, 'hash': HEX.encode(hashBytes)};
}

/// Generates a real OpenPGP Ed25519 (legacy) keypair for the login payload.
///
/// Internxt's server now validates these keys ("keys.ecc.publicKey is not a
/// valid OpenPGP public key"), so the old placeholder strings are rejected.
/// This mirrors the official CLI's KeysService.generateNewKeysWithEncrypted:
/// an EdDSA/Ed25519 primary key plus an ECDH/Curve25519 encryption subkey, with
/// the public key sent base64-encoded and the armored private key AES-256-GCM
/// encrypted under the password (fixed magic IV/salt).
///
/// Fresh keys are generated on every login (as the official SDK does); the
/// server preserves any pre-existing account keys, so this is non-destructive.
/// Generates a fresh locked dart_pg Ed25519 private key. The default
/// production implementation; overridable in tests via [generateKeys]'s
/// `keyGenerator` seam.
// Returns a freshly generated *locked* dart_pg Ed25519 private key. Typed
// `dynamic` because dart_pg's key interface type isn't exported from its
// public library; the only member we call is `.decrypt(passphrase)`.
dynamic _generateLockedPgpKey(String passphrase) => OpenPGP.generateKey(
      ['inxt@inxt.com'],
      passphrase,
      type: KeyType.ecc,
      curve: Ecc.ed25519,
    );

Map<String, dynamic> generateKeys(String password,
    {dynamic Function(String passphrase)? keyGenerator}) {
  // dart_pg requires a passphrase to generate; we immediately decrypt to get
  // the unencrypted armored private key, matching openpgp.js (no passphrase),
  // then re-encrypt it ourselves with the Internxt AES-GCM scheme.
  const tmpPassphrase = 'internxt-cli-ephemeral';
  final genKey = keyGenerator ?? _generateLockedPgpKey;

  // dart_pg's OpenPGP.generateKey is intermittently flaky: for some random
  // Ed25519 keys its own subkey-binding-signature verification (run during
  // generation) trips a RangeError in Helper.readMPI — an MPI whose declared
  // bit-length doesn't match its byte length. Generation is nondeterministic,
  // so a freshly generated key almost always succeeds. Retry a bounded number
  // of times before surfacing the failure, rather than failing the whole login
  // on a transient library quirk.
  Object? lastError;
  for (var attempt = 0; attempt < 8; attempt++) {
    try {
      final locked = genKey(tmpPassphrase);
      final privateKey = locked.decrypt(tmpPassphrase);
      // `privateKey` is dynamic (dart_pg's key interface isn't exported);
      // .armor() returns the armored text — cast to String for the gate.
      final privateKeyArmored = privateKey.armor() as String;
      final publicKeyArmored = privateKey.publicKey.armor() as String;

      final publicKeyB64 = base64.encode(utf8.encode(publicKeyArmored));
      final privateKeyEncrypted = internxtAesGcmEncrypt(
          privateKeyArmored, password, appMagicIv, appMagicSalt);

      return {
        'privateKeyEncrypted': privateKeyEncrypted,
        'publicKey': publicKeyB64,
        'revocationCertificate': '',
        'ecc': {
          'publicKey': publicKeyB64,
          'privateKeyEncrypted': privateKeyEncrypted,
        },
        'kyber': {
          'publicKey': null,
          'privateKeyEncrypted': null,
        },
      };
    } catch (e) {
      lastError = e;
      // fall through and regenerate a fresh key
    }
  }
  throw Exception(
      'OpenPGP key generation failed after 8 attempts (dart_pg flakiness): '
      '$lastError');
}

/// Replicates `@internxt/lib` `aes.encrypt(text, password, {iv, salt})`.
///
/// AES-256-GCM with a PBKDF2-SHA512 derived key (2145 iterations, 32 bytes).
/// Output layout (base64-encoded): salt[64] + iv[16] + authTag[16] + ciphertext.
String internxtAesGcmEncrypt(
  String text,
  String password,
  String ivHex,
  String saltHex, {
  int hops = 2145,
}) {
  final iv = Uint8List.fromList(HEX.decode(ivHex));
  final salt = Uint8List.fromList(HEX.decode(saltHex));

  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA512Digest(), 128))
    ..init(Pbkdf2Parameters(salt, hops, 32));
  final key = pbkdf2.process(Uint8List.fromList(utf8.encode(password)));

  final gcm = GCMBlockCipher(AESEngine())
    ..init(true, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));
  final out = gcm.process(Uint8List.fromList(utf8.encode(text)));

  // pointycastle appends the 16-byte auth tag after the ciphertext; the
  // Internxt format places the tag before the ciphertext.
  final ciphertext = out.sublist(0, out.length - 16);
  final tag = out.sublist(out.length - 16);

  final result =
      Uint8List(salt.length + iv.length + tag.length + ciphertext.length);
  var offset = 0;
  result.setAll(offset, salt);
  offset += salt.length;
  result.setAll(offset, iv);
  offset += iv.length;
  result.setAll(offset, tag);
  offset += tag.length;
  result.setAll(offset, ciphertext);

  return base64.encode(result);
}

/// Inverse of [internxtAesGcmEncrypt] — replicates `@internxt/lib` `aes.decrypt`.
/// Input layout (base64): salt[64] + iv[16] + authTag[16] + ciphertext.
String internxtAesGcmDecrypt(String encData, String password,
    {int hops = 2145}) {
  final raw = base64.decode(encData);
  final salt = raw.sublist(0, 64);
  final iv = raw.sublist(64, 80);
  final tag = raw.sublist(80, 96);
  final ciphertext = raw.sublist(96);

  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA512Digest(), 128))
    ..init(Pbkdf2Parameters(Uint8List.fromList(salt), hops, 32));
  final key = pbkdf2.process(Uint8List.fromList(utf8.encode(password)));

  // pointycastle expects the auth tag appended after the ciphertext.
  final input = Uint8List(ciphertext.length + tag.length)
    ..setAll(0, ciphertext)
    ..setAll(ciphertext.length, tag);

  final gcm = GCMBlockCipher(AESEngine())
    ..init(
        false,
        AEADParameters(
            KeyParameter(key), 128, Uint8List.fromList(iv), Uint8List(0)));
  return utf8.decode(gcm.process(input));
}

String encryptTextWithKey(String textToEncrypt, String secret) {
  final random = Random.secure();
  final salt = Uint8List.fromList(List.generate(8, (_) => random.nextInt(256)));

  final keyIv = getKeyAndIvFrom(secret, salt);
  final key = keyIv['key']!;
  final iv = keyIv['iv']!;

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

  return HEX.encode(result);
}

String decryptTextWithKey(String encryptedText, String secret) {
  final cipherBytes = Uint8List.fromList(HEX.decode(encryptedText));
  final salt = cipherBytes.sublist(8, 16);

  final keyIv = getKeyAndIvFrom(secret, salt);
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

  return utf8.decode(decrypted);
}

Map<String, Uint8List> getKeyAndIvFrom(String secret, Uint8List salt) {
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

  return {'key': key, 'iv': iv};
}

// --- File crypto (AES-256-CTR + SHA-512 key derivation) ---

Uint8List getFileDeterministicKey(Uint8List key, Uint8List data) {
  final combined = Uint8List(key.length + data.length);
  combined.setAll(0, key);
  combined.setAll(key.length, data);

  return crypto.sha512.convert(combined).bytes as Uint8List;
}

Uint8List generateFileBucketKey(String mnemonic, String bucketId) {
  final seed = Uint8List.fromList(bip39.mnemonicToSeed(mnemonic));
  final bucketIdBytes = Uint8List.fromList(HEX.decode(bucketId));
  return getFileDeterministicKey(seed, bucketIdBytes);
}

Uint8List generateFileKey(String mnemonic, String bucketId, Uint8List index) {
  final bucketKey = generateFileBucketKey(mnemonic, bucketId);
  return getFileDeterministicKey(
    bucketKey.sublist(0, 32),
    index,
  ).sublist(0, 32);
}

Uint8List decryptStream(
  Uint8List encryptedData,
  String mnemonic,
  String bucketId,
  String fileIndexHex,
) {
  final index = Uint8List.fromList(HEX.decode(fileIndexHex));
  final fileKey = generateFileKey(mnemonic, bucketId, index);
  final iv = index.sublist(0, 16);

  final cipher = CTRStreamCipher(AESEngine())
    ..init(false, ParametersWithIV(KeyParameter(fileKey), iv));

  return cipher.process(encryptedData);
}

Map<String, dynamic> encryptStream(
  Uint8List data,
  String mnemonic,
  String bucketId,
) {
  final random = Random.secure();
  final index =
      Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)));
  final fileKey = generateFileKey(mnemonic, bucketId, index);
  final iv = index.sublist(0, 16);

  final cipher = CTRStreamCipher(AESEngine())
    ..init(true, ParametersWithIV(KeyParameter(fileKey), iv));

  final encryptedData = cipher.process(data);

  return {
    'data': encryptedData,
    'index': HEX.encode(index),
  };
}
