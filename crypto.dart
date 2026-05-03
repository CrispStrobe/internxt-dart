// Internxt crypto primitives — the trust root.
//
// All functions here are pure (no I/O, no auth state). Extracted from
// cli.dart in Phase 4. Coverage is anchored by test/crypto_test.dart
// (22 tests).
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
import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';

// --- Password / text crypto (AES-256-CBC + OpenSSL EVP_BytesToKey + MD5) ---

Map<String, String> passToHash(String password, String salt) {
  final saltBytes = HEX.decode(salt);
  final passwordBytes = Uint8List.fromList(utf8.encode(password));

  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA1Digest(), 64))
    ..init(Pbkdf2Parameters(Uint8List.fromList(saltBytes), 10000, 32));

  final hashBytes = pbkdf2.process(passwordBytes);
  return {'salt': salt, 'hash': HEX.encode(hashBytes)};
}

Map<String, dynamic> generateKeys(String password) {
  final encryptedPk =
      encryptTextWithKey('placeholder-private-key-for-login', password);

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

String encryptTextWithKey(String textToEncrypt, String secret) {
  final random = Random.secure();
  final salt =
      Uint8List.fromList(List.generate(8, (_) => random.nextInt(256)));

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

Uint8List generateFileKey(
    String mnemonic, String bucketId, Uint8List index) {
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
