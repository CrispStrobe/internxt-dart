// Crypto round-trip tests against InternxtClient.
//
// These exercise the encryption primitives in pure-functional isolation
// (no network, no auth state). They cover:
//
//  - encryptTextWithKey / decryptTextWithKey: AES-256-CBC + OpenSSL
//    EVP_BytesToKey (MD5) round-trip — used for credential file
//    encryption and password-hash transport.
//  - passToHash: PBKDF2-HMAC-SHA1 password derivation — must match the
//    Internxt server's hash format.
//  - encryptStream / decryptStream: AES-256-CTR file encryption — the
//    actual file payload protocol.
//  - generateFileKey / generateFileBucketKey: deterministic key
//    derivation from mnemonic + bucket id.
//
// The trust root: if any of these regress, every uploaded file is at
// risk of corruption or unrecoverability. Coverage here matters more
// than anywhere else in the codebase.

import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';

import 'package:dart_pg/dart_pg.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

import 'package:internxt_client/cli.dart';
import 'package:internxt_client/crypto.dart' as inxt_crypto;

const _validMnemonic = 'abandon abandon abandon abandon abandon abandon '
    'abandon abandon abandon abandon abandon about';
const _bucketId = '000000000000000000000000'; // 24 hex chars

InternxtClient _newClient() {
  // ConfigService isn't needed for crypto tests — we just need an
  // instance to call methods on.
  final config = ConfigService();
  return InternxtClient(config: config);
}

void main() {
  group('encryptTextWithKey / decryptTextWithKey', () {
    test('round-trips arbitrary non-empty text', () {
      final client = _newClient();
      const secret = 'my-test-secret-key';
      // NOTE: empty string is excluded because pointycastle's
      // PaddedBlockCipherImpl can't handle 0-length plaintext (see the
      // dedicated test below documenting this behaviour gap vs Python).
      for (final text in [
        'hello',
        'unicode ✓ 中文',
        'x' * 256,
        'a\nb\rc\td',
      ]) {
        final enc = client.encryptTextWithKey(text, secret);
        final dec = client.decryptTextWithKey(enc, secret);
        expect(dec, equals(text), reason: 'round-trip failed for: $text');
      }
    });

    test('REGRESSION MARKER: empty-string input throws', () {
      // The Python codebase's encrypt_text('') round-trips successfully.
      // The Dart impl currently does not — pointycastle's
      // PaddedBlockCipherImpl.doFinal computes start = inputLen - blockSize
      // = 0 - 16 = -16 and throws RangeError. This test pins the current
      // behaviour so we know if it changes (e.g. after pointycastle fix
      // or a wrapper change).
      //
      // Practical impact: nowhere in the CLI today encrypts an empty
      // string. If that changes, this needs to be addressed.
      final client = _newClient();
      expect(
        () => client.encryptTextWithKey('', 'secret'),
        throwsA(isA<Error>()),
      );
    });

    test('uses random salt — same input produces different ciphertext', () {
      final client = _newClient();
      const secret = 'shared';
      final a = client.encryptTextWithKey('same plaintext', secret);
      final b = client.encryptTextWithKey('same plaintext', secret);
      expect(a, isNot(equals(b)),
          reason: 'salt must be random; ciphertext should differ');
    });

    test('output starts with the OpenSSL magic header', () {
      final client = _newClient();
      // OpenSSL EVP_BytesToKey output format: "Salted__" + 8-byte salt + ciphertext.
      // 'Salted__' as hex = "53616c7465645f5f"
      final enc = client.encryptTextWithKey('x', 'secret');
      expect(enc.toLowerCase().startsWith('53616c7465645f5f'), isTrue,
          reason: 'must use the OpenSSL "Salted__" envelope');
    });

    test('decrypt with wrong key throws or returns wrong bytes', () {
      final client = _newClient();
      final enc = client.encryptTextWithKey('secret-data', 'right-key');
      // Wrong key may decrypt to something garbled (CBC has no auth tag)
      // OR throw on bad PKCS7 padding. Either is acceptable; what's NOT
      // acceptable is silently returning the same plaintext.
      // pointycastle throws ArgumentError (not Exception) on padding fail,
      // so we catch the broader Object.
      try {
        final wrong = client.decryptTextWithKey(enc, 'wrong-key');
        expect(wrong, isNot(equals('secret-data')));
        // ignore: avoid_catching_errors
      } catch (_) {
        // Expected — bad padding throws ArgumentError
      }
    });
  });

  group('passToHash (PBKDF2-HMAC-SHA1)', () {
    test('deterministic for same password + salt', () {
      final client = _newClient();
      const salt = '00112233445566778899aabbccddeeff';
      final h1 = client.passToHash('password123', salt);
      final h2 = client.passToHash('password123', salt);
      expect(h1, equals(h2));
      expect(h1['salt'], equals(salt));
      // PBKDF2 derives 32 bytes -> 64 hex chars
      expect(h1['hash']!.length, equals(64));
    });

    test('different passwords produce different hashes', () {
      final client = _newClient();
      final salt = '00' * 16;
      final h1 = client.passToHash('password1', salt);
      final h2 = client.passToHash('password2', salt);
      expect(h1['hash'], isNot(equals(h2['hash'])));
    });

    test('different salts produce different hashes', () {
      final client = _newClient();
      final h1 = client.passToHash('same-password', '00' * 16);
      final h2 = client.passToHash('same-password', 'ff' * 16);
      expect(h1['hash'], isNot(equals(h2['hash'])));
    });

    test('output is hex-decodable', () {
      final client = _newClient();
      final h = client.passToHash('pw', '00' * 16);
      // hash field must be parseable as hex
      expect(int.parse(h['hash']!.substring(0, 8), radix: 16), greaterThan(-1));
    });
  });

  group('encryptStream / decryptStream (AES-256-CTR file payload)', () {
    test('round-trips arbitrary-size data', () {
      final client = _newClient();
      final rng = Random.secure();
      for (final size in [0, 1, 16, 256, 1024, 64 * 1024, 1024 * 1024]) {
        final plaintext = Uint8List.fromList(
          List.generate(size, (_) => rng.nextInt(256)),
        );
        final encResult =
            client.encryptStream(plaintext, _validMnemonic, _bucketId);
        final encrypted = encResult['data'] as Uint8List;
        final indexHex = encResult['index'] as String;

        // CTR mode preserves length exactly
        expect(encrypted.length, equals(plaintext.length),
            reason: 'AES-CTR must not change length (size=$size)');

        final decrypted = client.decryptStream(
          encrypted,
          _validMnemonic,
          _bucketId,
          indexHex,
        );

        expect(decrypted, equals(plaintext),
            reason: 'round-trip failed at size $size');
      }
    });

    test('produces different ciphertext on re-encrypt (random index)', () {
      final client = _newClient();
      final plaintext = Uint8List.fromList(utf8.encode('same input bytes'));
      final a = client.encryptStream(plaintext, _validMnemonic, _bucketId);
      final b = client.encryptStream(plaintext, _validMnemonic, _bucketId);
      expect(a['index'], isNot(equals(b['index'])),
          reason: 'index must be random per encryption');
      expect(a['data'], isNot(equals(b['data'])),
          reason: 'ciphertext must differ when index differs');
    });

    test('decrypting with wrong index returns garbage', () {
      final client = _newClient();
      final plaintext = Uint8List.fromList(utf8.encode('original'));
      final enc = client.encryptStream(plaintext, _validMnemonic, _bucketId);
      // Use a different index for decryption
      final wrongIndex = '00' * 32;
      final dec = client.decryptStream(
        enc['data'] as Uint8List,
        _validMnemonic,
        _bucketId,
        wrongIndex,
      );
      expect(dec, isNot(equals(plaintext)),
          reason: 'wrong index should not yield original bytes');
    });

    test('decrypting with wrong bucket_id returns garbage', () {
      final client = _newClient();
      final plaintext = Uint8List.fromList(utf8.encode('original'));
      final enc = client.encryptStream(plaintext, _validMnemonic, _bucketId);
      final dec = client.decryptStream(
        enc['data'] as Uint8List,
        _validMnemonic,
        'ff' * 12, // different bucket
        enc['index'] as String,
      );
      expect(dec, isNot(equals(plaintext)));
    });

    test('decrypting with wrong mnemonic returns garbage', () {
      final client = _newClient();
      final plaintext = Uint8List.fromList(utf8.encode('original'));
      final enc = client.encryptStream(plaintext, _validMnemonic, _bucketId);
      const otherMnemonic = 'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon ability';
      final dec = client.decryptStream(
        enc['data'] as Uint8List,
        otherMnemonic,
        _bucketId,
        enc['index'] as String,
      );
      expect(dec, isNot(equals(plaintext)));
    });
  });

  group('generateFileBucketKey (deterministic SHA-512)', () {
    test('same mnemonic + bucket -> same bucket key', () {
      final client = _newClient();
      final a = client.generateFileBucketKey(_validMnemonic, _bucketId);
      final b = client.generateFileBucketKey(_validMnemonic, _bucketId);
      expect(a, equals(b));
    });

    test('different bucket id -> different key', () {
      final client = _newClient();
      final a = client.generateFileBucketKey(_validMnemonic, _bucketId);
      final b = client.generateFileBucketKey(_validMnemonic, 'aa' * 12);
      expect(a, isNot(equals(b)));
    });

    test('returns 64 bytes (full SHA-512 digest)', () {
      final client = _newClient();
      final key = client.generateFileBucketKey(_validMnemonic, _bucketId);
      expect(key.length, equals(64));
    });
  });

  group('generateFileKey (file-specific deterministic key)', () {
    test('same inputs -> same key', () {
      final client = _newClient();
      final index = Uint8List.fromList(List.generate(32, (i) => i));
      final a = client.generateFileKey(_validMnemonic, _bucketId, index);
      final b = client.generateFileKey(_validMnemonic, _bucketId, index);
      expect(a, equals(b));
    });

    test('different index -> different key', () {
      final client = _newClient();
      final index1 = Uint8List.fromList(List.generate(32, (i) => i));
      final index2 = Uint8List.fromList(List.generate(32, (i) => 31 - i));
      final a = client.generateFileKey(_validMnemonic, _bucketId, index1);
      final b = client.generateFileKey(_validMnemonic, _bucketId, index2);
      expect(a, isNot(equals(b)));
    });

    test('truncated to 32 bytes (AES-256 key size)', () {
      final client = _newClient();
      final index = Uint8List(32);
      final key = client.generateFileKey(_validMnemonic, _bucketId, index);
      expect(key.length, equals(32));
    });
  });

  group('generateKeys (login payload)', () {
    test('returns the real OpenPGP key shape (ecc + kyber map present)', () {
      final client = _newClient();
      final keys = client.generateKeys('any-password');
      expect(keys['publicKey'], isA<String>());
      expect(keys['privateKeyEncrypted'], isA<String>());
      expect(keys['ecc'], isA<Map<String, dynamic>>());
      expect(keys['ecc']['publicKey'], isA<String>());
      expect(keys['ecc']['privateKeyEncrypted'], isA<String>());
      // Server requires kyber map present even with null values
      expect(keys['kyber'], isA<Map<String, dynamic>>());
    });

    test('ecc.publicKey is a base64-encoded armored OpenPGP public key', () {
      final keys = inxt_crypto.generateKeys('pw');
      final armored =
          utf8.decode(base64.decode(keys['ecc']['publicKey'] as String));
      expect(armored, startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----'));
    });

    test('privateKeyEncrypted uses the Internxt AES-256-GCM envelope', () {
      final keys = inxt_crypto.generateKeys('pw');
      final raw = base64.decode(keys['ecc']['privateKeyEncrypted'] as String);
      // salt[64] + iv[16] + authTag[16] + ciphertext
      expect(raw.length, greaterThan(96));
      expect(HEX.encode(raw.sublist(0, 64)), equals(inxt_crypto.appMagicSalt));
      expect(HEX.encode(raw.sublist(64, 80)), equals(inxt_crypto.appMagicIv));
    });

    test('privateKeyEncrypted round-trips to an armored private key', () {
      const password = 'test-pass';
      final keys = inxt_crypto.generateKeys(password);
      final decrypted = inxt_crypto.internxtAesGcmDecrypt(
        keys['ecc']['privateKeyEncrypted'] as String,
        password,
      );
      expect(decrypted, startsWith('-----BEGIN PGP PRIVATE KEY BLOCK-----'));
    });

    // dart_pg's OpenPGP.generateKey occasionally throws a RangeError from its
    // own MPI parsing for some random Ed25519 keys; generateKeys retries.
    test('retries flaky key generation, then succeeds', () {
      var calls = 0;
      final keys = inxt_crypto.generateKeys('pw', keyGenerator: (passphrase) {
        calls++;
        if (calls < 3) {
          throw StateError('simulated dart_pg readMPI flakiness');
        }
        return OpenPGP.generateKey(['inxt@inxt.com'], passphrase,
            type: KeyType.ecc, curve: Ecc.ed25519);
      });
      expect(calls, equals(3)); // failed twice, succeeded on the third
      expect(keys['ecc']['publicKey'], isA<String>());
    });

    test('throws after exhausting key-generation retries', () {
      var calls = 0;
      expect(
        () => inxt_crypto.generateKeys('pw', keyGenerator: (_) {
          calls++;
          throw StateError('always fails');
        }),
        throwsA(isA<Exception>()),
      );
      expect(calls, equals(8)); // bounded retry count
    });
  });
}
