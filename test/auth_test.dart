// Unit tests for auth.dart.
//
// HTTP-bound functions are exercised here via `MockClient` from
// `package:http/testing.dart` — auth.dart's three http-bound
// functions all accept an optional `http.Client` parameter, so we
// can intercept requests and assert on shape without hitting the
// network. Production callers continue to pass null and use the
// top-level `http.get/post/...` helpers.
//
// `computeBridgePass` is a pure SHA-256 derivation pinned as a
// regression marker — every authenticated network call depends on
// this hash matching what the gateway computes, so locking in the
// algorithm here protects against silent breakage.

import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import '../auth.dart';

void main() {
  group('computeBridgePass (bridge auth derivation)', () {
    test('returns lowercase hex of SHA-256 over the stringified userId', () {
      // Known vector: SHA-256("hello") computed independently.
      // This pins the algorithm + the lower-case hex encoding.
      final expected =
          '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
      expect(computeBridgePass('hello'), equals(expected));
    });

    test('coerces non-string userId to string before hashing', () {
      // The Internxt API has historically returned `userId` as either a
      // String (post-Phase-7 hydration) or an int (legacy). The
      // `.toString()` coercion in computeBridgePass is what saved us
      // — without it we'd hit a runtime type error.
      final fromString = computeBridgePass('42');
      final fromInt = computeBridgePass(42);
      expect(fromInt, equals(fromString),
          reason: 'int and stringified-int must hash identically');
    });

    test('different inputs produce different digests', () {
      // Trivial sanity check that we're not returning a constant.
      expect(
        computeBridgePass('user-a'),
        isNot(equals(computeBridgePass('user-b'))),
      );
    });

    test('output is 64 hex chars (256 bits)', () {
      final h = computeBridgePass('any-user-id-string');
      expect(h.length, equals(64));
      expect(RegExp(r'^[0-9a-f]+$').hasMatch(h), isTrue,
          reason: 'must be lowercase hex');
    });
  });

  group('is2faNeeded (mocked http)', () {
    test('returns true when gateway responds {tfa: true}', () async {
      final client = MockClient((req) async {
        // Pin the contract: lowercased + trimmed email goes in the body.
        expect(req.method, equals('POST'));
        expect(req.url.path, endsWith('/auth/login'));
        final body = json.decode(req.body) as Map<String, dynamic>;
        expect(body['email'], equals('alice@example.com'));
        return http.Response(json.encode({'tfa': true, 'sKey': 'unused'}), 200);
      });
      expect(
        await is2faNeeded('https://api.test', '  Alice@Example.com ',
            client: client),
        isTrue,
      );
    });

    test('returns false when gateway responds {tfa: false}', () async {
      final client = MockClient((_) async =>
          http.Response(json.encode({'tfa': false, 'sKey': 'unused'}), 200));
      expect(
        await is2faNeeded('https://api.test', 'bob@example.com',
            client: client),
        isFalse,
      );
    });

    test('returns false on transport errors (silent degrade)', () async {
      // Auth contract: a transient 2FA-check failure should NOT block
      // login. The caller proceeds and the actual login call surfaces
      // any real auth failure with its own error.
      final client =
          MockClient((_) async => throw http.ClientException('flaky network'));
      expect(
        await is2faNeeded('https://api.test', 'carol@example.com',
            client: client),
        isFalse,
      );
    });

    test('returns false on 4xx responses (silent degrade)', () async {
      // A 400/500 here would normally throw via makeRequest's error
      // path; is2faNeeded swallows so login can proceed.
      final client =
          MockClient((_) async => http.Response('{"error":"bad"}', 400));
      expect(
        await is2faNeeded('https://api.test', 'dave@example.com',
            client: client),
        isFalse,
      );
    });
  });

  group('apiRefreshToken (mocked http)', () {
    test('200 response returns parsed JSON map', () async {
      final client = MockClient((req) async {
        // Pin the contract: GET /users/refresh with bearer token.
        expect(req.method, equals('GET'));
        expect(req.url.path, endsWith('/users/refresh'));
        expect(req.headers['Authorization'], equals('Bearer tok-abc'));
        return http.Response(
          json.encode({
            'token': 'new-legacy-token',
            'newToken': 'new-bearer-token',
            'user': {'userId': 'u-1'},
          }),
          200,
        );
      });
      final result =
          await apiRefreshToken('https://api.test', 'tok-abc', client: client);
      expect(result['newToken'], equals('new-bearer-token'));
      expect((result['user'] as Map)['userId'], equals('u-1'));
    });

    test('non-200 response throws double-wrapped Exception', () async {
      // The double-wrapping is intentional — preserves the monolith's
      // error-message shape so any callers doing string-matching keep
      // working. Pinning this ensures a future "cleanup" doesn't
      // unintentionally flatten the message.
      final client = MockClient((_) async => http.Response('forbidden', 403));
      await expectLater(
        () => apiRefreshToken('https://api.test', 'tok-stale', client: client),
        throwsA(isA<Exception>().having(
          (e) => e.toString(),
          'message',
          contains('Token refresh failed'),
        )),
      );
    });

    test('transport error is rewrapped as "Token refresh failed"', () async {
      final client = MockClient(
          (_) async => throw http.ClientException('connection reset'));
      await expectLater(
        () => apiRefreshToken('https://api.test', 'tok', client: client),
        throwsA(isA<Exception>().having(
          (e) => e.toString(),
          'message',
          allOf(contains('Token refresh failed'), contains('connection reset')),
        )),
      );
    });
  });
}
