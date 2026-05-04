// Unit tests for auth.dart's pure helpers.
//
// The HTTP-bound functions (is2faNeeded, login, apiRefreshToken)
// are exercised via the live smoke suite — they need a real
// `http.Client` to test, which would mean refactoring the auth
// surface to accept an injectable client. Tracked under
// "Auth/api/drive unit coverage" in PLAN.md.
//
// What we *can* test cheaply is computeBridgePass: pure SHA-256
// over a stringified userId. Pinning it locks in the bridge-auth
// derivation so a future refactor can't quietly change the
// algorithm and silently break every authenticated network call.

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
}
