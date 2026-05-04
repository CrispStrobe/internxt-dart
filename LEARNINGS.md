# Learnings

Insights from the audit + test build-out on this Dart port. Mostly
captured **after** the equivalent learnings on the Python sibling
([`internxt-cli/LEARNINGS.md`](https://github.com/CrispStrobe/internxt-cli/blob/main/LEARNINGS.md))
— so the deltas (where Dart's tooling, language, or ecosystem nudged
us in a different direction) are the most useful part here.

---

## On the audit itself

### `dart analyze` is enough — but only after enabling the right rules

Out of the box, `dart analyze` runs a permissive analyser that misses
real bugs. The `package:lints/recommended.yaml` baseline plus three
project-specific tightenings caught everything we needed:

| Rule | Caught |
|---|---|
| `override_on_non_overriding_member` (raised from warning to **error**) | The 9 lying `@override` annotations in `webdav_filesystem.dart`. Same bug-shape as the Python WebDAV PROPPATCH bug. |
| `unused_import` (raised to error) | 2 vestigial imports in `cli.dart`. |
| `unused_local_variable` (default warning) | 2 dead locals. |
| `dead_code` (default warning) | The 7 dead private methods in `cli.dart`. |
| `prefer_relative_imports` (style) | Caught the test imports referring to `../cli.dart` — kept relative for the monolith era. |

What we **didn't** turn on, deliberately:

- `strict-casts`, `strict-inference`, `strict-raw-types` — each
  generates 100–150 errors in this JSON-heavy codebase because every
  API response is `Map<String, dynamic>`. The errors are real type
  imprecisions but cleaning them up requires the Phase 4 module split
  first (so the JSON parsing layer can be isolated and the rest can
  go strict).

Lesson: **don't enable strict modes on a JSON-heavy codebase before
you have module boundaries to contain the dynamic surface.** The
strict-mode warnings will be 100% noise from the API parsing layer
and obscure the real findings elsewhere.

### `dart fix --apply` is dangerous on this codebase

The shotgun `dart fix --apply` invocation corrupted `cli.dart` on
first run: 504 errors after autofix, including 158 undefined-identifier
and 13 unterminated-string-literal errors. The auto-style transforms
mangled string interpolations.

Recovery: `git stash` and restart with manual edits only. From then
on, every fix went through `dart analyze` → `Edit` tool → re-run
`dart analyze` until clean. Ten times slower, but every change is
visible and reversible.

If you do need a fix at scale, use `dart fix --code <specific-rule>`
to limit blast radius. Never the unscoped form.

---

## On the trust roots

`crypto` and `auth` are the modules where any bug compromises every
user operation. Currently they're embedded in the monolith; Phase 4
will split them out and we'll target 100% coverage on each (matching
the Python sibling's policy).

The crypto unit tests already pin:

- **AES-256-CTR round-trip across 0 B, 1 B, 16 B, 256 B, 1 KB, 64 KB,
  1 MB.** Catches off-by-one errors at the block boundary and the
  zero-length edge case.
- **`encryptStream` re-encrypt produces different ciphertext.** Two
  encryptions of the same plaintext must differ — catches anyone
  "optimizing" by hoisting index generation out of the function.
- **OpenSSL `Salted__` magic header pin.** The credential file
  encryption is wire-compatible with OpenSSL `EVP_BytesToKey`. The
  test asserts the first 16 hex chars of the output are
  `53616c7465645f5f` ("Salted__"). If anyone "modernizes" the
  envelope, every existing credential file becomes unreadable —
  this test makes that breakage visible immediately.
- **Wrong-key decrypt either throws OR returns garbage.** What's NOT
  acceptable is silently returning the original plaintext. CBC has no
  auth tag, so the test catches both branches.

### The pointycastle empty-string gap

`pointycastle`'s `PaddedBlockCipherImpl.doFinal` computes
`start = inputLen - blockSize` and indexes into the buffer. For
empty input that's `0 - 16 = -16`, which throws `RangeError`.

Python's `cryptography` library handles empty plaintext cleanly. The
Dart impl doesn't. We pinned the current Dart behaviour as a
**REGRESSION MARKER test** rather than working around it:

```dart
test('REGRESSION MARKER: empty-string input throws', () {
  expect(() => client.encryptTextWithKey('', 'secret'),
      throwsA(isA<Error>()));
});
```

Practical impact: nothing in the CLI today encrypts an empty string.
If that changes, this test fires and we know to either patch
pointycastle, swap to a different cipher wrapper, or add a special
case for empty input.

The **pattern** generalizes: when you find a behaviour gap with a
sibling implementation that doesn't currently bite, pin it as a
regression marker. Don't paper over it; don't ignore it. Make sure
future-you sees it.

---

## On testing the monolith before splitting it

The audit-then-test-then-refactor sequence (Phases 1 → 2 → 3 → 4) was
the right call, even though it temporarily made the codebase ugly:

- **Phase 2** (unit tests) had to import private members. We renamed
  9 crypto methods from `_foo` to `foo` so the external test file
  could reach them. Aesthetically wrong (they're private to the
  monolith), but it gave the refactor a safety net.
- **Phase 4** (the split) will make those methods genuinely
  module-public when crypto moves to `crypto.dart`. The underscore
  rename then becomes correct, not a workaround.

Lesson: **don't refactor and add tests in the same commit.** Tests-
first means the refactor's job is "keep the green-bar green"; tests
during means you can't tell if the refactor broke something or just
re-shaped what the tests cover.

---

## On safety patterns for live tests

These are mirrored almost verbatim from the Python sibling — the
patterns are language-agnostic:

### Sentinel folder

Every operation must happen inside a known-prefix folder
(`/__test_inxt_dart_smoke__/<run-uuid>/`) so cleanup can
indiscriminately trash everything under it. Without this, a buggy
test that uploads to a path it computed wrong could pollute the
user's real data.

### Unique names per call

Every file/folder name in a live test gets a UUID suffix via
`_uniqueName()`. This is for the `package:test` retry mechanism: when
a flaky test gets retried, the prior attempt may have already created
an entry with the test's "logical" name. Without uniqueness, the
second attempt hits 409 Conflict and the rerun fails deterministically
— defeating the whole point of auto-retry.

### Auto-skip without creds

The whole live suite is gated on `IXT_ACCOUNT` and `IXT_PWD` env vars
(loaded from `.env` if present — Dart's `Platform.environment` is
read-only, so we maintain a side-channel `_envOverrides` map). Without
them, every test in the file is skipped via a single dummy `test()`
call with `skip: skipReason`. This makes the suite **safe to commit**
— contributors who don't have creds, or CI with no secrets, run the
61 unit tests and skip the 12 live tests cleanly.

### Cleanup in `tearDownAll`

Module-scope teardown trashes the entire sentinel folder, regardless
of whether tests pass or fail. Because Internxt's trash retains items
for 30 days, even if cleanup itself fails the user can recover via
the web UI. **Defense in depth on a shared resource.**

### The `.env` gitignore audit

Before committing anything, verify with `git check-ignore .env` AND
`git diff --cached --name-only | grep .env`. Both must come back
clean. Done at every commit involving live-test changes. The
gitignore file alone isn't enough — `git add .` could in principle
pick it up if someone reorders the rules.

We ran this check on every Phase 3 commit. The `.env` was copied from
the Python sibling's checkout (same real account) — paranoid mode
applied throughout.

---

## On rate limiting and eventual consistency

Same backend behaviour as the Python sibling:

- **Rate limiting** under sustained operations (~30+ requests in a
  minute) — endpoints return 5xx with non-JSON bodies.
- **Eventual consistency** on the path cache after server-side
  mutations — usually <1s, occasionally 2-5s under load.
- **Trash index lag** is much larger than the path cache — measured
  at >30s consistently in a dedicated probe (`trash listing
  eventual-consistency latency` live test). A freshly-trashed file
  doesn't surface in `/storage/trash/paginated` for at least that
  long. The lifecycle test's 6s retry was always doomed; the
  restore-then-find step is what actually verifies the lifecycle.

## On gateway gaps in PUT meta operations (Phase 9.6 + probe)

Multiple distinct shapes of brokenness in the metadata-update path,
verified empirically by `tool/probe_setmeta.dart` against the live
gateway. Each has a dedicated live regression marker that fires
when behavior changes.

**Folder path** (`setFolderTimestamp` / PUT /folders/{uuid}/meta):

- Bare `{modificationTime}` → 400 "plainName should not be empty"
- `{plainName, modificationTime}` → 200 but **gateway silently
  overwrites mtime with `now()`**. Verified by GET-PUT-GET round-trip:
  requested 2021-06-01 reflects back as today's timestamp.

**File path** (`setFileTimestamp` / PUT /files/{uuid}/meta) — TWO
compounding bugs:

- Bare `{modificationTime}` → 400 "Missing update file metadata"
- `{plainName, type, modificationTime}` (echoing self) → **409
  "name already exists"** — the gateway runs a uniqueness check
  that doesn't exclude the file itself
- Bare same-name rename `{plainName, type}` (no mtime) → also
  **409** — confirms the uniqueness check is independent of
  the timestamp field
- Rename to a NEW name + mtime → 200 but **gateway still silently
  overwrites mtime** (same as folder path)

So the file timestamp update is broken end-to-end: even
sidestepping the 409 via temp-rename doesn't actually persist
mtime.

**Comparison with the Python sibling**: Python has
`set_folder_timestamps` (only folder, no file) and sends a partial
body `{modificationTime}` only. That body shape currently 400s
against the live gateway — Python's tests are mocked
(`tests/test_webdav_set_property.py` uses `unittest.mock.patch`),
so they never observed this. Python's WebDAV PROPPATCH for folders
would fail end-to-end against today's gateway; nobody has noticed
because PROPPATCH is advisory and clients don't break on it.

**Our handling**:
- `lib/drive.dart`'s `setFileTimestamp` and `setFolderTimestamp`
  stay honest — they do the documented PUT, surface whatever the
  gateway returns. Non-WebDAV callers see real errors.
- `lib/webdav_filesystem.dart` swallows the 409 in file PROPPATCH
  (`InternxtFile.setStat`) — PROPPATCH is officially advisory in
  the WebDAV spec, no point breaking the WebDAV op over a known
  gateway gap.
- Live markers `setFolderTimestamp known-broken marker` and
  `setFileTimestamp known-broken marker (gateway 409)` pin both
  failure modes.

The mitigation in Dart: `package:test`'s built-in `retry:` parameter
(2 retries) wrapped around each live test:

```dart
const liveRetries = 2;

void liveTest(String description, dynamic Function() body) {
  test(description, body, retry: liveRetries);
}
```

Combined with per-call unique names, the live suite stabilized at
12/12 across consecutive runs. One run flaked at 11/12 before retries
were added — same shape of flake the Python sibling sees.

---

## On `package:file` and the WebDAV `@override` bug

Nine methods in `webdav_filesystem.dart` were marked `@override` but
the named members don't exist on the `package:file` interfaces.

The bug-shape is identical to the Python sibling's WebDAV PROPPATCH
bug (`from wsgidav.util import rfc_1123_to_timestamp` — never existed
in any released wsgidav version). In both cases:

- The author wrote against an **older or imagined** API.
- The lying annotations / imports compiled fine.
- Dynamic dispatch saved them at runtime (the methods are still
  reachable, just not via the contract they claimed to implement).
- A static analyser configured for it (Dart's
  `override_on_non_overriding_member`, Python's `pylint
  no-name-in-module`) flagged it as a warning.
- We had to **dial the rule up to error** and treat it as
  blocking-CI to actually make the fix happen.

Lesson: **don't dismiss "lying contract" warnings as cosmetic.** They
mark the boundary where your code thinks it's plugging into something
that may have moved on. The runtime might not crash today; it will
when the supertype changes.

---

## On the gap between unit tests and integration tests

The headline finding of Phase 3 was the `_clearParentCache` cache-
coherency bug: the function read `metadata['folderId']` (legacy int)
before `metadata['folderUuid']` (string), but the cache key is the
string UUID. Silent invalidation failure.

Unit tests stubbed `getFileMetadata` directly to return a fake map —
the test author chose what fields were present. Reality returns
**both** `folderId` and `folderUuid`, with `folderUuid` being the
authoritative one. The unit-tested code path took the `folderId`
branch; live behaviour did the same; only the live test surfaced the
fact that the cache wasn't actually being cleared.

This is the **exact same lesson** as Python's
`create_folder_recursive` cache bug: unit tests verify your code
does what you think the backend does. Integration tests verify what
the backend actually does.

The fix in both languages was a one-line reorder. The bug in both
languages went undetected for the entire pre-audit lifetime of the
code. Cache layers are where this pattern bites — they're glue code
between two systems with different shapes, and the integration test
is the only thing that exercises both shapes together.

---

## On Dart-specific things that surprised us

### `Platform.environment` is read-only

In Python you can `os.environ['FOO'] = 'bar'` to inject env vars for
testing (with cleanup via `monkeypatch`). Dart's `Platform.environment`
is `Map<String, String>` — read-only, no mutator. To load `.env` for
the live tests we built a side-channel `_envOverrides` map and a
`_env(key)` helper that checks overrides first, then
`Platform.environment`. Slightly clunkier but avoids reaching for a
package:dotenv dependency just for one test file.

### `package:test`'s `retry:` is built in

Python needed `pytest-rerunfailures` (a third-party plugin) for retry
support. Dart's `package:test` ships with a `retry:` parameter on
`test()`. One less dependency to manage. Used for the entire live
suite.

### `pointycastle`'s padding implementation has gaps

See above on empty-string handling. More generally: pointycastle is
the canonical Dart crypto library, but it's lower-level than Python's
`cryptography` package. The `PaddedBlockCipherImpl` wrapper makes
assumptions about non-empty input that aren't documented. If the
crypto module grows new use cases, expect to either work around
pointycastle quirks or replace it with a thinner wrapper.

### The `as String?` cast pattern for nullable JSON

The cache bug fix in `_clearParentCache` looks like:

```dart
parentUuid = (metadata['folderUuid'] as String?) ??
    metadata['folderId']?.toString();
```

The `as String?` cast is the Dart-idiomatic way of saying "I know the
JSON value at this key is either a string or absent." Without the
cast, the value is `dynamic` and the `??` fallback to a different
type triggers analyser warnings (and sometimes wrong behaviour at
runtime if the value is a non-string truthy thing). Always cast at
JSON boundaries.

---

## What I'd do differently next time

1. **Set up `analysis_options.yaml` before writing any tests.** We
   added it during Phase 1 audit fixes; should have been the first
   commit. The default analyser missed several of the bugs we later
   found by tightening rules.

2. **Don't run `dart fix --apply`. Ever. On any codebase.** Unscoped
   autofix is too dangerous. Use `dart fix --code <rule>` if you must.

3. **Write the regression-marker tests during the audit, not after.**
   The empty-string and credentials-plain-JSON markers were added
   when writing the unit suite; should have been added the moment
   the gap was first noticed.

4. **Compare against the sibling implementation early.** The cache
   bug we found in Phase 3 was the same shape as one already known
   in the Python sibling. If we'd done the cross-implementation
   comparison earlier, we'd have known to look at every cache
   invalidation site preemptively.

5. **Test the cache layer separately from the operations layer.**
   Same lesson as Python. The `_clearParentCache` bug was only
   catchable with live tests because no unit test exercised the
   invalidation directly. A targeted unit test that calls
   `_invalidateCache(uuid)` and then asserts the next listing hits
   the network would have caught the keying bug at the unit level.

---

## Final numbers

| Metric | Value |
|---|---|
| Total tests | 73 (61 unit + 12 live) |
| Bugs found and fixed | 8 (7 audit + 1 from live tests) |
| `dart analyze` errors | 0 |
| `dart analyze` warnings | 0 |
| `dart analyze` info-level lints | 38 (all pure style) |
| Unit suite runtime | ~32 seconds |
| Live suite runtime | ~45 seconds |
| Lines of test code | ~1148 (61 unit) + ~476 (12 live) |
| Lines of production code | ~5105 (cli.dart + webdav_filesystem.dart) |
| Test-to-production ratio | ~1:3 |

The test-to-production ratio is much lower than the Python sibling's
1.3:1. This is because the Dart codebase is a single 4317-line
monolith — testing it from outside is awkward, so coverage is
shallower. Phase 4 (the module split) is the prerequisite for
bringing the ratio up to the same level as Python.
