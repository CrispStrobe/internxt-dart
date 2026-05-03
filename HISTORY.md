# History

A historical record of the work done in this Dart port. New work is added
to the top. For forward-looking work see [`PLAN.md`](PLAN.md); for the
retrospective lessons see [`LEARNINGS.md`](LEARNINGS.md).

---

## Phase 4 (complete): module split

`cli.dart` was decomposed from a 4317-line monolith into focused
sibling modules at the project root. Each extraction is its own
commit and re-runs the full 73-test suite (61 unit + 12 live) to
confirm no behaviour change. Tests stay green via thin delegating
wrappers on `InternxtClient` plus `export` directives in cli.dart,
so existing `import '../cli.dart';` keeps working.

| Commit | Module | Lines | Notes |
|---|---|---|---|
| 4.a | `config.dart` | 152 | `ConfigService` — credential / batch-state / WebDAV PID persistence. No instance-state coupling. |
| 4.b | `crypto.dart` | 211 | Trust root: AES-256-CBC + EVP_BytesToKey, PBKDF2-SHA1, AES-256-CTR, SHA-512 key derivation. Live tests confirm wire-compat with the real backend. Dropped per-call `log()` debug noise. |
| 4.c | `utils.dart` | 45 | `formatSize` + `shouldIncludeFile`. Pure functions, already test-covered. |
| 4.d | `cache.dart` | 84 | `CacheEntry` + `cacheDuration` + `invalidateCache` + `clearParentCache`. Cache *storage* (the two `Map<String, CacheEntry>` fields) stays on `InternxtClient` — its lifetime is tied to a logged-in session. The `clearParentCache` doc comment pins the Phase 3 folderId-vs-folderUuid lesson so a future edit can't quietly reintroduce it. |
| 4.e | `api.dart` | 118 | `makeRequest` — central HTTP transport with 5xx exponential-backoff retry and network-exception retry. Bearer token is now a snapshot parameter rather than instance-state read; on retries the same token is reused (matches monolith behavior since refresh isn't driven from inside the function). Refresh orchestration stays in cli.dart pending the auth.dart extraction. Every endpoint call (auth, files, folders, trash, network) routes through this function — 12/12 live tests are the gate. |
| 4.f | `auth.dart` | 167 | `is2faNeeded` + `login` + `apiRefreshToken` + `computeBridgePass`. Owns the multi-step login dance (salt fetch → PBKDF2 hash → access token → hydration → bridge pass) and the raw refresh call. The orchestrator `refreshToken()` and the state mutator `setAuth()` stay on `InternxtClient` because they tie the protocol to the `_isRefreshingToken` lock, ConfigService persistence, and the 7 session fields. `computeBridgePass` dedupes a SHA-256 inline expression that lived in two places. |
| 4.g | `api.dart` (extended) | +110 → 228 | Six raw drive endpoint helpers — `getFileMetadata`, `getFolderMetadata`, `updateFileMetadata`, `updateFolderMetadata`, `searchFiles`, `getFolderAncestors`. Each is a thin `makeRequest` + `json.decode` wrapper. Sub-extraction to shrink drive.dart's eventual surface; the cli.dart wrappers are now one-line delegates. |
| 4.h.1 | `drive.dart` | 266 | Mutating ops: `moveFile` / `moveFolder`, `renameFile` / `renameFolder`, `setFileTimestamp` / `setFolderTimestamp`, `trashItems`, `deletePermanently`, `getTrashContent`. Each takes the gateway URL + bearer token snapshot, plus the two cache maps where invalidation is needed. Calls `inxt_api` and `inxt_cache` directly rather than via callbacks (drive is layered above both, so the direct dependency is fine). The internal `_clearParent` helper binds `clearParentCache`'s metadata-fetcher callbacks to the (URL, token) snapshot. The dead `_clearParentCache` wrapper was dropped from cli.dart since drive.dart was its only consumer. |
| 4.h.2 | `drive.dart` (extended) | +304 → 570 | Cache-aware paginated listing + path resolution: `listFolders`, `listFolderFiles`, `resolvePath`. The two listing primitives share the cache-hit-or-paginate shape; `resolvePath` walks the tree using both. `rootFolderId` is passed nullable through `resolvePath` and the function does its own "logged in?" check. The dropped log-noise paid an unexpected dividend: dart-analyze info-level lints fell from 39 → 34 because the old long methods carried several `prefer_final_locals` / `unnecessary_this` nits that disappeared with them. |
| 4.h.3 | `drive.dart` (extended) | +452 → 1022 | Recursive folder creation + search / find / tree: `createFolder`, `createFolderRecursive` (with the 409-conflict recovery preserved exactly — invalidate, sleep 1s, refetch, look for the colliding folder), `resolveOrCreateRemoteFolder`, `buildFullPath`, `search`, `findFiles`, `printTree`. `printTree` keeps the `printLine` callback so the caller can route output anywhere (stdout, buffer, log). The `_apiSearchFiles` and `_apiGetFolderAncestors` underscore wrappers were dropped — drive.dart calls `inxt_api.searchFiles` / `inxt_api.getFolderAncestors` directly. The dead `_createFolder` cli.dart wrapper was also dropped (only caller was `createFolderRecursive`, which moved). Info-level lints fell further from 34 → 24. |
| 4.i | `upload.dart` | 594 | Full upload pipeline: `startUpload` (POST start), `uploadChunkWithProgress` (streamed PUT with stdout progress), `finishUpload` (POST finish), `createFileEntry` (POST /files + parent invalidation), `uploadFile` (encrypt → push → finalize → register), `uploadSingleItem` (conflict policy + timestamp prep + uploadFile), `upload` (top-level batch driver with resumable state). The 5 ms inter-chunk delay is preserved exactly — it prevents socket saturation that otherwise causes progress to "jump" to 100% before the network catches up. The inline SHA-256 in `uploadFile` was replaced with `inxt_auth.computeBridgePass` (deduped). User-facing `print()` UX preserved; `log()` debug noise dropped. |
| Dead-code cleanup | — | -43 | Two never-called methods that survived the Phase 1 dead-private-method audit because they weren't underscore-prefixed: `istence` (a half-written batch existence-check from commit `392bbe9` "chunking etc") and `uploadThumbnailAsync` (a stub with a TODO that just logged). Same shape as the 7 dead private declarations removed in Phase 1; these were missed because the audit rule was scoped to `_`-prefixed methods. |
| 4.j | `download.dart` | 460 | Final extraction. `getDownloadLinks` (network basic-auth GET for shard URL + decryption index), `downloadFile` (in-memory metadata→links→GET→decrypt, returns the bytes), `downloadFileStreamed` (chunked network read with stdout progress, decrypt-then-write-to-disk; note: still buffers full encrypted payload before decrypt), `downloadPath` (top-level resolve-and-dispatch with batch state for recursive folder downloads). The dead `_getNetworkAuth` cli.dart wrapper was dropped — every call site in download.dart inlines `inxt_auth.computeBridgePass(userIdForAuth)` instead, deduping with the upload pipeline. The `_makeRequest` cli.dart wrapper also became dead with this extraction (every endpoint call has been moved to a module that calls `inxt_api.makeRequest` directly) and was dropped, along with the now-unused `package:crypto/crypto.dart` import. |

cli.dart down from 4317 → 2176 LOC — a 50% reduction. Phase 4 complete.

### Final module layout

| Module | LOC | Responsibility |
|---|---|---|
| `cli.dart` | 2176 | CLI entrypoint, command dispatch (handle*), `InternxtClient` skeleton with the 7 session fields + 2 cache maps + `setAuth` + `refreshToken` orchestrator + thin delegating wrappers. |
| `config.dart` | 152 | `ConfigService` — credential / batch-state / WebDAV PID file persistence. |
| `crypto.dart` | 211 | Trust root: AES-256-CBC + EVP_BytesToKey, PBKDF2-SHA1, AES-256-CTR, SHA-512 key derivation. |
| `utils.dart` | 45 | `formatSize`, `shouldIncludeFile`. Pure functions. |
| `cache.dart` | 84 | `CacheEntry`, `cacheDuration`, `invalidateCache`, `clearParentCache`. |
| `api.dart` | 228 | `makeRequest` (HTTP transport with retries) + raw drive endpoint helpers (metadata get/put, search, ancestors). |
| `auth.dart` | 167 | `is2faNeeded`, `login`, `apiRefreshToken`, `computeBridgePass`. The protocol; orchestration stays in cli.dart. |
| `drive.dart` | 1022 | All drive domain ops: mv/rename/timestamps/trash, paginated cache-aware listing, path resolution, recursive folder creation, search/find/tree. |
| `upload.dart` | 594 | Upload pipeline: start/chunk/finish/createFileEntry primitives + per-file orchestrator + per-item conflict policy + top-level batch driver with resumable state. |
| `download.dart` | 460 | Download pipeline: links primitive + in-memory and streamed downloaders + top-level path dispatcher with resumable state. |
See [`PLAN.md`](PLAN.md) for the full Phase 4 roadmap and a planned
Phase 6 that publishes the result as a library for cloud-dart to
consume.

The Python sibling at [`internxt-cli`](https://github.com/CrispStrobe/internxt-cli)
got the same audit + test treatment first. Several of the bug-shapes
caught here mirror what surfaced there — they're called out as such.

---

## Audit + Test Infrastructure (initial pass)

A targeted audit across the monolithic `cli.dart` (~4300 LOC) and
`webdav_filesystem.dart` (~790 LOC), followed by a 73-test suite (61
unit + 12 live integration) built up alongside the audit fixes.

End state: **0 dart-analyze errors, 0 warnings, 38 info-level lints
(style only), 73 tests passing (61 unit in ~32s + 12 live in ~45s)**.

The codebase is a single-file monolith by design (so far) and has not
been split into modules yet — that's Phase 4 in [`PLAN.md`](PLAN.md).
The unit + live suite serves as the safety net for that refactor.

---

### Bug fixes

#### Critical

1. **`cli.dart:_clearParentCache` — folderId vs. folderUuid silent cache miss** *(found by live integration test)*
   The function read `metadata['folderId']` (legacy integer) before
   `metadata['folderUuid']` (string UUID), but the path cache is keyed
   by string UUID. The integer value silently failed to invalidate, so
   a trashed/renamed/moved file would still resolve from the stale
   parent listing. Same bug-shape as the Python sibling's
   `create_folder_recursive` cache-coherency bug — and same lesson:
   only catchable with integration tests against the real backend.
   **Fixed:** prefer `folderUuid` (with `as String?` cast), fall back
   to `folderId.toString()` so the cache key always matches.

#### High

2. **`webdav_filesystem.dart` — 9 lying `@override` annotations**
   Methods on `InternxtFileSystem`, `InternxtDirectory`, and
   `InternxtFile` were marked `@override` but the named members don't
   exist on the `package:file` interfaces (e.g. `homeDirectory`,
   `pathSeparator`, `isWatchSupported`, `symbolicLinkTarget`,
   `createTemp`, `createTempSync`, `fs`, `setStat`). This is exactly
   the bug-shape we saw in the Python WebDAV PROPPATCH handler:
   declarations claiming to plug into a supertype contract that has
   moved on. With `override_on_non_overriding_member` set to `error`,
   the analyzer now blocks future occurrences.
   **Fixed:** removed the `@override` annotations. Kept the methods
   themselves in case the WSGI layer reaches them via dynamic dispatch.

3. **`cli.dart` — 7 dead private declarations**
   `_encryptPasswordHash`, `_computeBridgeAuth`, `_getSecurityDetails`,
   `_wait`, `_deleteFilePermanently`, `_uploadChunk`,
   `_deleteFolderPermanently` were defined but never called. The
   active `login()` inlines the same logic the first three would have
   done; the others were superseded by helpers like
   `_uploadChunkWithProgress` and never deleted.
   **Fixed:** removed all seven.

4. **`pubspec.yaml` — missing `path` dependency**
   `webdav_filesystem.dart` imports `package:path/path.dart` but the
   package was not declared in `pubspec.yaml`. It worked in the
   author's local checkout because some other dependency pulled `path`
   in transitively, but a fresh `dart pub get` on a clean machine could
   easily fail.
   **Fixed:** added `path: ^1.8.0` as a direct dependency.

#### Medium / hygiene

5. **`io.BytesBuilder` → `BytesBuilder` (3 sites)**
   The `dart:io` re-export of `BytesBuilder` is deprecated; it lives
   in `dart:typed_data` (already imported). Future Dart SDKs will
   remove the indirect import.
   **Fixed:** migrated all three call sites.

6. **2 unused locals removed** — `targetFolderUuid`, `stopwatch`.
7. **2 unused imports removed** — `package:file/file.dart`,
   `package:file/local.dart` from `cli.dart` (used only by
   `webdav_filesystem.dart` internally).
8. **`dart format` pass** — Phase 1.b commit, separated from logic
   changes so format churn is reviewable in isolation.

#### Safety

- **`.env` gitignored preemptively** (Phase 0). The same `.env` file
  used by the Python sibling holds real account credentials. The
  gitignore was added before the file was copied into the Dart
  workspace, removing the risk window where credentials could be
  staged accidentally.
- **`cli_old.dart` deleted** (Phase 0). 124 KB of stale pre-monolith
  code that would have caused confusion during the split refactor.

---

### Test infrastructure (new)

#### Suite

**61 Dart unit tests** across 3 test files in `test/`, covering:

- **Crypto** (`test/crypto_test.dart`, 22 tests) — AES-256-CBC + OpenSSL
  EVP_BytesToKey round-trip for credential text encryption (with the
  OpenSSL "Salted__" magic header pinned), AES-256-CTR file payload
  round-trip across 0 B–1 MB sizes (including the 0-size edge case),
  PBKDF2-HMAC-SHA1 password-hash determinism, deterministic SHA-512
  bucket-key derivation, file-key truncation to 32 bytes, and the
  `generateKeys` login-payload shape.
- **Config persistence** (`test/config_test.dart`, 22 tests) —
  ConfigService directory creation, credentials save/read/clear cycle
  (with corruption tolerance), WebDAV PID file lifecycle, batch ID
  determinism + cross-input divergence, batch state self-healing on
  corrupt files. All operations isolated in per-test temp directories.
- **Pure-function utilities** (`test/utils_test.dart`, 17 tests) —
  `formatSize` across all unit thresholds (B, KB, MB, GB) with null/
  non-numeric handling and decimal precision pinning;
  `shouldIncludeFile` glob filtering with include/exclude any-of
  semantics and case-sensitivity.

The crypto suite is the trust root: any regression here corrupts
every uploaded file. Coverage there matters more than anywhere else.

#### Regression markers

Two tests pin **deliberate divergences** from the Python sibling so a
future refactor can't silently "fix" them without us noticing:

- **`encryptTextWithKey('')` throws `RangeError`.** The pointycastle
  `PaddedBlockCipherImpl.doFinal` computes `start = inputLen - blockSize
  = 0 - 16 = -16` for empty input. Python's implementation handles
  empty strings cleanly. Nothing in the CLI today encrypts an empty
  string, so the gap is academic — the test makes sure it stays that
  way.
- **Credentials file is plain JSON.** Python encrypts the credentials
  file with AES-256-CBC + a fixed `APP_CRYPTO_SECRET`. The Dart impl
  stores plain JSON. Neither is real protection (the secret is
  shippable in the binary), but the Python version is defence-in-depth
  and the divergence is worth aligning eventually. The test pins the
  current Dart behaviour.

#### Live integration smoke test

`test/live_smoke_test.dart` — **12 opt-in tests** that run against the
real Internxt backend. Auto-skipped unless `IXT_ACCOUNT` and `IXT_PWD`
are set in env (or in a gitignored `.env` file).

Safety properties (mirrored from the Python sibling):

- All operations happen under a **sentinel folder**
  `/__test_inxt_dart_smoke__/<run-uuid>/` with a fresh UUID per run.
  Nothing outside that prefix is touched.
- Every file/folder name within a test gets a per-call UUID suffix so
  reruns are idempotent and never collide with prior attempts.
- `tearDownAll` trashes the entire sentinel folder even on test
  failure. Internxt's trash retains items for 30 days, so even if
  cleanup fails the user can recover via the web UI.
- Auto-rerun on transient failures via `package:test`'s `retry:`
  parameter (`liveTest` wrapper, 2 retries).
- **No cassette recording** — bytes/responses live only in memory;
  nothing about the user's account is written to the repo.
- Uses an isolated `ConfigService(dataDir: tempDir)` so the test never
  touches `~/.internxt-cli/`.

Coverage:

| Category | Tests |
|---|---|
| Auth + listing | login + creds shape; list root |
| Upload/download | full round-trip integrity (encrypted bytes, then decrypted back) |
| Path operations | resolve sentinel from cold cache; missing-path throws; recursive 3-level folder creation |
| File operations | rename in place; move between folders |
| Folder operations | rename; move to another parent |
| Trash | trash file removes from listing; trash non-empty folder removes children |

To run:

```bash
# Once: put creds in .env (gitignored, never committed)
echo 'IXT_ACCOUNT=you@example.com' > .env
echo 'IXT_PWD=your-password' >> .env

# Run the live smoke (~45s)
dart test test/live_smoke_test.dart

# Force-skip (e.g. in CI)
DART_TEST_SKIP_LIVE=1 dart test
```

The cache-coherency bug (item 1 in the Critical section) was the
test suite's first real find. All 12/12 tests now pass consistently
across consecutive runs.

#### Tooling

- **`analysis_options.yaml`** — extends `package:lints/recommended.yaml`
  plus three project-specific tightenings:
  - `unused_import` → error (was warning)
  - `override_on_non_overriding_member` → error (was warning) — this is
    the rule that would have caught the WebDAV `@override` bug at
    analyse time.
  - `deprecated_export_use` → warning
  - Style rules: `prefer_relative_imports`, `unnecessary_lambdas`.
- **Strict mode deliberately not enabled.** `strict-casts`,
  `strict-inference`, and `strict-raw-types` each generate 100–150
  spurious errors in this JSON-heavy codebase because every API
  response is `Map<String, dynamic>`. Will revisit after the Phase 4
  module split, where the JSON parsing can be isolated.
- **`pubspec.yaml`** dev-dependencies: `test`, `coverage`, `lints`.

---

### Caveats

This is a smaller pass than the Python sibling. Specifically:

- **No coverage report yet.** The monolith makes per-module coverage
  meaningless; will measure after Phase 4 splits the file.
- **No CI yet.** The Python sibling has GitHub Actions running ruff,
  mypy, bandit, and pytest. Dart's `dart analyze` + `dart test` are
  the equivalent gates but aren't wired into CI in this repo.
- **WebDAV provider not unit-tested.** Same as Python initially. The
  Phase 4 split should make this tractable.
- **Smaller live suite than Python.** Python has 28 live tests
  covering search, find, copy, conflict-handling. Dart has 12. The
  ones we ship cover the path and mutation primitives — the search/
  find/copy gaps are tracked in [`PLAN.md`](PLAN.md).
