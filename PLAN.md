# Plan / Roadmap

What's known to be unimplemented, broken, or worth porting from the
Python sibling ([`internxt-cli`](https://github.com/CrispStrobe/internxt-cli)).
The 73-test suite (61 unit + 12 live) at the end of the audit serves
as the safety net for everything below.

For what's been done already, see [`HISTORY.md`](HISTORY.md).
For lessons from the audit, see [`LEARNINGS.md`](LEARNINGS.md).

---

## Phase 4: split the monolith (in progress)

**Status:** ConfigService, crypto, and utils have been extracted. cli.dart
down from 4317 → 3997 LOC. Three new modules at the project root:
`config.dart` (152), `crypto.dart` (211), `utils.dart` (45). Tests stay
green via thin delegating wrappers + re-exports. Each extraction got
its own commit (4.a, 4.b, 4.c).

**Still ahead (in this phase):**
- `auth.dart` — login orchestration, refresh, bridge auth, credential
  rotation. Touches a lot of `InternxtClient` instance state (token,
  mnemonic, bucketId, rootFolderId) — extraction will need a clear
  decision on whether auth holds those fields or `InternxtClient` does.
- `api.dart` — `_makeRequest`, pagination helpers, raw endpoint
  methods. Probably extract before `auth` since auth depends on it.
- `cache.dart` — `_CacheEntry`, `_folderCache`, `_fileCache`,
  `_invalidateCache`, `_clearParentCache`. The cache layer is where
  the bug we found in Phase 3 lived; a dedicated module makes future
  cache-correctness audits tractable.
- `drive.dart` — path resolution, list, mv, rename, copy, trash,
  recursive folder ops. Largest remaining chunk.
- `upload.dart` — encrypt → push → finalize → drive-entry pipeline +
  memory-gated concurrency.
- `download.dart` — download + decrypt + write + timestamp preserve.

After all extractions land, drop the delegating wrappers on
InternxtClient and migrate tests to call the top-level functions
directly.

---

`cli.dart` was originally **4317 lines** in a single file. It mixed:

- CLI entrypoint + Click-equivalent (`args` package) command parsing
- HTTP client + endpoint methods
- Auth (login, refresh, credential persistence)
- Crypto (AES-CTR file payload, AES-CBC + EVP_BytesToKey credentials,
  PBKDF2 password hash, key derivation)
- Drive operations (path resolution, cache, upload, download, mv,
  rename, copy, trash, recursive folder ops)
- Memory-gated upload concurrency
- Progress rendering
- Glob matching
- Filename sanitization

A natural split:

- `lib/internxt_cli/crypto.dart` — `passToHash`, `encryptTextWithKey`,
  `decryptTextWithKey`, `getKeyAndIvFrom`, `getFileDeterministicKey`,
  `generateFileBucketKey`, `generateFileKey`, `encryptStream`,
  `decryptStream`, `generateKeys`. **The trust root.**
- `lib/internxt_cli/config.dart` — `ConfigService` + batch-state
  helpers. Already loosely coupled; clean lift.
- `lib/internxt_cli/api.dart` — raw HTTP endpoint methods (`_request`,
  pagination helpers, login, refresh, file/folder CRUD, trash).
- `lib/internxt_cli/auth.dart` — login orchestration + 2FA + bridge
  auth + credential rotation.
- `lib/internxt_cli/drive.dart` — path cache, `resolvePath`,
  `listFolderFiles`, `createFolderRecursive`, mv/rename/copy/trash
  operations, `_clearParentCache` (the cache-coherency bug we just
  fixed lives here).
- `lib/internxt_cli/upload.dart` — upload pipeline (encrypt → push →
  finalize → drive-entry), memory gate, concurrency control,
  resumable checkpoints.
- `lib/internxt_cli/download.dart` — download + decrypt + write +
  timestamp preserve.
- `lib/internxt_cli/utils.dart` — `formatSize`, glob matching,
  filename sanitization, progress rendering.
- `lib/internxt_cli.dart` — public facade (re-exports the above).
- `bin/inxt.dart` — CLI entry (Click-equivalent command tree).
- `cli.dart` — keep as a thin shim that re-exports `lib/internxt_cli.dart`
  for tests that already use `import '../cli.dart';`. Allows Phase 4
  to land without rewriting the test imports.

After the split:
- Drop the `_underscore` workaround on the 9 crypto methods we renamed
  in Phase 2 — they become genuinely public (file-public) members of
  the `crypto.dart` module.
- Re-enable `strict-casts` and `strict-inference` in
  `analysis_options.yaml`. The JSON-parsing layer can take the dynamic
  hits while the rest of the code goes strict.
- Measure per-module coverage. Aim for **100% on `crypto.dart` and
  `auth.dart`** (the trust roots), 80%+ on the rest.

Risk: ~every test changes its import path, but the `cli.dart` shim
mitigates that. Each extraction commit should keep the full 73-test
suite green.

Estimated work: ~4 hours, +150 LOC of test imports / facade re-exports.

---

## Phase 6: publish as a library + reunify with `cloud-dart`

A separate Flutter app at `~/code/cloud-dart/` (the `CrispCloud`
repo) embeds its own copy of `internxt_client.dart`. As of this
audit it diverges by ~2700 lines from this CLI's version: same
underlying protocol, but with Flutter-specific integration classes
(`extends FilenFileSystem`, isolate-friendly callbacks, UI-thread-
aware error reporting) bolted on. The two copies will keep drifting
unless we unify them.

The plan, **after Phase 4 finishes**:

### Step 6a: convert internxt-dart to a real Dart package

Once cli.dart is fully decomposed (auth/api/cache/drive/upload/
download all extracted), restructure for `package:` import:

- Move modules to `lib/internxt_client/`
- Add `lib/internxt_client.dart` as the public barrel (re-exports
  everything CrispCloud-or-other consumers might want)
- Keep `bin/inxt.dart` as the CLI entrypoint
- Keep root `cli.dart` as a backwards-compat shim if/when needed
- Tag a version (`v0.1.0`) and pin it from `cloud-dart`'s pubspec.yaml
  via `git: { url: ..., ref: v0.1.0 }`

Estimated work: ~2 hours after Phase 4 lands.

### Step 6b: audit cloud-dart's divergence

Three buckets to classify every divergent block in
`~/code/cloud-dart/lib/services/internxt_client.dart`:

- **(a) Bug fixes / improvements** that should backport into
  internxt-dart. The `cloud-dart` copy may have features or fixes
  the CLI version is missing. Each one becomes its own PR.
- **(b) Genuinely Flutter-specific code** that stays in cloud-dart:
  `FilenFileSystem` integration, isolate spawning, UI-thread error
  channels, anything that needs `package:flutter`. Extract these
  into focused modules in `cloud-dart/lib/services/internxt_flutter/`.
- **(c) Accidental drift** — places where one copy was edited and
  the other wasn't. Delete the older version in favour of whichever
  is currently correct.

This is read-and-classify work, no code changes. Estimated ~2 hours.

### Step 6c: rewire cloud-dart to consume the library

- Remove the embedded `internxt_client.dart`
- Add the dependency in cloud-dart's pubspec.yaml
- Update imports throughout cloud-dart (`import
  'package:internxt_client/internxt_client.dart'`)
- Keep only the (b)-bucket modules locally
- Run cloud-dart's existing test suite (or smoke-test the Flutter app)
  to confirm nothing regressed

Estimated work: ~3 hours.

### Risks

- **API surface lock-in.** The first version we publish becomes a
  contract with cloud-dart. Worth keeping `v0.x` so we can iterate
  on the API without semver pain.
- **`pointycastle` and `bip39` versioning.** Both packages have had
  breaking releases in recent history. Pinning compatible ranges in
  internxt-dart's pubspec is critical — cloud-dart's app may already
  be on a different range.
- **Flutter SDK constraints.** internxt-dart targets pure Dart; if
  cloud-dart pins a specific Flutter version that constrains the
  Dart SDK floor, internxt-dart may need to widen its
  `environment: sdk:` constraint to match.

### Why this is worth it

Two divergent 4000+ line files in two repos is unmaintainable. Every
audit fix from Phases 0–5 (the cache-coherency bug, the `@override`
fixes, the dropped dead code) currently lives in only one of them.
Unifying lets the next audit cover both at once.

---

## Functional gaps vs. the Python sibling

The Python CLI has features we never ported. Each is a self-contained
addition.

### Trash lifecycle (`trash-list`, `trash-restore`, `trash-clear`)

The Python sibling has `trash-list`, `trash-restore-path`, and
`trash-clear` commands. The Dart version can trash items but has no
recovery path from the CLI — the user has to use the Internxt web UI.

Backend endpoints to add:
- `GET /storage/trash/paginated` — list trash contents
- `POST /trash/restore` — restore a single item
- `DELETE /storage/trash/all` — empty trash

Estimated work: ~80 LOC + 3 unit tests + 2 live tests.

### Search (`search`, `find`)

Python has both server-side fuzzy search and a client-side recursive
wildcard `find`. Dart has neither. The server-side endpoint is
`POST /storage/items/search` (or similar — confirm against Python's
`api.py`).

Estimated work: ~60 LOC + 2 unit tests + 1 live test (with retry for
the 2-10s eventual consistency we saw in Python live tests — the
search index isn't immediate).

### `whoami`, `quota`, `config` commands

Three small commands the Python sibling exposes. `whoami` prints the
logged-in email; `quota` prints used/limit storage; `config` prints
the active config keys.

Estimated work: ~30 LOC each + 1 unit test each.

### Conflict-handling on upload (skip / overwrite / safety-pattern)

Python has a tested `on_conflict='skip'|'overwrite'|'safety_pattern'`
flag for the upload path. Safety-pattern uploads to a temp name first,
then renames the existing target to a `.bak` suffix, then promotes
the temp upload. The Dart impl has the conflict detection but only
prints "target exists, skipping" — no overwrite or safety-pattern path.

This is the highest-priority feature gap from a data-safety angle.
Without `safety_pattern`, a user re-uploading a file is one keystroke
away from losing the existing version.

Estimated work: ~120 LOC + 4 unit tests + 3 live tests (the live
tests are the only way to verify the right UUIDs land on the server
in each branch).

---

## Reliability work

### WebDAV provider — exists but lightly tested

`webdav_filesystem.dart` (788 LOC) implements the WebDAV server side
but has no unit tests. We removed 9 wrong `@override` annotations in
Phase 1, but that only fixed compile-time noise — the actual behaviour
under HTTP traffic is unverified.

Same shape as the Python sibling's gap (see Python `PLAN.md` section
F). The recommended path:

1. Start the WebDAV server in a background isolate on a free local
   port (127.0.0.1 only, no LAN exposure).
2. Run real HTTP requests against it: `OPTIONS`, `PROPFIND`, `MKCOL`,
   `PUT`, `GET`, `DELETE`, `MOVE`, `PROPPATCH`.
3. All ops inside the existing live-test sentinel folder.
4. Both the small-file (in-memory) and large-file (disk-buffer) paths
   on PUT.

This catches the macOS-Finder-specific quirks (`If: <token>`
conditional headers, `Depth: infinity`) and the disk-buffer streaming
path that's invisible to unit tests.

Estimated work: ~3 hours, +400 LOC of test code.

### Stale-cache audit

The `folderId`-vs-`folderUuid` cache bug we found in `_clearParentCache`
suggests the same shape may exist elsewhere. Audit every mutating
method to confirm cache invalidation:

- `moveFile`, `moveFolder` — do they invalidate **both** old and new
  parent caches?
- `renameFile`, `renameFolder` — same parent, but does the cache
  store names?
- `copyItem` — does the destination parent get the new entry?
- `updateFile` (after replace) — does the parent listing show the
  new metadata?
- `setFolderTimestamps` — does the parent show the updated mtime?

Each should be paired with a live test that does the mutation, then
re-resolves a path through the cache, then verifies the cached value
reflects the mutation. The path-cache layer is the trust root for
correctness from the user's perspective; one stale entry produces
"file not found" errors that are infuriating to debug.

Estimated work: ~2 hours of audit + ~5 live tests.

---

## Tooling

### CI

No GitHub Actions in this repo. Should mirror the Python sibling:

```yaml
- run: dart pub get
- run: dart analyze --fatal-infos
- run: dart format --output=none --set-exit-if-changed .
- run: dart test test/crypto_test.dart test/config_test.dart test/utils_test.dart
  # Live tests skipped in CI (no creds; see below)
```

The live suite stays opt-in via `IXT_ACCOUNT` / `IXT_PWD` env vars.
Same recommendation as Python: don't put real creds in GitHub Secrets
for a personal-use project.

Estimated work: 1 hour (one workflow file).

### `dart fix --apply` is dangerous

We learned this the painful way: `dart fix --apply` corrupted the
source on its first invocation (504 errors after autofix, including
158 undefined-identifier and 13 unterminated-string-literal errors —
the auto-style transforms mangled string interpolations). Don't run
it on this codebase. Use individual `dart fix` invocations with
`--code <name>` if you need a specific lint fix at scale, but not the
shotgun version.

Recorded in `LEARNINGS.md` so this is a one-time mistake.

### Coverage threshold

Once Phase 4 lands and per-module coverage is meaningful, set a CI
gate: `crypto.dart` and `auth.dart` must be 100%, total ≥ 80%. The
Python sibling has the same shape — non-trust-root code is allowed
to drop coverage on platform-specific or print-heavy branches that
unit tests can't exercise cleanly.

---

## Out of scope (explicit non-goals)

These are intentionally not on the roadmap:

- **Workspaces** — same decision as Python. Personal accounts only.
- **Sync engine** — that's the desktop client.
- **GUI** — wrong tool for a CLI.
- **Cross-account migration** — interesting, separate project.
- **Symlink to / from `cloud-dart`** — investigated; the cloud-dart
  copy at `~/code/cloud-dart/lib/services/internxt_client.dart` is a
  different tree (a Flutter app's embedded client, not the
  command-line tool). Not worth merging via symlink — they'll diverge
  on intent (CLI ergonomics vs. Flutter callbacks).

---

## Suggested next session

If you want to ship one more bundle of work, in order of value:

1. **Phase 4: split the monolith** (~4 hours) — unblocks measurable
   coverage, strict typing, and clean module boundaries. Required
   prerequisite for any of the gap work below.
2. **Conflict-handling on upload** (~3 hours) — biggest data-safety
   gap. Without `safety_pattern`, re-uploads are destructive.
3. **WebDAV reliability test rig** (~3 hours) — biggest real-world
   blind spot, mirrors what we'd recommended for Python.
4. **Trash lifecycle** (~2 hours) — closes the most-visible upstream
   functional gap.

Total: roughly two sessions. Would close every meaningful gap
identified by this audit and bring the Dart port to feature parity
with the Python sibling on everything except search.

If you can only do one: **Phase 4**. Everything else is much easier
once the file is split.
