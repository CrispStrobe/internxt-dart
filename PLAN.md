# Plan / Roadmap

What's known to be unimplemented, broken, or worth porting from the
Python sibling ([`internxt-cli`](https://github.com/CrispStrobe/internxt-cli)).
The 73-test suite (61 unit + 12 live) at the end of the audit serves
as the safety net for everything below.

For what's been done already, see [`HISTORY.md`](HISTORY.md).
For lessons from the audit, see [`LEARNINGS.md`](LEARNINGS.md).

---

## Phase 4: split the monolith (complete)

**Status:** complete. cli.dart down from 4317 → 2176 LOC (a 50%
reduction). Nine sibling modules at the project root: `config.dart`
(152), `crypto.dart` (211), `utils.dart` (45), `cache.dart` (84),
`api.dart` (228), `auth.dart` (167), `drive.dart` (1022),
`upload.dart` (594), `download.dart` (460). Tests stay green via
thin delegating wrappers + re-exports. See `HISTORY.md` for the
per-extraction details and the final module layout table.

**State-vs-protocol split, consistent across all layers:** instance
state (the 7 session fields, `_isRefreshingToken` lock, two cache
maps) lives on `InternxtClient`; protocol / helper functions live
in their respective modules and take their dependencies as
parameters.

**Side-effects of the extraction worth keeping in mind:**
- `dart analyze` info-level lints fell from 39 → 19 because the
  long monolith methods carried several `prefer_final_locals` /
  `unnecessary_this` nits that disappeared with them.
- Three pre-existing dead-code follow-ups were caught in passing
  (the `istence` and `uploadThumbnailAsync` methods + the
  `_makeRequest` / `_invalidateCache` / `_getNetworkAuth` wrappers
  that became orphaned). Same shape as the Phase 1 dead-private-
  method audit; these were missed because the original audit rule
  was scoped to `_`-prefixed names and these had different
  naming.
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

### Search (`search`, `find`) — DONE in Phase 5 (live-tested)

`search` (server-side fuzzy via `GET /fuzzy/{query}`) and `findFiles`
(client-side recursive glob) are both in `drive.dart` and exercised
by live tests as of the live-test parity pass. The remaining work
is wiring them to user-facing CLI subcommands (the methods exist but
are not surfaced via `bin/inxt search` or similar).

### `whoami`, `quota`, `config` commands

Three small commands the Python sibling exposes. `whoami` prints the
logged-in email; `quota` prints used/limit storage; `config` prints
the active config keys.

`getStorageUsage` is **DONE in Phase 5.a** — the endpoint helper
exists in `api.dart`. What's missing is the `quota` user-facing
subcommand wiring.

Estimated work: ~30 LOC each + 1 unit test each.

### Conflict-handling on upload — partial (`skip` + `overwrite` DONE)

`onConflict='skip'` and `onConflict='overwrite'` are both implemented
in `upload.dart` and exercised by the live suite. Still missing:
`safety_pattern` (upload to temp name → rename existing to `.bak`
→ promote temp). Without it, the `overwrite` branch destroys the
previous version with no recovery path beyond Internxt's 30-day
trash.

Estimated work: ~80 LOC + 2 unit tests + 1 live test for the
`safety_pattern` branch alone.

### File copy (`copy_item`) — DONE in Phase 5.c

Implemented in `upload.dart` as the download → re-upload pattern
(no server-side copy endpoint exists). Live-tested.

### File replace-in-place (`update_file`) — DONE in Phase 5.d

Implemented in `upload.dart` as `updateFile` + `replaceFile`
endpoint helper in `api.dart`. Same UUID is preserved across
replace. Live-tested. **Wiring `updateFile` into the Dart WebDAV
layer's PUT-on-existing path is the remaining work** — currently
the WebDAV layer trashes + re-uploads, churning the UUID.

### `list_folder_with_paths` enriched listing — DONE in Phase 5.b

Library-level method in `drive.dart` returning entries annotated
with `path`, `displayName`, `sizeDisplay`, and `modified`. Live-
tested.

---

## Phase 7: performance + UX parity with the Python sibling

The Python sibling has had ~6 months of post-audit polish since the
fork point: chunked uploads, memory-gated concurrency, parallel
worker pools, batch-mv ergonomics, throttled progress, clean Ctrl+C
abort. The Dart port has the basic upload/download flows working
but lacks most of the perf/UX layer above them. This phase brings
the Dart port up to par.

Items are listed in implementation order — earlier ones are
prerequisites for later ones (memory gate must precede parallel
upload pool; pre-scan layer needs the per-parent cache to land
first).

### 7.1 Memory-gated upload concurrency

Python `cdaa7d7` ("limit uploads < oom") wraps every upload in a
`_mem_acquire` / `_mem_release` pair. The semaphore reserves
~`2 * file_size` (plaintext + encrypted copy held simultaneously),
blocks workers when free RAM falls below the reservation, and
releases half the reservation right after `del plaintext` once the
encrypt step completes.

Without this, the Dart port can OOM the process when uploading a
single large file on a small box, and the situation gets much
worse when 7.2 lands and N uploads happen concurrently.

**Status: GAP.** `uploadFile` reads the entire file into memory
(`localFile.readAsBytes()`), encrypts in place, then sends. No
back-pressure.

Estimated work: ~80 LOC for the gate (process-wide mutex over a
counter; condition variable to wake waiters on release) + ~20 LOC
of integration in `uploadFile` and `updateFile`. Unit-testable.

### 7.2 `--workers N` parallel upload pool

Python `3af32cb` runs the per-file upload pass in a
`ThreadPoolExecutor(max_workers=N)` with default 4. Per-file
operations are independent (each gets its own shard URL, encrypts
independently, hits a distinct network endpoint), so they
parallelize cleanly. Memory gate prevents OOM when N workers all
have large files in flight.

**Status: GAP.** `upload()` in `upload.dart` is a sequential `for`
loop over tasks.

Estimated work: ~80 LOC. Use bounded `Future`-pool pattern (no
isolates needed — Dart's I/O is async-friendly). Add `--workers`
arg parsing in cli.dart, default 4.

### 7.3 Batch-mv ergonomics (multi-source, dry-run, parallel, on-conflict)

Python `4ed03c9` rebuilt the `mv` command around rsync-style
multi-source semantics, parallel execution, dry-run preview, and a
conflict policy.

**Status: gap.** Dart `handleMovePath` accepts exactly two args
(source pattern + dest), runs sequentially, has no `--dry-run`,
no `--workers`, no `--on-conflict`, and doesn't filter "source
already in target" no-ops.

Estimated work: ~150 LOC. Mostly orthogonal to 7.1/7.2 (mv doesn't
have a memory pressure problem) but reuses the parallel-pool
helper from 7.2.

### 7.4 Pre-scan + Pass 1/Pass 2 + size/mtime skip

Python `3af32cb` restructured the recursive upload as:
- **Pre-scan**: list the remote target subtree once.
- **Pass 1 (mkdir)**: create remote folders, but skip everything
  that pre-scan already saw.
- **Pass 2 (uploads)**: per-file work, using the per-parent file
  cache that Pass 1 seeded — Pass 2 makes zero listing calls.
- **Per-file size/mtime skip**: re-uploads only when local size
  differs from remote (and mtime when `-p`).

**Status: gap.** Dart's `upload()` calls `createFolderRecursive`
on every parent (hits the 409-conflict-recovery path on every
existing folder), and `uploadSingleItem` calls `resolvePath` on
every file (lists the parent on cold cache).

Estimated work: ~120 LOC + 1 live test exercising the "re-run with
zero changes is a no-op" assertion.

### 7.5 Folder cache TTL 10m → 1h

Python `3af32cb` bumped `_FOLDER_CACHE_TTL_S` from 600 to 3600 to
avoid mid-batch cache misses on long uploads.

**Status: gap.** `cache.dart`'s `cacheDuration` is still
`Duration(minutes: 10)`.

Estimated work: 1 line. Worth a brief comment explaining the
tradeoff (staler reads vs fewer mid-batch refetches). Group with
7.4's commit since they're related.

### 7.6 Throttled progress counters for scan/plan/Pass 2

Python `f0889fb` added a `~5/sec` in-place counter to each phase:

```
  -> 📋 Scanning remote: 1,234 folders, 45,678 files
  -> 🔎 Planning: scanned 9,012, queued 8,500, skipped 512
  -> 📤 Uploaded 4,250/8,500 ( 50.0%) ok=4,200 err=50
```

Each phase finalizes its line with a force-flush + newline so the
next log message starts cleanly.

**Status: gap.** Dart has the per-file chunk progress (the streamed
PUT bar) but no scan/plan/batch counters — big batches show long
silences.

Estimated work: ~50 LOC. Tiny `_ProgressLine` helper that
debounces stdout writes to ~200 ms intervals. Hook into the
pre-scan, planning, and Pass-2 phases from 7.4.

### 7.7 Ctrl+C clean abort

Python `374a1be` wires SIGINT into the upload pipeline:
- `threading.Event` flag is set on Ctrl+C.
- Queued workers see the flag at the top of `_do_upload` and
  return `('cancelled', ...)` immediately.
- `executor.shutdown(wait=False, cancel_futures=True)` drops
  futures that haven't started yet.
- In-flight uploads finish their current network call (Python
  threads can't be killed mid-stream).
- Summary line still prints, with an "ABORTED by user" header
  and the cancelled count. Process exits 130.

**Status: gap.** Dart has nothing for cancellation. Ctrl+C just
kills the process mid-stream, leaving the batch-state file in
whatever state the last save left it.

Estimated work: ~80 LOC. Use `ProcessSignal.sigint.watch()` and a
shared `_Cancelled` flag threaded through the upload pipeline.
Needs to be wired through 7.2's parallel pool too — should land
together with or shortly after 7.2.

### 7.8 List shows mtime column

Python `764d9b1` added a Modified column to the `list` output.
The Python `list_folder_with_paths` already includes the
`modified` field (Python's name) → Dart's `modified` field via
Phase 5.b — **the data is there**; only the rendering column is
missing.

**Status: gap.** `handleList` in cli.dart shows Type / Name / Size
/ UUID. No timestamp column.

Estimated work: ~10 LOC. Format the existing `modificationTime` /
`updatedAt` field; widen the table by one column.

### 7.9 20 GB upper bound + dynamic timeout

Python `upload_file_to_folder` rejects files larger than
`TWENTY_GIGABYTES = 20 GB` up front, and computes a per-file
upload timeout as
`max(300, file_size / (100 KB/s)) + 60` seconds so very-large
uploads don't hit a fixed 30-second timeout mid-stream.

**Status: gap.** Dart has no upper bound; oversized files fail
later in the pipeline with confusing errors. There's no per-upload
timeout at all (the `package:http` `StreamedRequest` inherits
whatever the underlying client uses).

Estimated work: ~20 LOC. Defensive check at the top of
`uploadFile`/`updateFile`; pass a `Duration` into the streamed
PUT.

### 7.10 WebDAV reliability test rig

Already in the Reliability section below — listed here as #10
because it's in the same priority list. ~3 hours / ~400 LOC of
test code. Spawn the WebDAV server on a free local port, run real
HTTP requests against it (OPTIONS, PROPFIND, MKCOL, PUT, GET,
DELETE, MOVE, PROPPATCH), all inside the existing live-test
sentinel folder, both small (in-memory) and large (disk-buffer)
PUT paths.

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
