# Plan / Roadmap

What's known to be unimplemented, broken, or worth porting from the
Python sibling ([`internxt-cli`](https://github.com/CrispStrobe/internxt-cli)).
The current 150-test suite (108 unit + 42 live) is the safety net
for everything below.

For what's been done already, see [`HISTORY.md`](HISTORY.md).
For lessons from the audit, see [`LEARNINGS.md`](LEARNINGS.md).

## Status snapshot (after Phase 8)

**Done:**
- Phase 4 — module split (10 modules at root)
- Phase 5 — 5 PINNED GAP feature ports (search, copy, update, listing, usage)
- Phase 7 — 10 perf/UX parity items (memory gate, parallel upload, batch mv, pre-scan + size-skip, cache TTL, progress, Ctrl+C, mtime column, size limit, WebDAV test rig)
- Phase 8 — 5 functional gaps closed (trash lifecycle, quota CLI, safety_pattern, WebDAV PUT preserves UUID)

**Open (ordered by next-up priority):**
1. CI workflow (GitHub Actions)
2. Re-enable `strict-casts` / `strict-inference` now that JSON parsing is contained
3. Phase 6 — publish as a Dart package + reunify with cloud-dart

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

### Step 6a — partially DONE (publish-prep landed in Phase 9.4)

Phase 9.4 (commit pending) shipped the publish-prep portion:

- pubspec.yaml has `description`, `homepage`, `repository`,
  `issue_tracker`, version `0.1.0`, and `executables: { inxt: inxt }`.
- `bin/inxt.dart` is the CLI entry-point (a thin shim over root
  `cli.dart`).
- `LICENSE.txt` → `LICENSE`, `readme.md` → `README.md`,
  `CHANGELOG.md` added.
- `dart pub publish --dry-run` accepts the package shape (only
  warning is "uncommitted files," which clears on commit).

**Still ahead — the full library restructure**, gated on cloud-dart
being ready to consume:

- Move modules to `lib/internxt_client/` (or `lib/src/`).
- Add `lib/internxt_client.dart` as the public barrel.
- Update internal cross-imports + test imports.
- Keep root `cli.dart` as a thin shim if/when needed for legacy
  test paths, OR drop it and migrate tests to package imports.

The publish-prep landed first because the restructure requires
disrupting test imports (`'../cli.dart'` → `'package:internxt_client/...'`)
across all `test/*.dart` files, and there's no concrete consumer
need yet. When cloud-dart is ready (step 6b/6c), we do the move
in one focused commit and tag v0.2.0.

Estimated remaining work: ~1 hour for the move itself.

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

## Functional gaps — all closed in Phases 5 and 8

| Item | Status | Where |
|---|---|---|
| Trash lifecycle (list/restore/clear) | DONE | Phase 8.1 |
| Search + find as CLI subcommands | DONE | already wired pre-8 |
| `whoami` / `config` CLI subcommands | DONE | already wired pre-8 |
| `quota` CLI subcommand | DONE | Phase 8.2 |
| Conflict-handling: `safety_pattern` | DONE | Phase 8.4 |
| File copy (`copy_item`) | DONE | Phase 5.c |
| File replace-in-place (`update_file`) | DONE | Phase 5.d |
| `list_folder_with_paths` enriched listing | DONE | Phase 5.b |
| WebDAV PUT-on-existing preserves UUID | DONE | Phase 8.5 |

See [`HISTORY.md`](HISTORY.md) for per-feature commit links and
implementation notes.

---

## Phase 7 — all closed

The Python sibling had ~6 months of post-audit polish since the
fork point: chunked uploads, memory-gated concurrency, parallel
worker pools, batch-mv ergonomics, throttled progress, clean Ctrl+C
abort. Phase 7 ported each one. See [`HISTORY.md`](HISTORY.md) for
the per-item commit table. All 10 sub-items closed:

| # | What | Commit |
|---|---|---|
| 7.1 | Memory-gated upload concurrency (`MemoryGate`) | `b820578` |
| 7.2 | `--workers N` parallel upload pool (`runBoundedPool`) | `d463197` |
| 7.3 | Batch-mv ergonomics (multi-source / dry-run / parallel / on-conflict) | `cf40f20` |
| 7.4 | Pre-scan + size-based skip on re-upload | `f4b1813` |
| 7.5 | Folder cache TTL 10 min → 1 hr | `83790d4` |
| 7.6 | Throttled progress counters (`ProgressLine`) | `ce661ad` |
| 7.7 | Ctrl+C clean abort (`CancellationToken`) | `f9e4b7c` |
| 7.8 | `list` shows Modified column | `8779029` |
| 7.9 | 20 GB upper bound + dynamic timeout | `9a9be42` |
| 7.10 | WebDAV reliability test rig + 2 real bug fixes | `81a182b` |

The original detailed Phase 7 plan ran ~180 lines here; collapsed
to this table since all items are now in HISTORY.md with full
commit references.

---

## Reliability work

### WebDAV provider — DONE in Phase 7.10

`test/webdav_live_test.dart` spawns the actual WebDAV server on a
free local port (127.0.0.1 only) and drives it with raw HTTP for
`OPTIONS`, `PUT`, `GET`, `DELETE`, `PROPFIND`. Caught two real
bugs in `webdav_filesystem.dart`: `InternxtFile.create()` threw
unconditionally (broke every PUT) and `creds['userIdForAuth']!`
was null on fresh login (auth value lives under two keys).

Possible follow-on tests if a future use case justifies them:
`MKCOL`, `MOVE`, `COPY`, `PROPPATCH`, the macOS-Finder-specific
quirks (`If: <token>` conditional headers, `Depth: infinity`).

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

### CI — open

No GitHub Actions in this repo yet. Workflow needs to mirror the
Python sibling's gates:

```yaml
- run: dart pub get
- run: dart analyze --fatal-infos
- run: dart format --output=none --set-exit-if-changed .
- run: dart test test/crypto_test.dart test/config_test.dart \
                  test/utils_test.dart test/cache_test.dart \
                  test/upload_test.dart test/cli_test.dart
  # Live tests stay opt-in via IXT_ACCOUNT / IXT_PWD env vars;
  # CI skips them (don't put real creds in GitHub Secrets for a
  # personal-use project).
```

Estimated work: 1 hour (one workflow file).

### `dart fix --apply` is dangerous (recorded in LEARNINGS.md)

`dart fix --apply` corrupted the source on its first invocation
during the audit. Use `dart fix --code <name>` for scoped fixes;
never the unscoped form.

### Strict casts / inference — open

`analysis_options.yaml` has `strict-casts` / `strict-inference`
disabled. Phase 4 contained the JSON parsing layer in `api.dart`,
so the dynamic-typed surface is now isolated. Re-enabling these
would surface ~50–100 real type imprecisions across the rest of
the codebase that we can fix incrementally.

Estimated work: 2 hours (turn on the flags, fix what surfaces).

### Coverage threshold — open

Set a CI gate: `crypto.dart` and `auth.dart` must be 100%, total
≥ 80%. Per-module coverage is now meaningful since Phase 4
extracted the modules.

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

(See the "Status snapshot" at the top for the current open-work
shortlist. The detailed "Suggested next session" prose that lived
here through Phase 4 has been retired — every item it pointed at
has either been done or is captured in a more specific section
above.)
