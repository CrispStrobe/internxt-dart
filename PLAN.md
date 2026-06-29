# Plan / Roadmap

What's known to be unimplemented, broken, or worth porting from the
Python sibling ([`internxt-cli`](https://github.com/CrispStrobe/internxt-cli)).
The current 194-test suite (155 unit + 39 live) is the safety net
for everything below.

For what's been done already, see [`HISTORY.md`](HISTORY.md).
For lessons from the audit, see [`LEARNINGS.md`](LEARNINGS.md).

## Status snapshot (after Phase 6.c)

**Done:**
- Phase 4 — module split (10 modules at root)
- Phase 5 — 5 PINNED GAP feature ports (search, copy, update, listing, usage)
- Phase 7 — 10 perf/UX parity items (memory gate, parallel upload, batch mv, pre-scan + size-skip, cache TTL, progress, Ctrl+C, mtime column, size limit, WebDAV test rig)
- Phase 8 — 5 functional gaps closed (trash lifecycle, quota CLI, safety_pattern, WebDAV PUT preserves UUID)
- Phase 9 — doc sweep, GitHub Actions CI, `strict-casts: true` everywhere, publish-prep (pubspec / bin / CHANGELOG)
- Phase 9.5 — coverage gate in CI (per-file thresholds; gate script at `tool/check_coverage.dart`)
- Phase 9.6 — stale-cache audit + cache-invalidation fixes for `set{File,Folder}Timestamp`; pinned a gateway-side gap (Internxt silently overwrites `modificationTime` on PUT-meta) as a known-broken regression marker
- Phase 9.7 / 9.7.1 — extend coverage to `cache.dart`/`api.dart`/`auth.dart`; http-injectable refactor (optional `http.Client` on `makeRequest` + auth functions, MockClient pattern in tests)
- Phase 9.7.2 — drive unit coverage + extend http.Client injection to all 9 api.dart helpers + 11 drive.dart functions. New `test/drive_test.dart` (16 tests). Coverage gate adds `drive.dart` at 40% (actual 41.34%); `api.dart` jumps 30 → 48.89% as side-effect.
- Phase 9.8 — `strict-inference` + `strict-raw-types` re-enabled in analysis_options.yaml. 22 warnings surfaced + fixed (mostly `Future.delayed` missing type arg, bare `[]` in cast contexts, raw `Future`/`Iterable`/`Map`/`List` field types). Production code clean; test code follow-on cleanup landed in same commit.
- Probe + LEARNINGS update — `tool/probe_setmeta.dart` empirically maps the gateway's PUT-meta failure modes for both files (409 + silent overwrite) and folders (silent overwrite). Findings written into `LEARNINGS.md`. WebDAV file PROPPATCH (`InternxtFile.setStat`) now swallows the 409 (PROPPATCH is advisory).
- **Phase 6.a — lib/ restructure + 5 cloud-dart-enabling extensions.** All 11 root modules moved into `lib/`, public barrel at `lib/internxt_client.dart`, test imports switched to `package:internxt_client/...`. Plus the five extensions (B1–B5) the cloud-dart rewire required:
  - B1: `downloadFileBytes(...)` (UUID-based) on `InternxtClient` + extends Phase 9.7.1's http.Client injection to `getFileMetadata` and `getDownloadLinks`. New `test/download_test.dart` mocks the full streaming-decrypt pipeline.
  - B2: path facade upstreamed from cloud-dart as `lib/paths.dart` (extension methods on `InternxtClient`: `listPath`, `uploadFileBytes`, `downloadFileByPath`, `downloadFileBytesByPath`, `createFolderPath`, `deletePath`, `movePath`, `renamePath`). Added `bridgeUser` / `userIdForAuth` as InternxtClient state with the Phase 7.10 fallback (fresh login lacks `userIdForAuth` → fall back to `userId`). New `test/paths_test.dart`.
  - B3: `ConfigService({String? dataDir})` → `ConfigService({String? configPath})`. Symmetric `configPath` getter added later for cloud-dart's adapter to read.
  - B4: `networkUrl` / `driveApiUrl` → constructor-overridable instance fields with `defaultNetworkUrl` / `defaultDriveApiUrl` static constants. cloud-dart's Web build passes Vercel proxy paths.
  - B5: `ConfigStorage` interface (`exists` / `read` / `write` / `delete` / `init`) that `ConfigService` composes. Default `FileConfigStorage` mirrors prior file-IO behavior; `InMemoryConfigStorage` for tests. cloud-dart's Web build provides a `SharedPreferencesStorage` impl.
- **Phase 6.b — cloud-dart divergence audit.** See `AUDIT_6B.md`. Read-and-classify pass over cloud-dart's 4681-line `internxt_client.dart` plus 3 sibling files. Headline: cloud-dart was a pre-Phase-4 fork lacking all Phase 5/7/8/9 work; rewire was mechanical drop-in after B1–B5 landed. Validation pass mapped every adapter callsite to a matching package signature.
- **Phase 6.c — cloud-dart rewire.** Done in cloud-dart's commit `e0eecd2` (and live-verified in `322b010`). Removed ~4640 LOC of embedded protocol from `cloud-dart/lib/services/internxt_client.dart`; replaced with a 41-line shim re-exporting the package + a kIsWeb-aware `InternxtUrls` helper. Adapter rewired to construct from the package. Path facade comes from B2 upstream — cloud-dart's `internxt_client_extensions.dart` deleted. Live smoke test (`test/internxt_rewire_live_test.dart`) drives login → upload → download → trash through the rewired adapter against the real gateway: 5/5 pass. flutter analyze: 0 errors. flutter build macos + flutter build web both succeed. Multi-repo divergence is permanently closed.

**Open — independently shippable:**
- **Publish to pub.dev.** The package is consumed via git dep by cloud-dart (was path → switched to git in Phase 6.c follow-on so Vercel + CI work). Publishing v0.1.0 → v0.2.0 (with the B1–B5 + drive coverage + strict-inference work) would let cloud-dart pin a version constraint instead of `ref: main`. Wait until the API has had a couple of weeks of cloud-dart usage to surface any rough edges first.

**Open — small follow-ons (live regression markers, all currently firing as expected):**
- **Trash-listing latency.** Dedicated probe (`trash listing eventual-consistency latency` live test) measures: as of 2026-05-04, the trash index lag is **>30s** — a freshly-trashed file does NOT appear in `/storage/trash/paginated` within 30s of polling. The lifecycle test's 6s best-effort retry was always doomed. The probe will print the actual latency if/when Internxt fixes it.
- **`/users/me` 404.** Tightened to require a 404 specifically (was: any of {404, Not Found, Cannot GET}). Fires if the endpoint comes online.
- **`setFolderTimestamp` gateway-overwrite.** Gateway silently overwrites `modificationTime` with `now()` on PUT-meta. Pinned: `actualMtime - targetMtime > 60s`. Fires if the gateway honors the requested value.
- **`setFileTimestamp` 409 conflict.** NEW finding (parallel marker added 2026-05-04). PUT /files/{uuid}/meta with the documented plainName+type echo triggers a 409 "name already exists" — gateway uniqueness check doesn't exclude the file itself. Distinct from the folder behavior; this path can't even attempt the timestamp update. See LEARNINGS.md "On gateway gaps in PUT meta operations".

**Open — cloud-dart side:**
- **Add GitHub Actions to cloud-dart.** No CI workflow currently. Would catch any future drift like the placeholder signature mismatch we fixed during 6.c. Mirror internxt-dart's `.github/workflows/ci.yml`: `flutter analyze` + `flutter test` on push/PR to main. Skip live tests (need creds). ~30 min.

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

### Step 6b: audit cloud-dart's divergence — DONE

See `AUDIT_6B.md` for the full pass. Headline findings:

- **cloud-dart contributes essentially nothing back-ports-able as protocol.**
  It's a pre-Phase-4 fork lacking all Phase 5/7/8/9 work. ~6 months of
  internxt-dart progress hasn't propagated.
- **Two small upstream candidates:** the path-based facade
  (`internxt_client_extensions.dart`, 148 lines) and an in-memory
  `downloadFileBytes` wrapper. Both are useful for any consumer.
- **Five blockers (B1–B5)** identified by the validation pass that must be
  fixed in internxt-dart before 6.c can be a clean drop-in. All small;
  ~2h aggregate. Listed under Phase 6.a above.
- **Flutter-specific surface is small:** the `FilenFileSystem` subclasses
  (L4637–L4681) are dead code in the Flutter deployment (only the dead
  `InternxtCLI` instantiates them) — no extraction needed. Real Flutter
  bits are 13 `kIsWeb` branches that the B4/B5 extension points cover, plus
  the `InternxtClientAdapter` (130 lines) which stays in cloud-dart by design.

### Step 6c: rewire cloud-dart to consume the library

Per AUDIT_6B.md "Phase 6.c — concrete steps (revised post-validation)":

- Add `internxt_client` dep to cloud-dart's pubspec.yaml
- Delete `~4400 LOC` of embedded protocol + dead CLI + dead file-system code
- Swap imports throughout (`internxt_client.dart` → package import)
- Wire B4 (URL override) and B5 (`SharedPreferencesStorage` for Web) at the
  adapter construction site
- Fix `internxt_client_placeholder.dart` signatures to track published library
- Delete `internxt_client_extensions.dart` (path facade now upstream via B2)
- Smoke-test: login, list, upload, download, move, rename, trash

Estimated work: ~2 hours (was ~3 — facade port and config-storage abstraction
move into 6.a, leaving only mechanical drop-in here).

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

### Stale-cache audit — done (Phase 9.6)

Walked every mutating call site in `drive.dart` + `upload.dart`.
Findings:

- **Correct**: `moveFile`/`moveFolder` (clear src parent + invalidate
  dest), `renameFile`/`renameFolder` (clear src parent),
  `trashItems` (clear src parent), `restoreFromTrash` (invalidate
  dest, or fall through to `moveFile`/`moveFolder` which already
  invalidate), `createFolder` (invalidate parent),
  `createFileEntry` (invalidate dest folder, used by upload paths),
  `copyItem` (delegates to `uploadFile`), `updateFile` (invalidates
  current parent — UUID is preserved so source = dest).
- **Gap**: `setFileTimestamp` and `setFolderTimestamp` previously
  claimed "no cache invalidation needed" but cached listings
  *do* carry `modificationTime` (drive.dart:489 for files, 407
  for folders) and `ls --long` reads it (cli.dart:1514). Fixed
  both to call `_clearParent` before the PUT.

While adding a live test for the fix, two follow-on issues
surfaced on the live gateway:

1. `PUT /{files,folders}/{uuid}/meta` rejects partial bodies
   without `plainName` — returns 400 "Missing update file
   metadata". The Python sibling has the same bug (mock-tested
   only). Fixed by fetching current metadata and echoing
   `plainName`/`type` back unchanged in the payload.

2. Even with a valid payload, the gateway silently overwrites
   `modificationTime` with `now()` on every PUT — confirmed via
   direct GET-PUT-GET inspection. So the feature is end-to-end
   broken at the gateway level. Pinned as a known-broken live
   regression marker (`setFolderTimestamp known-broken marker`)
   that fires if Internxt fixes the endpoint.

Coverage: 4 new unit tests in `test/cache_test.dart` pinning
`clearParentCache`'s string-UUID keying as a Phase 3 regression
marker. Live regression marker for the gateway gap.

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

### Coverage threshold — done (Phase 9.5)

Per-file gate now in CI. Thresholds: `crypto.dart` 100%,
`utils.dart` 100%, `config.dart` 90%. Gate script at
`tool/check_coverage.dart`; CI runs `dart test --coverage=`,
formats with `coverage:format_coverage`, then invokes the gate.

The gate is intentionally per-file (not global). Most modules
(`auth.dart`, `api.dart`, `drive.dart`, `download.dart`,
`webdav_filesystem.dart`, large parts of `upload.dart` and
`cli.dart`) are exercised only via live tests and would zero
out a global average. Per-file thresholds protect the modules
that *are* unit-tested without forcing throwaway tests for the
rest. Expanding the gate is tracked under the "Auth/api/drive
unit coverage" follow-on above.

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

---

# Performance: within-file chunk concurrency (added 2026-06-29)

File-level concurrency ALREADY exists: `lib/upload.dart` has a `MemoryGate`
(~line 113) and a public `runWithConcurrency`-style pool (~172-201, `concurrency`
param) used for batch uploads (`workers`, default 4 — `uploadFiles`/`upload`,
~865). What is SEQUENTIAL is a SINGLE file: `start` is always requested with
`multiparts=1` (`lib/upload.dart` ~450), so every file is ONE streamed PUT
(`uploadChunkWithProgress` ~475 → `uploadFile` ~589), and downloads are ONE
streamed GET (`downloadFile` ~72 / `downloadFileStreamed` ~210). Mirror the
filen-dart "bounded chunk concurrency" work (read filen-dart PLAN.md
"Performance" + `LEARNINGS.md` first).

Internxt = **AES-CTR single keystream** (sequential, like a running hash) + **S3**.

## Step A — real multipart + parallel part uploads ✅ DONE
**Implemented** (`lib/upload.dart`). `startUpload` now takes `parts:` and
requests `multiparts=N`; a new `uploadPart` PUTs one part and returns its S3
ETag. A new `pushEncryptedShard` helper (used by both `uploadFile` and the
replace-file path) branches: ciphertext < 100 MiB → single PUT (unchanged);
≥ 100 MiB → true S3 multipart. The continuous-keystream ciphertext (one
`encryptStream` call, content hash computed once) is sliced into 30 MB parts via
`Uint8List.sublistView`; part PUTs run through the existing `runBoundedPool`
(concurrency = `uploadChunkWorkers`, default 4; CLI `upload --chunk-workers N`)
with `MemoryGate.acquire(partBytes)` per part. The parts manifest is filled BY
INDEX (`List.filled(parts, null)`), so finish-upload gets PartNumber 1..N in
order regardless of completion order; `runBoundedPool` surfaces the first part
failure. Unit tests: `test/multipart_upload_test.dart` (MockClient via
`runWithClient`): multipart branch + finish shard shape, small-file single-PUT,
manifest ordered under out-of-order completion, peak in-flight ≤ N, failing part
surfaced.

NOTE — gate nesting: `uploadFile` / `updateFileContent` already hold an outer
`MemoryGate.acquire(fileSize * 2)` across the whole upload, and the entire
ciphertext is RAM-resident (`encryptStream` returns the full buffer). So
`pushEncryptedShard` does NOT gate per-part: each part is a zero-copy
`Uint8List.sublistView` into the already-reserved buffer, and a nested per-part
acquire would deadlock against the outer reservation (the gate is process-wide
and non-reentrant). Concurrency is bounded by `runBoundedPool`. Verified live:
110 MB multipart upload round-trips byte-exact. (Also fixed: `generateKeys`
now retries `dart_pg`'s intermittently-flaky OpenPGP key generation.)

Original plan (kept for reference):
internxt-dart never does real multipart today. To get within-file upload
concurrency:
1. Request multipart: change `files/start?multiparts=1` (~line 450) to
   `multiparts=N` for files ≥ 100 MiB (N = ceil(size / 30 MB), capped at the server
   max). Parse the per-part `urls` + `UploadId` from the response — port the exact
   shape from internxt-cli `_perform_network_upload` (`services/drive.py:185`).
2. Producer/worker split: a SEQUENTIAL producer reads each 30 MB part, runs the CTR
   cipher IN ORDER and updates the content hash, then dispatches the part PUT through
   the existing pool (`runWithConcurrency` + `MemoryGate.acquire(partBytes)`).
3. Assemble the parts manifest ordered BY INDEX, then finish-upload with the
   multipart shard (UploadId + parts), mirroring internxt-cli.
Keep < 100 MiB files on the current single-PUT path.

## Step B — parallel ranged downloads ⬜ TODO (riskier; gate behind a flag)
`lib/download.dart` `downloadFile` (~72) streams one presigned S3 GET. S3 honors
HTTP `Range`. Split into N 16-B-aligned ranges, fetch concurrently (pool +
`MemoryGate`), write each at its offset (`RandomAccessFile.setPosition` +
`writeFrom` under a 1-permit lock; pre-`truncate`). AES-CTR is SEEKABLE: add a
decryptor that inits the counter at a 16-B-aligned offset (`counter += offset~/16`).

## CONSTRAINTS (both steps)
1. CTR encrypt/decrypt + content hash are strictly sequential (keystream/offset
   order); only the network transfer is parallel. Parts/ranges 16-B-aligned.
2. Order the parts manifest / range writes BY INDEX regardless of completion order.
3. Bound BYTES in flight with `MemoryGate` (30 MB parts — count is not enough).
4. Failures surfaced after join; fall back to sequential if Range unsupported
   (200 not 206) or the file is small.

## Tests (mirror `test/live_smoke_test.dart`, `@Tags(['live'])`, IXT_ACCOUNT/IXT_PWD)
Unit (MockClient): peak in-flight ≤ N; manifest ordered; seekable-CTR decrypt ==
plaintext; small files stay single-PUT / single-GET. `dart analyze` clean.
- [x] upload: peak parts in flight ≤ N (`test/multipart_upload_test.dart`)
- [x] upload: parts manifest ordered by PartNumber under out-of-order completion
- [x] small files (<100 MiB) stay single-PUT
- [ ] (Step B) seekable-CTR decrypt of an arbitrary aligned offset == plaintext
Live (`--tags live`): ≥100 MB upload byte-exact + faster than baseline; ranged
download byte-exact + faster; interrupted multipart resumes.
