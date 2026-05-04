# Phase 6.b — cloud-dart audit

Read-and-classify pass over `~/code/cloud-dart/lib/services/internxt_client.dart`
(and the three sibling files) against this repo's split. Input artifact for
Phase 6.c (rewire).

**Scope correction:** PLAN.md estimated ~2700 lines. Actual size is **4681
lines / 165KB** (`InternxtClient` class itself is 2623 lines, L1726–L4349;
the `InternxtCLI` block above it adds another 1682 lines; the rest is
`ConfigService` + a small Flutter tail).

## Lead — what this audit answers

The interesting question is **not** "is cloud-dart behind on protocol?" (it is —
it's a pre-Phase-4 fork lacking all Phase 5/7/8/9 work). The interesting
questions for Phase 6.c are:

1. **What does cloud-dart bring that internxt-dart should absorb?**
2. **What does cloud-dart's integration require internxt-dart to expose?**

Both are answered below. The full divergence catalogue is preserved in the
appendix as the basis for the rewire mechanics.

## (1) What cloud-dart brings — backport into internxt-dart

Two items, both small.

### A. Path-based facade — promote upstream

`internxt_client_extensions.dart` (148 lines) wraps `InternxtClient` with
path-oriented methods that resolve UUIDs internally. Today internxt-dart's
public functions take UUIDs everywhere; any non-CLI consumer wants this shape.

Methods to upstream:

| Extension method | Wraps |
|---|---|
| `listPath(path)` | `resolvePath` + `listFolders` + `listFolderFiles` |
| `uploadFile(bytes, name, targetPath)` | `upload` (single-file in-memory) |
| `downloadFileByPath(remote, local)` | `resolvePath` + `downloadPath` |
| `createFolderPath(path)` | `createFolderRecursive` |
| `deletePath(path)` | `resolvePath` + `trashItems` |
| `movePath(src, dst)` | `resolvePath` x2 + `moveFile`/`moveFolder` |
| `renamePath(path, newName)` | `resolvePath` + `renameFile`/`renameFolder` |

Implementation choice: extension methods on `InternxtClient` (shipped as
`paths.dart`, exported by the barrel). Roughly mechanical port with one
ergonomic improvement: the cloud-dart versions hardcode `onConflict: 'skip'`
and `preserveTimestamps: false` — upstream version should expose those as
named params.

Effort: ~30 min.

### B. `downloadFileBytes` (in-memory variant) — add to library

internxt-dart has `downloadFile` (full file → disk) and `downloadFileStreamed`.
cloud-dart has `downloadFileBytes` (returns `Uint8List`) — needed for in-RAM
file viewers (preview, image display, etc.). One thin wrapper to add: take the
streamed download and accumulate into a `BytesBuilder`.

Effort: ~15 min, +1 unit test.

That's it. Everything else cloud-dart contributes is **integration shape**
(adapter implementing `CloudStorageClient` interface; build-time placeholder
stub for disabled-Internxt builds), which stays in cloud-dart by design —
that's correct architecture, not work to backport.

## (2) What internxt-dart must expose — required for Phase 6.c

This is the load-bearing list. The library can't replace the monolith without
each of these.

| # | Requirement | Today's state | What to add |
|---|---|---|---|
| R1 | **Override URL constants** for Web (Vercel proxy paths). cloud-dart's `static String get networkUrl` returns `/api/internxt-network` on Web vs the real gateway on native. | `networkUrl` / `driveApiUrl` are top-level constants in `api.dart` | Make them constructor params on `InternxtClient` (or take a `URLs` config struct). Default to current values. |
| R2 | **HTTP client injection** for Web (skip custom User-Agent — browsers block it). | ✅ Phase 9.7.1 added optional `http.Client` to `makeRequest` + auth functions. | Already done. cloud-dart passes a Web-aware client. No new work. |
| R3 | **Config storage extension point** for `kIsWeb` SharedPreferences fallback. cloud-dart has `if (kIsWeb)` branches in `saveCredentials`/`readCredentials`/`clearCredentials` (+ batch state) that swap file-IO for `SharedPreferences`. | `ConfigService` is a single class doing file-IO directly. | Split file-IO into a tiny `ConfigStorage` interface that `ConfigService` composes. Default impl is the current file-IO; cloud-dart provides a SharedPreferences impl for Web. |
| R4 | **Public state fields** (`userId`, `bucketId`, `mnemonic`, `bridgeUser`). cloud-dart's adapter reads `_client.userId` directly (L28, L31, L36 of adapter file). | Already public fields on `InternxtClient` instance. | Verify they stay public after the lib/ restructure. Don't hide behind getters that change behavior. |
| R5 | **`login()` returns the full response map.** cloud-dart's adapter captures `_lastLoginResponse` for `AppState`. | `auth.dart`'s `login` returns `Map<String, dynamic>`. | ✅ Already fits. No work. |
| R6 | **Public API is a superset of placeholder stub's signatures.** `internxt_client_placeholder.dart` defines 18 method signatures that conditional-imports rely on; the real library must keep matching them or that file must be updated. | Mostly matches, since cloud-dart copied the surface from internxt-dart originally. | Audit signature compatibility once during 6.c. Any drift in default-param values needs to match. |

Net new work for internxt-dart to enable Phase 6.c: **R1 + R3 + (B from above)**.
R2/R4/R5/R6 are already covered or are validation, not coding.

## Implications for Phase 6.a (the lib/ restructure)

The lib/ move shouldn't change the API to be DI-heavy or interface-driven just
for cloud-dart. But while doing the move:

- Keep `InternxtClient` instance state public — cloud-dart's adapter reads it directly.
- Keep `login()` return type as `Map<String, dynamic>` — cloud-dart captures it.
- Add the URL override (R1) and `ConfigStorage` interface (R3) **at the same time** as the move, since both touch the public surface that cloud-dart will pin against.
- Add the path facade (item A above) and `downloadFileBytes` (item B) at the same time, so the first version cloud-dart depends on already has them.

This bundles ~1.5 hours of additional work into Phase 6.a, but it makes Phase
6.c a clean drop-in instead of a "publish, find a missing extension point,
publish a patch, retry" loop.

## Pre-flight validation — will the rewire actually work?

Hard validation pass: every callsite from cloud-dart that touches the embedded
client, against internxt-dart's published surface.

### Consumer surface (cloud-dart files that import the embedded client)

| File | Touches | What it accesses |
|---|---|---|
| `lib/main.dart` | `ConfigService` (named import only) | Constructs `ConfigService(configPath: ...)` for Internxt provider |
| `lib/services/app_state.dart` | `InternxtClientAdapter` (cast) + `ConfigService` (via `.config`) | Reads/clears credentials at logout/swap-provider points (5 sites) |
| `lib/services/cloud_storage_interface.dart` | `InternxtClientAdapter` (factory) | Constructs adapter when provider is internxt |
| `lib/services/internxt_client_adapter.dart` | `InternxtClient` (full) | Wraps client, implements `CloudStorageClient` |
| `lib/services/internxt_client_extensions.dart` | `InternxtClient` (full) | 7 path-based extension methods |
| `lib/services/internxt_client_placeholder.dart` | n/a — defines stub | Conditional-import build-disabled variant |
| `lib/services/webdav_filesystem.dart` | `FilenClient` only | **NOT a consumer of `InternxtClient`** — false positive in earlier grep (only imports `filen.dart`) |

`InternxtFileSystem`/`InternxtDirectory`/`InternxtFile` (the `FilenFileSystem`
subclasses at L4637–L4681) are referenced exactly once: at L336 inside the
dead `InternxtCLI` class. **They are dead code in the Flutter deployment**
and disappear when the CLI block goes. No need to relocate them in 6.c.

### Method-by-method parity check

Every call the adapter or extensions make on `InternxtClient`, mapped to
internxt-dart's published surface:

| cloud-dart call | internxt-dart equivalent | Match? |
|---|---|---|
| `client.userId` (read+write) | `String? userId;` field | ✅ public, mutable |
| `client.bucketId` (read+write) | `String? bucketId;` field | ✅ public, mutable |
| `client.config` (field) | `final ConfigService config;` | ✅ public |
| `client.login(email, pw, tfaCode: tfa)` | `login(String, String, {String? tfaCode}) -> Future<Map<String, dynamic>>` | ✅ exact signature |
| `client.is2faNeeded(email)` | `is2faNeeded(String) -> Future<bool>` | ✅ exact |
| `client.refreshToken()` | `refreshToken() -> Future<void>` | ✅ exact |
| `client.resolvePath(path)` | `resolvePath(String) -> Future<Map<String, dynamic>>` | ✅ exact |
| `client.listFolders(id, detailed: true)` | `listFolders(String, {bool detailed = false})` | ✅ compatible default |
| `client.listFolderFiles(id, detailed: true)` | `listFolderFiles(String, {bool detailed = false})` | ✅ compatible default |
| `client.upload(srcs, tgt, recursive:, onConflict:, preserveTimestamps:, include:, exclude:, bridgeUser:, userIdForAuth:, batchId:, saveStateCallback:)` | Same 11 named params, plus optional `workers = 4` and `cancellationToken` | ✅ superset (backwards-compatible) |
| `client.downloadPath(remote, localDestination:, recursive:, onConflict:, preserveTimestamps:, include:, exclude:, bridgeUser:, userIdForAuth:, batchId:, saveStateCallback:)` | Identical 11-param shape | ✅ exact |
| `client.downloadFile(uuid, bridgeUser, userIdForAuth, {preserveTimestamps:})` | Same shape | ✅ exact |
| `client.createFolderRecursive(path)` | Same | ✅ exact |
| `client.trashItems(uuid, type)` | Same | ✅ exact |
| `client.deletePermanently(uuid, type)` | Same | ✅ exact |
| `client.moveFile(uuid, destUuid)` | Same | ✅ exact |
| `client.moveFolder(uuid, destUuid)` | Same | ✅ exact |
| `client.renameFile(uuid, plainName, type)` | Same | ✅ exact |
| `client.renameFolder(uuid, name)` | Same | ✅ exact |
| `client.search(query, detailed:)` | Same | ✅ exact |
| `client.findFiles(start, pattern, maxDepth:)` | Same | ✅ exact |
| `client.printTree(...)` | Same | ✅ exact |
| `client.getTrashContent(limit: 1000)` | `getTrashContent({int offset = 0, int limit = 50})` | ✅ compatible (cloud-dart only passes `limit`) |
| **`client.downloadFileBytes(remote, onProgress:)`** | **MISSING** | ❌ must add (item B) |

### Gaps that block the rewire — and the fix

| # | Blocker | Fix | Where |
|---|---|---|---|
| B1 | `downloadFileBytes` missing on internxt-dart's `InternxtClient` | Add as ~10-line wrapper around streamed download with `BytesBuilder` accumulation | Phase 6.a |
| B2 | Path-facade methods (`listPath`, `uploadFile`-by-path, `downloadFileByPath`, `createFolderPath`, `deletePath`, `movePath`, `renamePath`) — adapter delegates to extension, extension currently lives only in cloud-dart | Port `internxt_client_extensions.dart` upstream (extension methods on `InternxtClient` or as a `paths.dart` module) | Phase 6.a |
| B3 | `ConfigService({required String configPath})` (cloud-dart) vs `ConfigService({String? dataDir})` (internxt-dart) — constructor param name and shape differ | Pick one: (a) rename internxt-dart `dataDir` → `configPath` (1-line breaking change in `config.dart` + tests + cli.dart callsite — affects 4 files); (b) cloud-dart updates `main.dart` to use `dataDir:`. **Recommend (a)** — `configPath` is a clearer name, internxt-dart only has 2 callsites, and `dataDir` is currently optional which makes the rename trivially backwards-compatible if we keep both for a release. | Phase 6.a (lib/ restructure is the natural moment) |
| B4 | URL override for Web build (Vercel proxy paths). cloud-dart's `static String get networkUrl` returns `/api/internxt-network` on Web | Make `networkUrl`/`driveApiUrl` non-static fields with constructor defaults. Cloud-dart constructs `InternxtClient(config: ..., networkUrl: '/api/internxt-network', driveApiUrl: '/api/internxt-drive')` for Web build | Phase 6.a |
| B5 | Web `ConfigService` swap to `SharedPreferences` (cloud-dart has 13 `kIsWeb` branches) | Extract a `ConfigStorage` interface (4 methods: `read`, `write`, `delete`, `list`). Default impl is current file-IO. Cloud-dart provides a `SharedPreferencesStorage` impl. Wire via `ConfigService({Storage? storage})` constructor param | Phase 6.a |

### Non-blocking issues found (cleanup, not rework)

- **Placeholder file's `login` return type wrong**: `Future<Map<String, String?>>` should be `Future<Map<String, dynamic>>`. Currently incorrect in cloud-dart's `internxt_client_placeholder.dart` L32. Adapter expects dynamic; the stub would actually fail to substitute correctly. Fix during 6.c when the placeholder is updated to track the published library.
- **`_CacheEntry` class** at L38 of cloud-dart's file — disappears with the protocol class replacement; no consumer outside InternxtClient.
- **`InternxtCLI`** (L44–L1454, ~1700 LOC) — confirmed unreferenced by Flutter binary. Only callsite is its own `main()` at L32. Delete wholesale in 6.c.
- **`InternxtFileSystem`/`InternxtDirectory`/`InternxtFile`** (L4637–L4681) — only callsite is L336 inside the dead `InternxtCLI`. Delete wholesale in 6.c. **No need for a `cloud-dart/lib/services/internxt_flutter/file_system.dart` extraction** — earlier audit framing was wrong about needing to keep these.

### GO/NO-GO

**GO**, conditional on Phase 6.a doing **all five of B1–B5**. Each is small (B1 ≈ 15 min, B2 ≈ 30 min, B3 ≈ 5 min, B4 ≈ 20 min, B5 ≈ 45 min — total ~2h on top of the existing ~1h lib/ restructure).

If any of B1–B5 is skipped, 6.c will fail mid-rewire and require an internxt-dart patch + republish + retry. Better to bundle them.

After 6.a includes all five, Phase 6.c is genuinely a mechanical drop-in:
1. Swap imports (1 search/replace per file).
2. Delete the embedded protocol class + dead CLI + dead file-system classes (~4400 LOC removed).
3. Implement `SharedPreferencesStorage` (≈30 LOC).
4. Wire URL overrides into adapter constructor.
5. Smoke-test the 7 user flows (login, list, upload, download, move, rename, trash).

## Phase 6.c — concrete steps (revised post-validation)

Assumes Phase 6.a has landed with all of B1–B5.

1. **Add dependency.** `cloud-dart/pubspec.yaml` adds `internxt_client` (path or git ref). Verify `pointycastle`, `bip39`, `http`, `args` version overlap. Pin compatible ranges.

2. **Replace the protocol class.** Delete L1726–L4349 (`InternxtClient` + state), L4624 (`formatSize`). Add `import 'package:internxt_client/internxt_client.dart';`. Net: -2700 LOC.

3. **Delete the dead CLI.** Remove L1–L1725 (the `main`, `_CacheEntry`, full `InternxtCLI` class, and `handleDownload` function). Confirmed unreferenced by Flutter binary. Net: -1725 LOC.

4. **Delete the dead file-system classes.** Remove L4637–L4681 (`InternxtFileSystem`/`InternxtDirectory`/`InternxtFile`). Confirmed only callsite is in the dead `InternxtCLI`. Net: -45 LOC.

5. **Construct the client with Flutter URLs.** In the adapter, pass `networkUrl` / `driveApiUrl` overrides for Web build via the new B4 constructor params:
   ```dart
   InternxtClient(
     config: config,
     networkUrl: kIsWeb ? '/api/internxt-network' : null, // null → default
     driveApiUrl: kIsWeb ? '/api/internxt-drive' : null,
   )
   ```

6. **Provide Flutter ConfigStorage.** Create `cloud-dart/lib/services/internxt_flutter/shared_prefs_storage.dart` implementing the published `ConfigStorage` interface (B5). Wire via the adapter's `ConfigService(storage: kIsWeb ? SharedPreferencesStorage() : null)`. ~30 LOC.

7. **Provide Flutter http.Client.** Construct an `http.Client` that doesn't set custom User-Agent on Web (Phase 9.7.1 pattern). Pass to the adapter, which forwards to library calls.

8. **Update sibling files.**
   - `internxt_client_adapter.dart`: switch relative import to `package:internxt_client/internxt_client.dart`. Remove the now-redundant `internxt_client_extensions.dart` import (path facade comes from the package via B2).
   - `internxt_client_extensions.dart`: **delete the file**. Its 7 methods are now in the published library.
   - `internxt_client_placeholder.dart`: fix `login` return type (`Map<String, String?>` → `Map<String, dynamic>`). Audit other signatures against the published library and update.

9. **Update `main.dart`.** L15 import: `import 'package:internxt_client/internxt_client.dart' show ConfigService;` (assuming B3 chose the rename to `configPath`). L122: keep `ConfigService(configPath: configPath)` as-is.

10. **Update `app_state.dart`.** L21 import: drop `import 'internxt_client.dart'` (only used for `InternxtClient` type-checking which goes through the adapter). All callsites already go through `InternxtClientAdapter`.

11. **Smoke-test.** Run cloud-dart's tests + manual flows: login (with and without 2FA), list root, upload a file, download a file, move a file, rename a file, trash a file. Protocol identical (replacement is a near-superset of what cloud-dart had).

12. **Tag internxt-dart v0.2.0**, pin cloud-dart's pubspec to it.

Total cloud-dart LOC change: **−4470, +~50**. Net −4420 LOC.

## Risks (revised)

- **`userIdForAuth` field.** internxt-dart's `setAuth` handles fresh-login (no `userIdForAuth` yet → fall back to `userId`). cloud-dart's adapter reads `_client.userId` directly. Verify the published lib's behavior matches the adapter's expectations (or update the adapter to read whichever is canonical).
- **Cache duration change.** internxt-dart's 1-hour TTL vs cloud-dart's 5 minutes. Verify the Flutter UI doesn't have UX expectations about freshness. If it does, expose TTL as a constructor param.
- **Vercel proxy paths.** Web build relies on those — R1 (URL override) is load-bearing; don't ship without it.
- **Cache invalidation behavior diff.** cloud-dart's buggy `_clearParentCache` (folderId-int silent no-op) gets replaced with a working version. UI flows that previously got stale listings after rename/move/trash will refresh correctly. Fix, not regression, but observable timing change.
- **20GB upload limit.** internxt-dart fail-fasts >20GB; cloud-dart currently doesn't. Post-rewire, very large uploads will fail-fast instead of churning. Probably desirable but visible.

## Estimated effort

| Phase | Work | Time |
|---|---|---|
| 6.a (revised) | lib/ restructure + R1 (URL override) + R3 (ConfigStorage) + item A (path facade) + item B (downloadFileBytes) | ~2.5 hours (was ~1) |
| 6.c (revised) | mechanical drop-in: delete monolith, swap imports, wire R1/R3 impls, move Flutter tail | ~2 hours (was ~3, since the facade port is now upstream and R1/R3 are pre-baked) |

Net: ~4.5 hours total, vs. ~4 hours under the original plan. Slightly more
work upfront in 6.a buys a much cleaner 6.c with no "publish a patch and
retry" cycle.

---

# Appendix — full divergence catalogue (the original audit)

The Flutter-specific surface is small and well-isolated:
- ~50 lines of `FilenFileSystem` adapter classes at the file tail (L4637–L4681).
- 13 `kIsWeb` branches scattered through HTTP / config / I/O paths.
- The two real Flutter-integration files are tiny: `internxt_client_adapter.dart`
  (130 lines) and `internxt_client_extensions.dart` (148 lines).
- `internxt_client_placeholder.dart` (159 lines) is build-time stub
  infrastructure for "Internxt support disabled" builds.

cloud-dart's `internxt_client.dart` is a **fork-point copy from before Phase 4**
(the module split) with **no Phase 5 / 7 / 8 features** and **no Phase 9.6 / 9.7
fixes**. ~6 months of internxt-dart work has not propagated.

## Three-bucket breakdown

### (a) Backport candidates — cloud-dart ahead

**Empty.** No protocol/feature work in cloud-dart that internxt-dart lacks.

The only candidate worth considering for "promoting upward" is the path-based
facade in `internxt_client_extensions.dart` (`listPath`, `uploadFile(path)`,
`downloadFileByPath`, `createFolderPath`, `deletePath`, `movePath`,
`renamePath`). These are useful for any consumer, not Flutter-specific. Worth
adding to internxt-dart's public library surface as part of Phase 6.a or 6.c —
**not because cloud-dart is "ahead"**, but because they're the natural ergonomic
wrappers a library consumer wants. Estimated ~30 min once the lib/ restructure
exists.

### (b) Genuinely Flutter-only — stays in cloud-dart

| Block | Lines | Stays as |
|---|---|---|
| `InternxtFileSystem extends FilenFileSystem` + `Directory` + `File` adapters | L4637–L4681 (~45 LOC) | `cloud-dart/lib/services/internxt_flutter/file_system.dart` |
| `kIsWeb` branches in `networkUrl` / `driveApiUrl` (Vercel proxy paths for Web build) | L1727–L1735 | Local override — wrap or subclass the published `InternxtClient` to provide alternate URLs |
| `kIsWeb` branches in `_makeRequest` (skip custom User-Agent on Web) | L2012–L2015 | Same — solved by the http.Client injection that landed in Phase 9.7.1; cloud-dart can pass a Web-aware client |
| `kIsWeb` branches in `ConfigService` (SharedPreferences vs filesystem) | scattered in L4349–L4621 | `cloud-dart/lib/services/internxt_flutter/config_service.dart` — own subclass implementing the config interface |
| `internxt_client_adapter.dart` (130 lines) — `CloudStorageClient` interface impl | full file | Stays — multi-provider abstraction (Filen / SFTP / WebDAV / Internxt) |
| `internxt_client_placeholder.dart` (159 lines) — build-time disabled stub | full file | Stays — Flutter conditional-import pattern |
| `internxt_client_extensions.dart` (148 lines) | full file | **Move upstream** to internxt-dart as path-based facade (see (a)) |

**Total Flutter-only LOC: ~250–400** depending on how the `kIsWeb` branches
get refactored. The 4681-line file is mostly **not** Flutter-specific — it's
just an old copy of the protocol.

### (c) Drift — internxt-dart is ahead, delete cloud-dart's copy

This is essentially the entire `InternxtClient` class (L1726–L4349) plus
`ConfigService` (L4349–L4621) plus `formatSize` (L4624). The **whole thing**
gets replaced by `import 'package:internxt_client/internxt_client.dart'` in
Phase 6.c.

The `InternxtCLI` block (L44–L1454, ~1700 lines) is **dead code** in the
Flutter app — only referenced by its own `main()` at L32 (which the Flutter
binary never invokes). Phase 6.c can delete this block entirely.

The `void main()` entrypoint (L32) and `_CacheEntry` (L38) at the very top
are only relevant to the dead `InternxtCLI` and disappear with it.

## Per-method classification: `InternxtClient` (L1726–L4349)

Method names match between the two repos almost 1:1 — cloud-dart uses
`_underscore`-prefixed private versions of what internxt-dart promoted to
public functions in Phase 4 + Phase 2. The classification below is therefore
"protocol method X has identical behavior, with the following deltas."

Legend:
- **=** identical or near-identical to internxt-dart (no Phase 5/7/8 changes apply)
- **▽** internxt-dart ahead — cloud-dart copy is buggy/stale; replace
- **▲** cloud-dart ahead — backport candidate (none found except as noted)
- **F** Flutter-only — keep separately

### State + setup

| cloud-dart symbol | line | vs. internxt-dart | Notes |
|---|---|---|---|
| `static String get networkUrl` | L1727 | F | `kIsWeb`-conditional Vercel proxy URL |
| `static String get driveApiUrl` | L1733 | F | Same |
| `static const appCryptoSecret` | L1736 | = | Hardcoded constant |
| 8 nullable session fields | L1741–L1748 | ▽ | **Missing `userIdForAuth`** (Phase 7.10 fix). cloud-dart has `userId`, `bridgeUser` only |
| `static const _cacheDuration = Duration(minutes: 5)` | L1751 | ▽ | Phase 7.5 bumped to 1 hour in internxt-dart |
| `_folderCache`, `_fileCache` maps | L1752–L1753 | = | Same shape |
| `_isRefreshingToken` lock | L1756 | = | Same |
| `setAuth(creds)` | L1766 | ▽ | Doesn't hydrate `userIdForAuth` (the Phase 7.10 bug — fresh login lacks the field; fix is to fall back to `userId` if absent) |

### HTTP layer

| cloud-dart symbol | line | vs. internxt-dart | Notes |
|---|---|---|---|
| `_makeRequest` | L1993 | ▽ | Same shape (5xx exponential backoff, network-error retry). **Missing**: `http.Client` injection (Phase 9.7.1). Has noisy `print('🌐 [HTTP Request]')` debug output not gated by `debugMode` |
| `_apiRefreshToken` | L1785 | = | Identical to internxt-dart's `apiRefreshToken` |
| `refreshToken` | L1865 | = | Same |

### Auth + crypto

| cloud-dart symbol | line | vs. internxt-dart | Notes |
|---|---|---|---|
| `is2faNeeded` | L2076 | = | Same |
| `_encryptPasswordHash` | L2098 | = | Renamed `computeBridgePass` in internxt-dart (Phase 9.7); identical body |
| `_computeBridgeAuth` | L2117 | = | Same |
| `login` (with 2FA) | L2128 | = | Same flow |
| `_getSecurityDetails` | L2213 | = | Same |
| `_passToHash`, `_generateKeys`, `_encryptTextWithKey`, `_decryptTextWithKey`, `_getKeyAndIvFrom` | L2251–L2363 | ▽ | Body identical; cloud-dart still has `_underscore` prefix that Phase 2 removed in internxt-dart. Replace by importing `package:internxt_client/internxt_client.dart` (which exports them as top-level functions) |
| `_getFileDeterministicKey`, `_generateFileBucketKey`, `_generateFileKey`, `_decryptStream`, `_encryptStream` | L4277–L4348 | ▽ | Same: identical body, still `_`-prefixed |

### Cache invalidation

| cloud-dart symbol | line | vs. internxt-dart | Notes |
|---|---|---|---|
| `invalidateCache` (public) | L1810 | = | Same |
| `_invalidateCache` (private duplicate) | L2401 | ▽ | Dead duplicate — internxt-dart removed in Phase 4 audit |
| `_clearParentCache` | L2408 | ▽ | **Has the Phase 3 bug**: `metadata['folderId'] ?? metadata['folderUuid']` — uses legacy int field first, which silently no-ops cache invalidation. Fix: use `folderUuid`/`parentUuid` only |

### Listings + path resolution

| cloud-dart symbol | line | vs. internxt-dart | Notes |
|---|---|---|---|
| `listFolders` | L2437 | = | Same pagination + cache logic |
| `listFolderFiles` | L2519 | = | Same |
| `resolvePath` | L2609 | = | Same |
| `getFileMetadata` | L2231 | = | Same |
| `getFolderMetadata` | L2240 | = | Same |
| **MISSING**: `listFolderWithPaths` | — | ▽ | Phase 5.b — not ported to cloud-dart |

### Folder ops

| cloud-dart symbol | line | vs. internxt-dart | Notes |
|---|---|---|---|
| `_createFolder` | L3122 | = | Same |
| `createFolderRecursive` | L3153 | = | Same conflict-resolution logic |
| `_resolveOrCreateRemoteFolder` | L3760 | = | Same |
| `_buildFullPath` | L4071 | = | Same |

### Move / rename / trash / timestamps

| cloud-dart symbol | line | vs. internxt-dart | Notes |
|---|---|---|---|
| `moveFile` | L3884 | = | Same |
| `moveFolder` | L3900 | = | Same |
| `renameFile` | L3920 | = | Same |
| `renameFolder` | L3940 | = | Same |
| `_apiUpdateFileMetadata` | L3954 | ▽ | Missing the Phase 9.6 fix (PUT meta requires echoing `plainName`/`type` back unchanged or it 400s) |
| `_apiUpdateFolderMetadata` | L3967 | ▽ | Same Phase 9.6 fix missing |
| `setFileTimestamp` | L3980 | ▽ | **No cache invalidation** — has the explicit (wrong) comment "No cache invalidation needed". Phase 9.6 fixed |
| `setFolderTimestamp` | L3988 | ▽ | Same — Phase 9.6 fixed in internxt-dart |
| `_deleteFilePermanently` | L3260 | = | Same |
| `_deleteFolderPermanently` | L3996 | = | Same |
| `trashItems` | L4006 | = | Same |
| `deletePermanently` | L4024 | = | Same |
| `getTrashContent` | L3820 | = | Same shape; no eventual-consistency retry (Phase 8.1+ work) |
| **MISSING**: `clearTrashAll` | — | ▽ | Phase 8.1 — not ported |
| **MISSING**: `restoreFromTrash` | — | ▽ | Phase 8.1 + the 404 fallback to `PATCH /files/{uuid}` with `destinationFolder` |

### Upload pipeline

| cloud-dart symbol | line | vs. internxt-dart | Notes |
|---|---|---|---|
| `uploadFile` (public, simple) | L1816 | = | Same |
| `_startUpload` | L3270 | = | Same |
| `_uploadChunkWithProgress` | L3296 | = | Same |
| `_uploadChunk` | L3344 | = | Same |
| `_finishUpload` | L3358 | = | Same |
| `_createFileEntry` | L3375 | = | Same |
| `_uploadFile` (orchestrator) | L3393 | ▽ | Missing 20GB upper bound check (Phase 7.9). No `MemoryGate`/`runBoundedPool` integration |
| `uploadThumbnailAsync` | L3450 | ▽ | **Dead code** — internxt-dart removed in Phase 4 audit. Never called anywhere in cloud-dart either (verified) |
| `uploadSingleItem` | L3466 | ▽ | Missing `safetyPattern` enhancement (Phase 8.4) |
| `upload` (batch) | L3579 | ▽ | Missing parallel-pool ergonomics (Phase 7.2/7.3), throttled progress (Phase 7.6), Ctrl+C cancellation (Phase 7.7) |
| **MISSING**: `MemoryGate` class | — | ▽ | Phase 7.1 |
| **MISSING**: `CancellationToken` class | — | ▽ | Phase 7.7 |
| **MISSING**: `ProgressLine` class | — | ▽ | Phase 7.6 |
| **MISSING**: `runBoundedPool` | — | ▽ | Phase 7.2 |
| **MISSING**: `shouldSkipForSizeMatch` | — | ▽ | Phase 7.4 |
| **MISSING**: `copyItem` | — | ▽ | Phase 5.c |
| **MISSING**: `updateFile` | — | ▽ | Phase 5.d (replace-in-place) |
| **MISSING**: `_safetyPatternUpload` | — | ▽ | Phase 8.4 |

### Download pipeline

| cloud-dart symbol | line | vs. internxt-dart | Notes |
|---|---|---|---|
| `_getDownloadLinks` | L3791 | = | Same |
| `_getNetworkAuth` | L3809 | ▽ | Dead helper in internxt-dart (Phase 4 audit removed); cloud-dart still has it but only the auth-chain refresh path uses it |
| `downloadFile` (full file → disk) | L2709 | = | Same |
| `downloadFileStreamed` | L2802 | = | Same |
| `downloadFileBytes` (in-memory) | L1957 | F | This shape is what cloud-dart exposes via the adapter for in-RAM file viewing. internxt-dart has the streamed variant; the bytes variant is a thin wrapper worth adding to the published library surface |
| `downloadFileByPath` | L1906 | = | Same — also exposed via the extensions file |
| `downloadPath` (batch) | L2884 | ▽ | Missing throttled progress (7.6), cancellation (7.7), pre-scan + size-skip (7.4) |
| `_wait` | L2882 | ▽ | Trivial helper; dead in internxt-dart |

### Search / find / tree

| cloud-dart symbol | line | vs. internxt-dart | Notes |
|---|---|---|---|
| `_apiSearchFiles` | L4043 | = | Same as `searchFiles` in api.dart |
| `_apiGetFolderAncestors` | L4058 | = | Same as `getFolderAncestors` in api.dart |
| `search` | L4097 | = | Same |
| `findFiles` | L4143 | = | Same |
| `printTree` | L4213 | = | Same |
| `shouldIncludeFile` | L2858 | = | Same — moved to `utils.dart` in internxt-dart |

### API helpers — missing entirely from cloud-dart

| internxt-dart symbol | Module | Phase | Notes |
|---|---|---|---|
| `getStorageUsage` | api.dart L252 | 5 | Quota CLI |
| `replaceFile` | api.dart L271 | 5 | File replace-in-place |
| `restoreItem` | api.dart L293 | 8.1 | Trash restore |
| `clearTrash` | api.dart L319 | 8.1 | Trash empty |
| `getUserInfo` | api.dart L341 | — | Live test marks this as known-404 |

## Per-method classification: `InternxtCLI` (L44–L1454)

**All dead code in cloud-dart's deployment.** Only entrypoint reference is
`void main()` at L32, which the Flutter binary never invokes. Phase 6.c
deletes this entire block (1411 LOC).

The CLI commands present (`handleLogin`, `handleListTrash`, `handleRestoreUuid`,
`handleRestorePath`, `handleMovePath`, `handleRenamePath`, `handleTrashPath`,
`handleDeletePath`, `handleList`, `handleListUUID`, `handleUpload`,
`handleDownloadPath`, `handleConfig`, `handleTest`, `handleSearch`, `handleFind`,
`handleTree`, plus WebDAV start/stop/status/mount/test/config) are an early
fork of internxt-dart's `cli.dart` — predates Phase 5/7/8 work. internxt-dart's
modern equivalents are in `cli.dart` (the InternxtCLI class at L48 + `main` at
L43). Nothing here is ahead of internxt-dart.

## Per-class classification: `ConfigService` (L4349–L4621) + `formatSize` (L4624)

| cloud-dart symbol | line | vs. internxt-dart | Notes |
|---|---|---|---|
| `ConfigService` constructor + path getters | L4349–L4411 | F | `kIsWeb` branches for SharedPreferences fallback. internxt-dart has the native-only version |
| `saveWebdavPid` / `readWebdavPid` / `clearWebdavPid` | L4415–L4448 | = | Same as internxt-dart's `config.dart` |
| `generateBatchId` / `getBatchStateFilePath` | L4451–L4458 | = | Same |
| `loadBatchState` / `saveBatchState` / `deleteBatchState` | L4463–L4541 | = | Same |
| `saveCredentials` / `readCredentials` / `clearCredentials` | L4544–L4621 | F | `kIsWeb` branches for SharedPreferences. internxt-dart has native-only |
| `formatSize(dynamic)` | L4624 | = | Identical to `utils.dart` |

For Phase 6.c: cloud-dart needs a Flutter `ConfigService` subclass (or composition wrapper) that swaps the file-IO portions for SharedPreferences when `kIsWeb`. The non-IO bits (PIDs, batch state, credential serialization shape) all come from the published library.

## Sibling files

### `internxt_client_adapter.dart` (130 lines) — KEEP IN cloud-dart

Implements `CloudStorageClient` interface. Wraps `InternxtClient` so AppState
can use the same abstraction across providers (Filen, SFTP, WebDAV, Internxt).
Captures `_lastLoginResponse` for AppState. **Pure Flutter integration. Stays.**

### `internxt_client_extensions.dart` (148 lines) — BACKPORT TO internxt-dart

Path-based facade extension methods on `InternxtClient`:
`listPath`, `uploadFile (path)`, `downloadFileByPath`, `createFolderPath`,
`deletePath`, `movePath`, `renamePath`. Useful for any consumer. Move
upstream as part of internxt-dart's public library surface (could be a
top-level `paths.dart` module or extension methods on the client class).

### `internxt_client_placeholder.dart` (159 lines) — KEEP IN cloud-dart

Build-time stub for "Internxt support disabled" builds. Throws `UnsupportedError`
from every method. Used via Flutter's conditional-import pattern. **Stays.**

## Phase 6.c — concrete steps

Line counts assume Phase 6.a has landed (`lib/internxt_client/` + barrel exists).

1. **Add dependency.** In `cloud-dart/pubspec.yaml`, add either a path
   dependency (`internxt_client: { path: ../internxt-dart }`) or git ref. Verify
   `pointycastle`, `bip39`, `http`, `args` version overlap. Pin compatible
   ranges if needed.

2. **Replace the protocol class.** Delete L1726–L4349 (InternxtClient + cache
   entry), L4624 (formatSize). Replace with
   `import 'package:internxt_client/internxt_client.dart';`.
   Net: -2700 LOC.

3. **Delete the dead CLI.** Remove L1–L1725 (the `main`, `_CacheEntry`, full
   `InternxtCLI` class, and `handleDownload` function). Confirmed unreferenced
   by Flutter binary. Net: -1725 LOC.

4. **Extract `ConfigService` to a Flutter subclass.** Move L4349–L4621 to a new
   file `cloud-dart/lib/services/internxt_flutter/config_service.dart` that
   either (a) extends the published `ConfigService` and overrides the
   `kIsWeb`-conditional methods, or (b) implements the same interface and
   composes the published one. Choice depends on which methods the published
   class makes virtual.

5. **Extract `kIsWeb` branches.** The 13 sites needing Flutter awareness boil
   down to: networkUrl/driveApiUrl (override the URL constants), `_makeRequest`
   User-Agent (use the Phase 9.7.1 `http.Client` injection), and ConfigService
   I/O (handled in step 4). Wrap or subclass the published `InternxtClient` in
   `cloud-dart/lib/services/internxt_flutter/web_aware_client.dart` if the URLs
   need overriding.

6. **Move FilenFileSystem adapters.** L4637–L4681 → `cloud-dart/lib/services/internxt_flutter/file_system.dart`.
   Update `import 'internxt_client.dart'` → package import.

7. **Update sibling files.** `internxt_client_adapter.dart` and
   `internxt_client_extensions.dart` change their relative `import 'internxt_client.dart'`
   to `import 'package:internxt_client/internxt_client.dart'` (or to the new
   Flutter wrapper from step 5 if needed). The placeholder file is unchanged.

8. **Backport the path-facade extensions** (separate, small commit in
   internxt-dart). Move `internxt_client_extensions.dart`'s 7 methods upstream.
   Add a `paths.dart` module or attach as extension methods.

9. **Smoke-test the Flutter app.** Run cloud-dart's existing test suite +
   manual flows: login, list root, upload a file, download a file, move,
   rename, trash. The protocol behavior should be identical (since the
   replacement is a near-superset of what cloud-dart had).

10. **Tag internxt-dart v0.2.0** and commit cloud-dart's pubspec to point at
    the published version.

## Risks

- **Crypto rename.** internxt-dart's Phase 2 dropped `_underscore` prefixes on
  10 crypto helpers. Any cloud-dart-internal call to `_passToHash` etc. must
  be updated. Grep should catch all of them — they only exist inside the
  embedded `InternxtClient` class which is being deleted wholesale.

- **`userIdForAuth` field.** internxt-dart's setAuth handles the case where
  fresh login doesn't have it (falls back to `userId`). cloud-dart's adapter
  layer reads `_client.userId` directly (L28, L31, L36 of adapter file). After
  6.c, those reads need to switch to whichever field is canonical post-login —
  verify the published `InternxtClient` exposes both or unifies them.

- **Cache duration change.** internxt-dart's 1-hour TTL is more aggressive
  than cloud-dart's 5 minutes. Worth verifying the Flutter UI doesn't have UX
  expectations about freshness (e.g., "pull to refresh" behavior). If it does,
  cloud-dart can override the TTL via a published constructor param if one
  exists, or live with the change.

- **Vercel proxy paths.** If the cloud-dart Web build relies on those proxy
  routes, the URL override (step 5) is load-bearing. Don't skip it.

- **Behavioral diff on cache invalidation.** cloud-dart's buggy
  `_clearParentCache` (folderId-int silent no-op) is being replaced with a
  working version. UI flows that previously got stale listings after rename/
  move/trash will now refresh correctly. This is a fix, not a regression, but
  it changes observable timing. Worth a smoke-test pass.

- **20GB upload limit.** internxt-dart raises a clear error >20GB; cloud-dart
  currently doesn't. Post-rewire, very large uploads will fail-fast instead
  of churning. Probably desirable but visible.

## Estimated effort for Phase 6.c

Original PLAN.md estimate: ~3 hours. Holds up — this audit confirms the
substantial work is mechanical (delete + replace + extract Flutter bits)
rather than reconciliation-heavy. The path-facade backport (item 8) is a
separate ~30 min item that could go either before or after the rewire.

## Appendix — confirmed Phase 9.6 / 9.7 drifts not yet propagated

These are the most recent fixes in internxt-dart that cloud-dart's copy
currently lacks. Listed for completeness; all are "delete cloud-dart's copy"
remedies in the rewire.

| Fix | internxt-dart commit | cloud-dart status |
|---|---|---|
| `setFileTimestamp` cache invalidation | b8f4e18 | wrong (explicit "no cache" comment at L3985) |
| `setFolderTimestamp` cache invalidation | b8f4e18 | wrong (same comment at L3993) |
| PUT meta requires `plainName`/`type` echo to avoid 400 | b8f4e18 | missing — would 400 on first attempt |
| `gateway silently overwrites modificationTime` known-broken marker | b8f4e18 | n/a (cloud-dart has no live tests) |
| http.Client injection for unit testability | e86a505 | missing |
| `computeBridgePass` rename + extraction | 0c8f96d | still inline in `_encryptPasswordHash` |
| Coverage gate | f48a1ae | n/a (no coverage tooling in cloud-dart) |

End of audit.
