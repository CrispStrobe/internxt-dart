# Changelog

## 0.2.4 — Upload target compatibility and local read hardening

### Added
- **Upload target parsing now matches the Python CLI compatibility layer.**
  `upload` accepts `--path` as an alias for `--target`, normalizes Windows-style
  backslash remote paths, and still supports the legacy shorthand
  `upload SOURCE /Remote` / `upload SOURCE \Remote`.

### Fixed
- **Large local upload reads are chunked and retried.** The Dart encryption
  pipeline still expects whole-file bytes, but the disk read itself no longer
  uses one monolithic `readAsBytes()` call. It reads in 8 MiB chunks, retries
  transient read failures, and reports the failing offset.
- **Drive file-entry creation avoids obvious duplicates after ambiguous 5xx
  responses.** The `/files` POST now checks the destination folder after a
  server-side failure and returns the already-created entry if the backend
  accepted the create despite losing the response.

## 0.2.3 — Stop masking real API errors as 401

### Fixed
- **HTTP error responses no longer come back as a bogus `401 No
  authentication strategy detected`.** `makeRequest` threw its
  `API Error: <code> - <body>` exception *inside* its own `try`, so the
  function's `catch` swallowed it and retried — and that retry did not
  forward `isNetworkAuth` / `networkUser` / `networkPass`. The retried
  request therefore went out with no `Authorization` header at all, the
  gateway answered 401, and after `maxRetries` that 401 was what surfaced.
  The true error was destroyed.

  Observed symptom: uploading past your storage quota reported
  `401 No authentication strategy detected` instead of the real
  `420 Max space used`. This affected **every** network-auth call that
  received any 4xx — quota, not-found, conflict, rate-limit.

  Error responses are now raised as a typed [`ApiException`] carrying
  `statusCode` and `body`, and are no longer retried (the doc comment
  always said 4xx were surfaced, not retried — the code disagreed). Both
  retry paths now forward every auth argument they were called with.
  `ApiException.toString()` is still exactly `API Error: <code> - <body>`,
  so existing callers that string-match the prefix are unaffected.

### Added
- **`ApiException`** — exported. Prefer branching on `statusCode` over
  parsing the message string.
- **`dart_test.yaml` registering the `live` tag.** Previously the tag was
  unknown, so `dart test --exclude-tags=live` silently matched nothing and
  ran the live suites anyway — a slow surprise for anyone with credentials
  in `.env`. `test/live_smoke_test.dart` and `test/webdav_live_test.dart`
  are now tagged `live`. The tag has no blanket `skip:`; the suites already
  self-skip without `IXT_ACCOUNT`/`IXT_PWD` or with `DART_TEST_SKIP_LIVE=1`.

## 0.2.2 — Truncated-download guard, serial multipart uploads

### Fixed
- **Truncated downloads now fail with a clear error instead of a `RangeError`.**
  All three download paths (`downloadFile`, `downloadFileBytes`,
  `downloadFileStreamed`) trimmed the decrypted buffer to the server-reported
  plaintext size via `sublist(0, fileSize)`. When a download was truncated or
  corrupt — or the server reported a size larger than the bytes it delivered —
  that threw an opaque `RangeError (end): Not in inclusive range`. The paths now
  share a `_trimToFileSize` helper that rejects negative sizes and under-length
  buffers with `Incomplete download: got N bytes, expected M`. Behavior is
  unchanged when the buffer is complete.

### Changed
- **Multipart uploads default to serial part PUTs** (`--chunk-workers` default
  `4` → `1`) for gateway reliability on single large files (>= 100 MiB). Pass
  `--chunk-workers N` to restore parallel part uploads. Ranged *downloads* keep
  their default of 4 workers — the option now only lowers the download default
  when explicitly passed.

## 0.2.1 — CLI secure credentials, rcat, bounded-memory downloads

### Added
- **Secure credential input + at-rest encryption** for the CLI (parity with the
  Python CLI). `login` reads `INTERNXT_EMAIL` / `INTERNXT_PASSWORD` / `INTERNXT_2FA`
  env vars and supports `--password-stdin` (never enters argv/process list).
  Credentials are no longer stored as plaintext JSON: the file-backed CLI now
  writes a `{fmt,src,ct}` envelope encrypted with a wrapping key from
  `INTERNXT_CREDENTIALS_KEY` (else a static constant), and the file is `chmod 600`
  / the data dir `700`. Legacy plaintext files are migrated on first read. A
  custom injected `ConfigStorage` (e.g. CrispCloud's secure storage) is left
  untouched — it encrypts at its own layer, so this avoids double-encryption.
- **`rcat` — stream stdin to a Drive file** (parity with the Python CLI):
  `inxt rcat <remote_path>` reads stdin and uploads it to a single named Drive
  file (`mariadb-dump | xz | inxt rcat /backups/db.xz`). The parent folder is
  created if missing. Internxt needs the exact size up front, so the stream is
  spooled to a temp file (`--temp-dir` to relocate) to measure its size, then
  encrypted+uploaded in one pass via the existing single-item upload path. Empty
  stdin aborts non-zero; a TTY with no pipe is rejected.
- **Bounded-memory disk-streaming download** for the CLI (`download` /
  `download-path`): the decrypted file is now written straight to disk with peak
  RAM bounded by the in-flight range/chunk size, not the whole file — closing the
  memory-model gap with the Python CLI. Parallel ranged-to-disk
  (`downloadRangedToFile`, writes positionally into a `RandomAccessFile`) when
  `--ranged` is on and the file is large; otherwise a single streaming GET
  decrypted chunk-by-chunk via an incremental AES-CTR cipher
  (`crypto.downloadDecryptor`). Cross-platform (Linux/macOS/Windows). The
  in-memory functions (`downloadFile`, `downloadFileBytes`,
  `downloadFileStreamed`) are unchanged for consumers (WebDAV, Flutter/Web) that
  need the bytes in memory.

## 0.2.0 — within-file transfer concurrency

A single large file now transfers with **bounded concurrency** (multi-file
batch concurrency already existed).

### Added
- **Real S3 multipart + parallel part uploads (Step A):** files ≥ 100 MiB upload
  as multiple 30 MB parts in parallel (previously a single streamed PUT), bounded
  by the existing `MemoryGate`. AES-CTR encryption stays sequential; only the part
  PUTs overlap, and the parts manifest is ordered by index.
- **Parallel ranged downloads (Step B, opt-in `--ranged`):** large downloads fetch
  multiple HTTP byte-ranges concurrently and decrypt each via a seekable AES-CTR
  decryptor, reassembled by offset. Falls back to the single-stream path when the
  server doesn't honor `Range` or the file is small.

### Preserved
- Per-file batch concurrency unchanged; files < 100 MiB keep the single-PUT path
  and non-ranged downloads keep the single-stream path.

### Notes
- **Multipart upload is automatic** for files ≥ 100 MiB (the server's multipart
  floor); its part PUTs run in parallel by default (`--chunk-workers`, default 4).
  **Ranged download stays opt-in** (`--ranged`, default off).
- Ranged download is feature-on-parity with the Python CLI (same 30 MB
  16-byte-aligned ranges, 1-byte `Range` probe → single-GET fallback on non-206,
  per-range CTR-seek decrypt, offset-ordered reassembly, worker + `MemoryGate`
  bounding; available on both `download` and recursive `download-path`). The CLI
  download path now also streams to disk with bounded RAM (see Unreleased),
  matching the Python CLI; the in-memory `downloadRangedToMemory` remains for
  consumers that want the bytes in memory.

## 0.1.0 — initial publish-prep release

First version with a `pubspec.yaml` properly configured for
`pub publish`. The CLI binary `inxt` is the published executable;
the library surface (the same modules consumed today via
`import '../cli.dart';` from tests) will move to `lib/` in a
follow-on release once `cloud-dart` is ready to consume it.

For the full audit + extraction story, see
[`HISTORY.md`](HISTORY.md). Highlights of what's in 0.1.0:

### Core capabilities

- Login, refresh, bridge auth, 2FA — full Internxt auth dance.
- Drive operations: `list`, `mv`, `rename`, `trash`, `copy`,
  `update` (replace-in-place preserving UUID), recursive folder
  ops, search, find, tree.
- Encrypted upload pipeline: AES-CTR + per-file index, chunked
  PUT with progress, resumable batch state.
- Encrypted download pipeline: in-memory + streamed-to-disk
  variants.
- Cache-aware paginated listings + path resolution.
- WebDAV server bridging Internxt to standard file-system clients
  (HTTP via `shelf_dav`).

### Performance + UX (Phase 7)

- Memory-gated upload concurrency (avoids OOM on parallel large
  uploads).
- `--workers N` parallel upload pool (default 4).
- Pre-scan + size-based skip on re-upload (re-running an unchanged
  tree uploads zero files).
- Throttled progress counters for scan/upload phases.
- `Ctrl+C` clean abort with resumable state.
- 20 GB upper bound + dynamic timeout per file.

### Conflict policy + safety

- Upload `--on-conflict` accepts `skip`, `overwrite`,
  `safety_pattern` (non-destructive, renames the existing file to
  `.bak` before upload).
- Batch `mv` supports `--workers`, `--dry-run`, `--on-conflict`,
  and rsync-style multi-source paths.
- WebDAV `PUT`-on-existing now uses the `updateFile` path so the
  drive UUID is preserved across replace.

### Tests

- 108 unit tests across `test/{crypto, config, utils, cache,
  upload, cli}_test.dart`.
- 38 live integration tests in `test/live_smoke_test.dart`
  (auto-skipped without `IXT_ACCOUNT` / `IXT_PWD`).
- 4 live WebDAV tests in `test/webdav_live_test.dart` exercising
  `OPTIONS`, `PUT`, `GET`, `DELETE`, `PROPFIND` against a real
  spawned WebDAV server.

### CI

- GitHub Actions workflow runs `dart analyze`, `dart format
  --set-exit-if-changed`, the unit suites, and a compile smoke
  check on every push to `main` and every PR.
- `strict-casts` is enabled in `analysis_options.yaml` — the
  JSON parsing layer (`api.dart`) is cast at the boundary so
  consumers of the library see properly typed return values.
