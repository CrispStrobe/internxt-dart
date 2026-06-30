# Changelog

## Unreleased

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
