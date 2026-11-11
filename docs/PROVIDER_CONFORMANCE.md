# Dart / Rust package compatibility

The package conformance workflow calls the actual Dart SDK source in this
checkout and the retained Rust implementation, using a pinned shared harness.
No live account or credential is used. The compiled Dart CLI probe runs the
same independent golden cases and loopback provider mocks as Rust.

Covered contracts include password and file-key derivation, Filen v2 metadata,
AES-GCM chunks with empty/boundary/large data, Internxt CBC text, CTR ranges and
incremental streams, Unicode, corrupted inputs, listings, pagination, caching,
HTTP denial/retry, and Internxt create/rename/move/trash payloads. Encryption
exports are cross-decrypted by the other implementations and backends. Linux
also requires the native Filen backend to load OpenSSL.

The workflow uses the app dependency combination (PointyCastle 4.0.0 / dart_pg
2.1.0). The shared Rust repository additionally tests the older locked Dart
combination (PointyCastle 3.9.1 / dart_pg 2.0.0). Do not combine PointyCastle 3.x
with dart_pg 2.1.0: that combination fails compilation. Existing SDK hermetic
unit/mock tests remain required; cross-language agreement cannot replace them.

## Running

From this package root with a sibling checkout of the pinned crisp-cloud-rs
harness, Python 3.12+, stable Rust and Dart 3.13.7:

```sh
python -m pip install cryptography==50.0.0
python ../crisp-cloud-rs/conformance/run.py --pointycastle 4.0.0 --dart-pg 2.1.0 --dart-internxt .
# Include --strict for the default-promotion gate.
dart test --exclude-tags=live
```

CI publishes `report.md`, `report.json`, wire traces, compiled probes and
resolved dependency lockfiles. The comparison gate fails missing cases,
positive-case rejection, byte differences, unexpected requests and Rust panics.
Exact reviewed gaps are explicitly reported and always set `promotion_ready`
to false. A green regression baseline does not mean every format is compatible.

Reviewed diagnostic areas include empty CBC encryption, envelope validation,
legacy Latin-1 versus UTF-8 secret encoding, negative CTR offsets, undecryptable
Filen listing entries and missing Internxt listing collections. Preserve existing
encrypted data when resolving these differences; a format change needs an
explicit compatibility strategy.

This gate checks SDK behavior used by GUI and CLI. Full authentication/key
exchange, engine selection/settings, transfer cancellation/resume, mobile FFI
packaging and performance require their own tests before changing app defaults.
Keep both Dart and Rust implementations supported. Automatic fallback must
remain a pre-operation availability decision, never a replay after a provider
or mutation failure.
