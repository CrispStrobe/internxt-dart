// Entrypoint for the `inxt` CLI executable.
//
// pubspec.yaml declares this file as the entry for the `inxt`
// executable. Running `dart pub global activate internxt_client`
// makes `inxt` available on PATH.
//
// All the CLI logic lives in cli.dart at the repo root. This file
// is intentionally a thin shim — it lets the package be invoked
// either via `dart cli.dart <args>` (legacy path) or via `inxt
// <args>` (post-publish) without duplicating any code.

import '../cli.dart' as cli;

void main(List<String> arguments) {
  cli.main(arguments);
}
