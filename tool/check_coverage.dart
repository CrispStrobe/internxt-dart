// Coverage gate. Parses coverage/lcov.info and enforces per-file
// thresholds for modules that have meaningful unit-test coverage.
//
// Why per-file (not global): most of this codebase is exercised
// only via the live integration suite (drive.dart, api.dart,
// auth.dart, download.dart, upload.dart, webdav_filesystem.dart),
// which CI cannot run without account credentials. A global
// threshold would either be misleadingly low or force adding
// throwaway tests just to pass the gate. Per-file thresholds
// pin the modules that *are* unit-testable and protect against
// regressions there.
//
// To extend: add an entry to `_thresholds` once a module gains
// real unit coverage. Keep thresholds at the achieved level (or
// slightly below for headroom) — the goal is regression detection,
// not aspirational targeting.
//
// Usage:
//   dart test --coverage=coverage <unit-test-files>
//   dart run coverage:format_coverage --lcov --in=coverage \
//     --out=coverage/lcov.info \
//     --packages=.dart_tool/package_config.json --report-on=.
//   dart run tool/check_coverage.dart

import 'dart:io';

const _thresholds = <String, double>{
  'crypto.dart': 100.0,
  'utils.dart': 100.0,
  'config.dart': 90.0,
  'cache.dart': 90.0,
};

void main() {
  final lcov = File('coverage/lcov.info');
  if (!lcov.existsSync()) {
    stderr.writeln('coverage/lcov.info not found — run tests with '
        '--coverage and format with coverage:format_coverage first.');
    exit(2);
  }

  final perFile = <String, ({int hit, int total})>{};
  String? currentFile;
  var hit = 0;
  var total = 0;

  for (final line in lcov.readAsLinesSync()) {
    if (line.startsWith('SF:')) {
      currentFile = line.substring(3);
      hit = 0;
      total = 0;
    } else if (line.startsWith('DA:')) {
      final parts = line.substring(3).split(',');
      if (parts.length >= 2) {
        total++;
        if ((int.tryParse(parts[1]) ?? 0) > 0) hit++;
      }
    } else if (line == 'end_of_record' && currentFile != null) {
      perFile[currentFile] = (hit: hit, total: total);
      currentFile = null;
    }
  }

  var failed = false;
  print('Coverage gate (per-file thresholds):');
  print('');
  for (final entry in _thresholds.entries) {
    final name = entry.key;
    final threshold = entry.value;
    final match = perFile.entries.firstWhere(
      (e) => e.key.endsWith('/$name') || e.key == name,
      orElse: () => MapEntry('', (hit: -1, total: 0)),
    );
    if (match.value.hit < 0) {
      stderr.writeln('  MISSING  $name (no entry in lcov.info — was '
          'it imported by any unit test?)');
      failed = true;
      continue;
    }
    final t = match.value.total;
    final h = match.value.hit;
    final pct = t == 0 ? 0.0 : 100.0 * h / t;
    final ok = pct + 0.0001 >= threshold;
    final status = ok ? 'OK   ' : 'FAIL ';
    print('  $status  ${name.padRight(20)} '
        '${h.toString().padLeft(4)} / ${t.toString().padLeft(4)}  '
        '${pct.toStringAsFixed(2).padLeft(6)}%  '
        '(threshold ${threshold.toStringAsFixed(0)}%)');
    if (!ok) failed = true;
  }

  print('');
  if (failed) {
    stderr.writeln('Coverage gate FAILED.');
    exit(1);
  }
  print('Coverage gate passed.');
}
