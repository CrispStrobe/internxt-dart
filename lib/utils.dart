// Pure-function utilities — formatting, glob filtering.
//
// No I/O, no auth state, no network. Extracted from cli.dart in
// Phase 4. Coverage in test/utils_test.dart (17 tests).

import 'package:glob/glob.dart';

/// Formats a byte count into a human-readable string (`1.5 MB`).
/// Returns `'N/A'` for null or non-numeric inputs that can't be parsed.
String formatSize(dynamic bytes) {
  if (bytes == null) return 'N/A';
  if (bytes is String) bytes = int.tryParse(bytes) ?? 0;
  if (bytes is! int) return 'N/A';
  if (bytes == 0) return '0 B';

  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  if (bytes < 1024 * 1024 * 1024) {
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
}

/// Glob-based include/exclude filter. Empty `include` means "no include
/// filter"; empty `exclude` means "no exclude filter". Exclude wins when
/// both match. Glob matching is case-sensitive.
bool shouldIncludeFile(
  String fileName,
  List<String> include,
  List<String> exclude,
) {
  if (include.isNotEmpty) {
    final matchesInclude =
        include.any((pattern) => Glob(pattern).matches(fileName));
    if (!matchesInclude) return false;
  }

  if (exclude.isNotEmpty) {
    final matchesExclude =
        exclude.any((pattern) => Glob(pattern).matches(fileName));
    if (matchesExclude) return false;
  }

  return true;
}
