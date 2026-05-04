/// Public library entry-point for the `internxt_client` package.
///
/// Re-exports the protocol surface needed by library consumers
/// (e.g., the cloud-dart Flutter app). The CLI's `main()` is
/// intentionally NOT re-exported — bin/inxt.dart imports cli.dart
/// directly for that.
///
/// Naming: this barrel exports everything as top-level symbols. If
/// you need module-prefixed access (e.g., `inxt_api.makeRequest`),
/// import the individual module file directly.
library;

export 'api.dart';
export 'auth.dart';
export 'cache.dart';
export 'config.dart';
export 'config_storage.dart';
export 'crypto.dart';
export 'download.dart';
export 'drive.dart';
export 'upload.dart';
export 'utils.dart';
export 'webdav_filesystem.dart';

// cli.dart contains the CLI entry-point and the InternxtClient
// session-state class. Re-export only the class — main() and the
// CLI command handlers stay private to bin/inxt.dart.
export 'cli.dart' show InternxtClient;
