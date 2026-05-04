// Entrypoint for the `inxt` CLI executable.
//
// pubspec.yaml declares this file as the entry for the `inxt`
// executable. Running `dart pub global activate internxt_client`
// makes `inxt` available on PATH.

import 'package:internxt_client/cli.dart' as cli;

void main(List<String> arguments) {
  cli.main(arguments);
}
