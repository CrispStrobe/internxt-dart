# Internxt CLI - Dart Edition 🎯

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A command-line interface (CLI) for interacting with Internxt cloud storage, implemented in Dart and designed to be compatible with the functionality of an internal Python blueprint. This is nothing offical from Internxt and still work in progress, so use at your own risk, and do not expect everything to work perfectly!

This tool allows you to manage your Internxt Drive files and folders directly from your terminal, including uploads, downloads, listing, moving, renaming, and trash operations.

## ✨ Features

* **Authentication:** Login/logout securely.
* **File Management:** List, upload, download, move, rename files and folders.
* **Path-Based Operations:** Interact with your drive using familiar file paths (e.g., `/Documents/report.pdf`).
* **Trash Management:** List trash contents, move items to trash, delete permanently, and restore items.
* **Recursive Operations:** Upload and download entire directory structures.
* **Conflict Handling:** Choose whether to overwrite or skip existing files during uploads/downloads.
* **Wildcard Support:** Use `*` and `?` for uploading multiple files (via shell expansion).
* **Timestamp Preservation:** Option to preserve original file modification times during uploads/downloads.
* **Filtering:** Include or exclude files based on patterns during uploads/downloads.
* **Cross-Platform:** Runs wherever the Dart SDK is available.

## 🛠️ Installation

1.  **Install Dart SDK:** Follow the instructions on the [official Dart website](https://dart.dev/get-dart).
2.  **Clone the Repository:**
    ```bash
    git clone https://github.com/CrispStrobe/internxt-dart.git
    cd internxt-dart
    ```
3.  **Get Dependencies:**
    ```bash
    dart pub get
    ```

## 🚀 Usage

All commands are run using the Dart executable:

```bash
dart cli.dart <command> [arguments...] [options...]
````

Example:

```bash
dart cli.dart list --uuids
dart cli.dart upload file.txt --target /Documents
dart cli.dart download-path /Documents/file.txt
```

## 📚 Commands

Here's a list of available commands:

-----

### Authentication

  * **`login`**

      * Logs you into your Internxt account. Prompts for email, password, and 2FA code if needed.
      * Usage: `dart cli.dart login`

  * **`logout`**

      * Logs you out and clears locally stored credentials.
      * Usage: `dart cli.dart logout`

  * **`whoami`**

      * Shows the email, user ID, and root folder ID of the currently logged-in user.
      * Usage: `dart cli.dart whoami`

-----

### File & Folder Operations

  * **`list [folder-uuid]`**

      * Lists the files and folders within a specific folder UUID. Defaults to the root folder if no UUID is provided.
      * Options:
          * `--uuids`: Show full UUIDs instead of truncated ones.
      * Usage:
          * `dart cli.dart list`
          * `dart cli.dart list <folder-uuid-from-previous-list> --uuids`

  * **`upload <sources...>`**

      * Uploads local files or directories to your Internxt Drive. Supports wildcards via shell expansion (e.g., `images/*.jpg`).
      * Options:
          * `-t, --target <path>`: Remote destination path (default: `/`).
          * `-r, --recursive`: Required to upload directories.
          * `-p, --preserve-timestamps`: Try to keep original file modification times.
          * `--on-conflict <mode>`: `overwrite` or `skip` (default: `skip`).
          * `--include <pattern>`: Only include files matching the glob pattern. Can be used multiple times.
          * `--exclude <pattern>`: Exclude files matching the glob pattern. Can be used multiple times.
      * Usage:
          * `dart cli.dart upload file.txt -t /Documents`
          * `dart cli.dart upload "assets/*.png" -t /Images --on-conflict overwrite`
          * `dart cli.dart upload my_folder/ -t /Backup -r -p --exclude "*.tmp"`

  * **`download <file-uuid>`**

      * Downloads a single file using its UUID.
      * Usage: `dart cli.dart download <file-uuid-from-list>`

  * **`download-path <path>`**

      * Downloads a file or folder using its remote path (e.g., `/Documents/report.pdf`).
      * Options:
          * `-t, --target <local_path>`: Local destination path/directory. If omitted, downloads to the current directory.
          * `-r, --recursive`: Required to download folders.
          * `-p, --preserve-timestamps`: Try to set the local file modification time to the remote time.
          * `--on-conflict <mode>`: `overwrite` or `skip` (default: `skip`).
          * `--include <pattern>`: Only include files matching the glob pattern (when downloading recursively).
          * `--exclude <pattern>`: Exclude files matching the glob pattern (when downloading recursively).
      * Usage:
          * `dart cli.dart download-path /Documents/file.txt`
          * `dart cli.dart download-path /Backup -r -t ./local_backup --include "*.jpg"`

  * **`mkdir-path <path>`**

      * Creates a new folder at the specified path. It automatically creates any necessary parent folders (like `mkdir -p`).
      * Usage: `dart cli.dart mkdir-path /Work/Projects/NewProject`

  * **`move-path <source-path> <destination-path>`**

      * Moves a file or folder from the source path to the destination *folder* path.
      * Options:
          * `-f, --force`: Skip confirmation.
      * Usage: `dart cli.dart move-path /Documents/report.pdf /Archive`

  * **`rename-path <path> <new-name>`**

      * Renames a file or folder at the specified path. Include the extension in `<new-name>` for files.
      * Options:
          * `-f, --force`: Skip confirmation.
      * Usage:
          * `dart cli.dart rename-path /Documents/report.pdf final_report.pdf`
          * `dart cli.dart rename-path /Archive OldArchive`

-----

### Trash Operations

  * **`list-trash`**

      * Lists all files and folders currently in the trash.
      * Options:
          * `--uuids`: Show full UUIDs instead of truncated ones.
      * Usage: `dart cli.dart list-trash`

  * **`trash-path <path>`**

      * Moves the file or folder at the specified path to the trash.
      * Options:
          * `-f, --force`: Skip confirmation.
      * Usage: `dart cli.dart trash-path /Temporary/old_file.txt`

  * **`delete-path <path>`**

      * **Permanently** deletes the file or folder at the specified path. **This cannot be undone.** Use with caution.
      * Options:
          * `-f, --force`: Skip confirmation (highly recommended to omit this).
      * Usage: `dart cli.dart delete-path /ReallyDeleteThis.txt --force`

  * **`restore-uuid <item-uuid>`**

      * Restores an item from the trash using its UUID to a specified destination folder.
      * Options:
          * `-t, --target <path>`: Destination folder path to restore to (default: `/`).
          * `-f, --force`: Skip confirmation.
      * Usage: `dart cli.dart restore-uuid <uuid-from-list-trash> -t /RestoredFiles`

  * **`restore-path <item-name>`**

      * Restores an item from the trash using its *name* (as shown in `list-trash`) to a specified destination folder. Fails if multiple items have the same name.
      * Options:
          * `-t, --target <path>`: Destination folder path to restore to (default: `/`).
          * `-f, --force`: Skip confirmation.
      * Usage: `dart cli.dart restore-path "My Report.pdf" -t /Documents`

-----

### Utility Commands

  * **`resolve <path>`**

      * A debugging tool that shows the type (file/folder) and UUID that a given path points to.
      * Usage: `dart cli.dart resolve /Documents/file.txt`

  * **`config`**

      * Displays the current configuration, including API endpoints and local file paths used by the CLI.
      * Usage: `dart cli.dart config`

  * **`test`**

      * Runs internal crypto and configuration tests to ensure compatibility with the blueprint.
      * Usage: `dart cli.dart test`

  * **`help`**

      * Shows the list of commands and options.
      * Usage: `dart cli.dart help`

-----

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0**. See the [LICENSE.txt](LICENSE.txt) file for details.
