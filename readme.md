# Internxt CLI - Dart Edition 🎯

[](https://www.gnu.org/licenses/agpl-3.0)

A command-line interface (CLI) for interacting with Internxt cloud storage, implemented in Dart. This is nothing official from Internxt and still a work in progress, so use at your own risk, and do not expect everything to work perfectly.

This tool allows you to manage your Internxt Drive files and folders directly from your terminal, including uploads, downloads, listing, moving, renaming, and trash operations. It also includes a **WebDAV server** to mount your Internxt Drive as a local disk.

## ✨ Features

  * **Authentication:** Login/logout securely, with **automatic session refresh**.
  * **WebDAV Server:** Mount your Internxt Drive as a local disk on macOS, Windows, or Linux.
  * **File Management:** List, upload, download, move, rename files and folders.
  * **Path-Based Operations:** Interact with your drive using familiar file paths (e.g., `/Documents/report.pdf`).
  * **Search & Discovery:**
      * Server-side fuzzy search (`search`).
      * Recursive, pattern-based file search (`find`).
      * Visual directory `tree` command.
  * **Performance:** **Local caching** for folder contents dramatically speeds up navigation and repeated commands.
  * **Resilience:** **Resumable uploads/downloads** (via batch state) and automatic retries on 5xx server errors.
  * **Trash Management:** List trash contents, move items to trash, delete permanently, and restore items.
  * **Recursive Operations:** Upload and download entire directory structures.
  * **Conflict Handling:** Choose whether to overwrite or skip existing files.
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
```

Example:

```bash
# List files
dart cli.dart list /Documents --uuids

# Upload a file and preserve its timestamp
dart cli.dart upload file.txt --target /Documents -p

# Download a file by its path
dart cli.dart download-path /Documents/file.txt

# Find all PDFs on your drive
dart cli.dart find / "*.pdf"

# Start the WebDAV server
dart cli.dart webdav-start
```

## 📚 Commands

Here's a list of available commands:

-----

### Authentication

  * **`login`**

      * Logs you into your Internxt account. Prompts for email, password, and 2FA code if needed.
      * Sessions are automatically refreshed, so you only need to log in again if your session fully expires.
      * Usage: `dart cli.dart login`

  * **`logout`**

      * Logs you out and clears locally stored credentials.
      * Usage: `dart cli.dart logout`

  * **`whoami`**

      * Shows the email, user ID, and root folder ID of the currently logged-in user.
      * Usage: `dart cli.dart whoami`

-----

### File & Folder Operations

  * **`list [path]`**

      * Lists the files and folders at a specific path. Defaults to the root folder (`/`) if no path is provided.
      * Options:
          * `--uuids`: Show full UUIDs instead of truncated ones.
      * Usage:
          * `dart cli.dart list`
          * `dart cli.dart list /Documents --uuids`

  * **`upload <sources...>`**

      * Uploads local files or directories to your Internxt Drive. Supports wildcards via shell expansion (e.g., `images/*.jpg`). Uploads are **resumable**.
      * Options:
          * `-t, --target <path>`: Remote destination path (default: `/`).
          * `-r, --recursive`: Required to upload directories.
          * `-p, --preserve-timestamps`: Try to keep original file modification times.
          * `--on-conflict <mode>`: `overwrite` or `skip` (default: `skip`).
          * `--include <pattern>`: Only include files matching the glob pattern. Can be used multiple times.
          * `--exclude <pattern>`: Exclude files matching the glob pattern. Can be used multiple times.
      * Usage:
          * `dart cli.dart upload file.txt -t /Documents -p`
          * `dart cli.dart upload "assets/*.png" -t /Images --on-conflict overwrite`
          * `dart cli.dart upload my_folder/ -t /Backup -r -p --exclude "*.tmp"`

  * **`download <file-uuid>`**

      * Downloads a single file using its UUID.
      * Usage: `dart cli.dart download <file-uuid-from-list>`

  * **`download-path <path>`**

      * Downloads a file or folder using its remote path (e.g., `/Documents/report.pdf`). Downloads are **resumable**.
      * Options:
          * `-t, --target <local_path>`: Local destination path/directory. If omitted, downloads to the current directory.
          * `-r, --recursive`: Required to download folders.
          * `-p, --preserve-timestamps`: Try to set the local file modification time to the remote time.
          * `--on-conflict <mode>`: `overwrite` or `skip` (default: `skip`).
          * `--include <pattern>`: Only include files matching the glob pattern (when downloading recursively).
          * `--exclude <pattern>`: Exclude files matching the glob pattern (when downloading recursively).
      * Usage:
          * `dart cli.dart download-path /Documents/file.txt -p`
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

### Search & Discovery

  * **`search <query>`**

      * Performs a fast, server-side search for files and folders matching a query.
      * Options:
          * `--uuids`: Show full metadata and paths (slower).
      * Usage:
          * `dart cli.dart search "report"`
          * `dart cli.dart search "invoice.pdf" --uuids`

  * **`find <path> <pattern>`**

      * Recursively finds files matching a glob pattern (e.g., `*.pdf`). The pattern is case-insensitive.
      * Options:
          * `--maxdepth <l>`: Limit the search to `l` levels deep. `-1` for infinite (default).
      * Usage:
          * `dart cli.dart find / "*.jpg"`
          * `dart cli.dart find /Documents "*.docx" --maxdepth 2`

  * **`tree [path]`**

      * Displays the folder structure as a visual tree. Defaults to root (`/`).
      * Options:
          * `-l, --depth <l>`: Maximum depth to display (default: 3).
      * Usage:
          * `dart cli.dart tree`
          * `dart cli.dart tree /Backup -l 4`

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

### WebDAV Server

  * **`webdav-start`**

      * Starts a local WebDAV server to mount your Internxt Drive as a network drive.
      * Options:
          * `--port <port>`: Port to run on (default: 8080).
          * `-b, --background`: Run the server in the background (detached).
      * Usage:
          * `dart cli.dart webdav-start` (Runs in foreground)
          * `dart cli.dart webdav-start -b --port 8888` (Runs in background on port 8888)
          * Note this provides a pure WebDAV server and no built-in directory browser which would serve a webpage. So you would need a WebDAV client to use it. E.g. in macOS: In Finder, press Cmd+K and type in http://localhost:8080. Or in Windows Explorer, click "Map network drive" and enter http://localhost:8080.
          

  * **`webdav-stop`**

      * Stops the background WebDAV server process.
      * Usage: `dart cli.dart webdav-stop`

  * **`webdav-status`**

      * Checks if a background WebDAV server process is running.
      * Usage: `dart cli.dart webdav-status`

  * **`webdav-mount`**

      * Displays platform-specific instructions for mounting the WebDAV drive in your OS.
      * Usage: `dart cli.dart webdav-mount`

  * **`webdav-test`**

      * Tests the connection to a *running* WebDAV server.
      * Usage: `dart cli.dart webdav-test`

  * **`webdav-config`**

      * Shows the WebDAV server configuration (port, user, pid file path).
      * Usage: `dart cli.dart webdav-config`

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

This project is licensed under the **GNU Affero General Public License v3.0**. See the `LICENSE` file for details.