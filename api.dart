// HTTP transport + raw drive endpoint wrappers.
//
// Extracted from cli.dart in Phase 4. `makeRequest` is the central
// HTTP transport with retries. The endpoint helpers below it are
// thin JSON-decoded wrappers around `makeRequest` for endpoints that
// don't carry domain logic — get/put metadata, search, ancestors.
// Higher-level operations (path resolution, mv/rename/copy/trash,
// upload, download) live in their own modules.
//
// State convention: nothing in this module holds instance state.
// Callers pass `driveApiUrl` and a bearer-token snapshot; refresh
// orchestration lives on `InternxtClient`.
//
// Behavior pinned by the live smoke suite (test/live_smoke_test.dart):
// every read/write/list operation in those tests routes through this
// module, so any regression here surfaces immediately.

import 'dart:convert';
import 'dart:math';

import 'package:http/http.dart' as http;

/// Central HTTP request handler.
///
/// Retries 5xx responses with exponential backoff (1s, 2s, 4s) and
/// network exceptions up to [maxRetries] times. 4xx responses are
/// surfaced as `Exception('API Error: <code> - <body>')` for the
/// caller to handle (typically a 401 triggers a refresh).
///
/// [bearerToken] is a snapshot captured by the caller: retries reuse
/// the same token rather than re-reading instance state, which matches
/// the original behavior since refresh is not driven from inside this
/// function. If [isNetworkAuth] is set, [networkUser]/[networkPass]
/// are used for HTTP Basic auth instead and [bearerToken] is ignored.
Future<http.Response> makeRequest(
  String method,
  Uri url, {
  String? bearerToken,
  Map<String, String>? headers,
  dynamic body,
  bool useAuth = true,
  bool isNetworkAuth = false,
  String? networkUser,
  String? networkPass,
  int retryCount = 0,
}) async {
  const maxRetries = 3;
  final requestHeaders = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'internxt-client': 'cli',
    'User-Agent': 'InternxtCLI/1.0.0 (Dart)',
    ...?headers,
  };

  if (isNetworkAuth && networkUser != null && networkPass != null) {
    final auth = base64Encode(utf8.encode('$networkUser:$networkPass'));
    requestHeaders['Authorization'] = 'Basic $auth';
  } else if (useAuth && bearerToken != null) {
    requestHeaders['Authorization'] = 'Bearer $bearerToken';
  }

  try {
    http.Response response;
    switch (method.toUpperCase()) {
      case 'GET':
        response = await http.get(url, headers: requestHeaders);
        break;
      case 'POST':
        response = await http.post(url, headers: requestHeaders, body: body);
        break;
      case 'PUT':
        response = await http.put(url, headers: requestHeaders, body: body);
        break;
      case 'PATCH':
        response = await http.patch(url, headers: requestHeaders, body: body);
        break;
      case 'DELETE':
        response = await http.delete(url, headers: requestHeaders, body: body);
        break;
      default:
        throw Exception('Unsupported method');
    }

    if (response.statusCode >= 500 && retryCount < maxRetries) {
      final delay = Duration(seconds: pow(2, retryCount).toInt());
      await Future.delayed(delay);
      return makeRequest(
        method,
        url,
        bearerToken: bearerToken,
        headers: headers,
        body: body,
        useAuth: useAuth,
        isNetworkAuth: isNetworkAuth,
        networkUser: networkUser,
        networkPass: networkPass,
        retryCount: retryCount + 1,
      );
    }

    if (response.statusCode >= 400) {
      throw Exception('API Error: ${response.statusCode} - ${response.body}');
    }

    return response;
  } catch (e) {
    if (retryCount < maxRetries) {
      return makeRequest(
        method,
        url,
        bearerToken: bearerToken,
        headers: headers,
        body: body,
        useAuth: useAuth,
        retryCount: retryCount + 1,
      );
    }
    rethrow;
  }
}

// --- Raw drive endpoint wrappers ---
// Each is a thin `makeRequest` call + json.decode. Return shapes
// match the gateway responses verbatim — callers do their own
// field extraction.

/// GET /files/{uuid}/meta — file metadata (name, fileType, folderUuid,
/// folderId, size, bucket, fileId, timestamps, …).
Future<Map<String, dynamic>> getFileMetadata(
  String driveApiUrl,
  String? bearerToken,
  String fileUuid,
) async {
  final response = await makeRequest(
    'GET',
    Uri.parse('$driveApiUrl/files/$fileUuid/meta'),
    bearerToken: bearerToken,
  );
  return json.decode(response.body);
}

/// GET /folders/{uuid}/meta — folder metadata (name, parentUuid,
/// parentId, timestamps, …).
Future<Map<String, dynamic>> getFolderMetadata(
  String driveApiUrl,
  String? bearerToken,
  String folderUuid,
) async {
  final response = await makeRequest(
    'GET',
    Uri.parse('$driveApiUrl/folders/$folderUuid/meta'),
    bearerToken: bearerToken,
  );
  return json.decode(response.body);
}

/// PUT /files/{uuid}/meta — update mutable file metadata fields.
/// Used for rename (`plainName`), retype (`type`), and timestamp
/// preservation (`modificationTime`).
Future<Map<String, dynamic>> updateFileMetadata(
  String driveApiUrl,
  String? bearerToken,
  String fileUuid,
  Map<String, dynamic> payload,
) async {
  final response = await makeRequest(
    'PUT',
    Uri.parse('$driveApiUrl/files/$fileUuid/meta'),
    bearerToken: bearerToken,
    body: json.encode(payload),
  );
  return json.decode(response.body);
}

/// PUT /folders/{uuid}/meta — update mutable folder metadata fields
/// (rename via `plainName`, timestamp preservation).
Future<Map<String, dynamic>> updateFolderMetadata(
  String driveApiUrl,
  String? bearerToken,
  String folderUuid,
  Map<String, dynamic> payload,
) async {
  final response = await makeRequest(
    'PUT',
    Uri.parse('$driveApiUrl/folders/$folderUuid/meta'),
    bearerToken: bearerToken,
    body: json.encode(payload),
  );
  return json.decode(response.body);
}

/// GET /fuzzy/{query} — server-side fuzzy search across the user's
/// drive. The response shape is unpredictable (sometimes
/// `{data: [...]}`, sometimes `{results: [...]}`, sometimes the bare
/// list); this helper normalizes to a `List<dynamic>`. Empty list
/// when the response shape is unrecognized.
Future<List<dynamic>> searchFiles(
  String driveApiUrl,
  String? bearerToken,
  String query,
) async {
  final response = await makeRequest(
    'GET',
    Uri.parse('$driveApiUrl/fuzzy/$query'),
    bearerToken: bearerToken,
  );
  final data = json.decode(response.body);
  final items = data['data'] ?? data['results'] ?? data;
  return items is List ? items : <dynamic>[];
}

/// GET /folders/{uuid}/ancestors — returns the parent chain for a
/// folder, used to reconstruct full readable paths in search results.
/// Returns an empty list if the response is malformed.
Future<List<dynamic>> getFolderAncestors(
  String driveApiUrl,
  String? bearerToken,
  String folderUuid,
) async {
  final response = await makeRequest(
    'GET',
    Uri.parse('$driveApiUrl/folders/$folderUuid/ancestors'),
    bearerToken: bearerToken,
  );
  final data = json.decode(response.body);
  return data is List ? data : <dynamic>[];
}

/// GET /users/usage — current storage usage. Shape varies by backend
/// version (`{usage, limit}` historically; sometimes just `{used}`).
/// Returns the raw map for the caller to interpret.
Future<Map<String, dynamic>> getStorageUsage(
  String driveApiUrl,
  String? bearerToken,
) async {
  final response = await makeRequest(
    'GET',
    Uri.parse('$driveApiUrl/users/usage'),
    bearerToken: bearerToken,
  );
  return json.decode(response.body);
}

/// PUT /files/{uuid} — replace a file's content while keeping its UUID.
///
/// Used by the in-place update path (`updateFile` in upload.dart) to
/// swap the network shard pointer of an existing drive entry without
/// creating a new UUID. Payload shape: `{fileId, size}` where
/// `fileId` is the network UUID returned by `finishUpload` for the
/// new content, and `size` is the new plaintext size in bytes.
Future<Map<String, dynamic>> replaceFile(
  String driveApiUrl,
  String? bearerToken,
  String fileUuid,
  Map<String, dynamic> payload,
) async {
  final response = await makeRequest(
    'PUT',
    Uri.parse('$driveApiUrl/files/$fileUuid'),
    bearerToken: bearerToken,
    body: json.encode(payload),
  );
  return json.decode(response.body);
}

/// POST /trash/restore — move an item out of trash.
///
/// `destinationFolderUuid` is optional; null means "restore to the
/// original parent folder". Internxt's gateway accepts the original
/// parent if it still exists; if not, the call typically fails or
/// silently no-ops, so prefer to pass an explicit destination when
/// the original parent might be gone.
Future<Map<String, dynamic>> restoreItem(
  String driveApiUrl,
  String? bearerToken,
  String itemUuid,
  String itemType, {
  String? destinationFolderUuid,
}) async {
  final response = await makeRequest(
    'POST',
    Uri.parse('$driveApiUrl/trash/restore'),
    bearerToken: bearerToken,
    body: json.encode({
      'uuid': itemUuid,
      'type': itemType,
      if (destinationFolderUuid != null)
        'destinationFolderUuid': destinationFolderUuid,
    }),
  );
  return json.decode(response.body);
}

/// DELETE /storage/trash/all — permanently empty the trash.
///
/// **Destructive.** Items are gone for good (Internxt does NOT
/// retain a recovery copy past this call). The CLI surface should
/// always confirm before invoking this.
Future<void> clearTrash(
  String driveApiUrl,
  String? bearerToken,
) async {
  await makeRequest(
    'DELETE',
    Uri.parse('$driveApiUrl/storage/trash/all'),
    bearerToken: bearerToken,
  );
}

/// GET /users/me — current user info.
///
/// REGRESSION MARKER: as of the Phase 5.a port, the live backend
/// returns 404 ("Cannot GET /api/users/me") for this endpoint. The
/// helper is provided for parity with the Python sibling and will
/// surface that 404 via [makeRequest]'s standard `Exception('API
/// Error: 404 - ...')` message.
///
/// If the endpoint comes online later, the live regression test
/// `users/me known-404 marker` will fail and remind us to wire
/// real callers (e.g. a richer `whoami` or `config` command).
Future<Map<String, dynamic>> getUserInfo(
  String driveApiUrl,
  String? bearerToken,
) async {
  final response = await makeRequest(
    'GET',
    Uri.parse('$driveApiUrl/users/me'),
    bearerToken: bearerToken,
  );
  return json.decode(response.body);
}
