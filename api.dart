// HTTP transport — central request handler with retries.
//
// Extracted from cli.dart in Phase 4. All endpoint methods on
// `InternxtClient` (auth, files, folders, trash, network) ultimately
// call `makeRequest` here. By design this module knows nothing about
// auth state or refresh — the caller passes a bearer token snapshot
// and is responsible for rotating it on 401. Refresh orchestration
// lives in cli.dart for now and will move to auth.dart in a later
// extraction.
//
// Behavior pinned by the live smoke suite (test/live_smoke_test.dart):
// every read/write/list operation in those tests routes through this
// function, so any regression here surfaces immediately.

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
