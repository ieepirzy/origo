import hashlib
import hmac
import html
import ipaddress
import json
import secrets
import socket
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .storage import OAuthStorage

import base64


_SUPPORTED_AUTH_METHODS = {"none", "client_secret_post", "client_secret_basic"}
_SUPPORTED_CIMD_AUTH_METHODS = {"none"}


def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode()).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return hmac.compare_digest(expected, code_challenge)
    return False


def _build_redirect(uri: str, params: dict) -> str:
    """Append params to uri, preserving any existing query string."""
    try:
        parts = urlparse(uri)
    except ValueError as e:
        raise ValueError(f"Invalid redirect URI: {e}") from e
    qs = urlencode(parse_qsl(parts.query) + list(params.items()))
    return urlunparse(parts._replace(query=qs))


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so a CIMD host can't 302 the fetch to an internal target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _is_public_host(hostname: str) -> bool:
    """Reject hostnames that resolve to loopback/private/link-local/reserved addresses."""
    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except OSError:
        return False
    for *_rest, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if getattr(ip, 'ipv4_mapped', None):
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return True


def _fetch_client_metadata_document(client_id: str, allow_private_hosts: bool = False) -> dict | None:
    """Fetch a Client ID Metadata Document (CIMD) for HTTPS URL client_ids."""
    try:
        parsed = urlparse(client_id)
    except ValueError:
        return None

    if parsed.scheme != "https" or not parsed.hostname:
        return None

    if not allow_private_hosts and not _is_public_host(parsed.hostname):
        return None

    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        request = urllib.request.Request(
            client_id,
            headers={"Accept": "application/json"},
            method="GET",
        )
        with opener.open(request, timeout=5) as response:
            if response.status != 200:
                return None
            content_type = response.headers.get("content-type", "")
            if "json" not in content_type:
                return None
            body = response.read(65536)
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None

    try:
        metadata = json.loads(body)
    except json.JSONDecodeError:
        return None

    if metadata.get("client_id", client_id) != client_id:
        return None
    return metadata


def _is_valid_redirect_uri(uri: str, allowed_custom_schemes: frozenset[str] = frozenset()) -> bool:
    """Reject redirect URIs whose scheme can't carry an auth code safely.

    https is always allowed; http is allowed only for the RFC 8252 §7.3
    loopback exemption used by native-app clients during development.
    Private-use URI schemes (RFC 8252 §7.1, e.g. "myapp://callback") are
    allowed only if the operator explicitly declared them via
    OAuthProvider(custom_redirect_uri_schemes=[...]) — never by default,
    since an unconfigured scheme could be claimed by another app on the
    same device.
    """
    try:
        parsed = urlparse(uri)
    except ValueError:
        return False

    if parsed.fragment or parsed.username is not None or parsed.password is not None:
        return False
    if parsed.scheme == "https":
        return bool(parsed.hostname)
    if parsed.scheme == "http":
        return (parsed.hostname or "") in ("localhost", "127.0.0.1", "::1")
    return parsed.scheme in allowed_custom_schemes


def _redirect_uri_error_description(allowed_custom_schemes: frozenset[str]) -> str:
    description = "must be valid URIs using https (or http://localhost for loopback)"
    if allowed_custom_schemes:
        schemes = ", ".join(f"{s}:" for s in sorted(allowed_custom_schemes))
        description += f", or one of these custom schemes: {schemes}"
    return description + "."


def _validate_scope(scope: str, scopes_supported: list[str]) -> bool:
    if not scope or not scopes_supported:
        return True
    requested = set(scope.split())
    return requested.issubset(set(scopes_supported))


def _base64url_json(data: dict) -> str:
    encoded = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode()


def _unsigned_id_token(issuer: str, client_id: str, subject: str, email: str | None, scope: str, ttl: int) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": subject,
        "aud": client_id,
        "iat": now,
        "exp": now + ttl,
    }
    if email and "email" in scope.split():
        claims["email"] = email
        claims["email_verified"] = True
    return f"{_base64url_json({'alg': 'none', 'typ': 'JWT'})}.{_base64url_json(claims)}."


# --- Discovery ---

async def oauth_metadata(request: Request) -> JSONResponse:
    base_url: str = request.app.state.base_url
    public_registration: bool = request.app.state.public_registration
    scopes_supported: list[str] = request.app.state.scopes_supported
    data = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "userinfo_endpoint": f"{base_url}/userinfo",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "client_id_metadata_document_supported": True,
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
    }
    if scopes_supported:
        data["scopes_supported"] = scopes_supported
    if public_registration:
        data["registration_endpoint"] = f"{base_url}/register"
    return JSONResponse(data)


async def protected_resource_metadata(request: Request) -> JSONResponse:
    base_url: str = request.app.state.base_url
    mcp_path: str = request.app.state.mcp_path
    scopes_supported: list[str] = request.app.state.scopes_supported
    resource_documentation: str | None = request.app.state.resource_documentation
    data = {
        "resource": f"{base_url}{mcp_path}",
        "authorization_servers": [base_url],
        "bearer_methods_supported": ["header"],
    }
    if scopes_supported:
        data["scopes_supported"] = scopes_supported
    if resource_documentation:
        data["resource_documentation"] = resource_documentation
    return JSONResponse(data)


# --- Registration ---

async def register(request: Request) -> JSONResponse:
    storage: OAuthStorage = request.app.state.storage
    public_registration: bool = request.app.state.public_registration
    custom_redirect_uri_schemes: frozenset[str] = request.app.state.custom_redirect_uri_schemes

    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    redirect_uris = body.get("redirect_uris", [])
    if not redirect_uris:
        return JSONResponse({"error": "invalid_request", "error_description": "redirect_uris required"}, status_code=400)

    if not isinstance(redirect_uris, list) or not all(
        isinstance(u, str) and _is_valid_redirect_uri(u, custom_redirect_uri_schemes) for u in redirect_uris
    ):
        return JSONResponse(
            {
                "error": "invalid_redirect_uri",
                "error_description": "redirect_uris " + _redirect_uri_error_description(custom_redirect_uri_schemes),
            },
            status_code=400,
        )

    if not public_registration:
        # In private mode, only pre-registered clients are allowed.
        # We still respond with a valid DCR response using a generated
        # client_id, but mark it as unverified — it will fail at /authorize.
        # Better: just reject.
        return JSONResponse(
            {"error": "access_denied", "error_description": "Dynamic registration is disabled."},
            status_code=400,
        )

    token_endpoint_auth_method = body.get("token_endpoint_auth_method", "client_secret_post")
    if not isinstance(token_endpoint_auth_method, str) or token_endpoint_auth_method not in _SUPPORTED_AUTH_METHODS:
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": "Unsupported token_endpoint_auth_method."},
            status_code=400,
        )

    client_id = secrets.token_urlsafe(16)
    client_secret = None if token_endpoint_auth_method == "none" else secrets.token_urlsafe(32)
    storage.register_client(client_id, client_secret, redirect_uris, token_endpoint_auth_method, body)

    response_body = {
        "client_id": client_id,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": token_endpoint_auth_method,
    }
    if client_secret is not None:
        response_body["client_secret"] = client_secret

    return JSONResponse(
        response_body,
        status_code=201,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
    )


# --- Authorize ---

def _consent_page(params: dict, csrf_token: str) -> HTMLResponse:
    expected_params = ["client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "resource", "scope"]
    hidden = "\n".join(
        f'<input type="hidden" name="{html.escape(str(k))}" value="{html.escape(str(params.get(k, "")))}">'
        for k in expected_params if k in params
    )
    hidden += f'\n    <input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">'
    escaped_client_id = html.escape(str(params.get('client_id', '')))
    page_html = f"""<!DOCTYPE html>
<html>
<head><title>Authorize Access</title>
<style>
  body {{ font-family: sans-serif; max-width: 480px; margin: 80px auto; padding: 0 20px; }}
  .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 32px; }}
  h2 {{ margin-top: 0; }}
  .client {{ font-family: monospace; background: #f5f5f5; padding: 4px 8px; border-radius: 4px; }}
  .actions {{ display: flex; gap: 12px; margin-top: 24px; }}
  button {{ padding: 10px 24px; border-radius: 6px; border: none; cursor: pointer; font-size: 15px; }}
  .approve {{ background: #2563eb; color: white; }}
  .deny {{ background: #e5e7eb; color: #111; }}
</style>
</head>
<body>
<div class="card">
  <h2>Authorize Access</h2>
  <p>Client <span class="client">{escaped_client_id}</span> is requesting access to your MCP server.</p>
  <form method="POST" action="/authorize">
    {hidden}
    <div class="actions">
      <button class="approve" type="submit" name="approved" value="true">Approve</button>
      <button class="deny" type="submit" name="approved" value="false">Deny</button>
    </div>
  </form>
</div>
</body>
</html>"""
    response = HTMLResponse(page_html)
    response.set_cookie("origo_csrf", csrf_token, httponly=True, samesite="lax", max_age=300, secure=True)
    response.headers["X-Frame-Options"] = "DENY"
    return response


async def authorize(request: Request) -> Response:
    storage: OAuthStorage = request.app.state.storage
    auto_approve: bool = request.app.state.auto_approve
    allow_private_cimd: bool = request.app.state.allow_private_cimd

    if request.method == "GET":
        params = dict(request.query_params)
    else:
        form = await request.form()
        params = dict(form)

    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method", "S256")
    state = params.get("state", "")
    response_type = params.get("response_type")
    resource = params.get("resource")
    scope = params.get("scope", "")
    scopes_supported: list[str] = request.app.state.scopes_supported

    if not all([client_id, redirect_uri, code_challenge]):
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    try:
        urlparse(redirect_uri)
    except ValueError:
        return JSONResponse({"error": "invalid_request", "error_description": "invalid redirect_uri."}, status_code=400)

    if response_type is None:
        return JSONResponse({"error": "invalid_request", "error_description": "response_type is required."}, status_code=400)

    if response_type != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)

    if code_challenge_method != "S256":
        return JSONResponse({"error": "invalid_request", "error_description": "Unsupported code_challenge_method."}, status_code=400)

    if not _validate_scope(scope, scopes_supported):
        return JSONResponse({"error": "invalid_scope"}, status_code=400)

    public_registration: bool = request.app.state.public_registration
    custom_redirect_uri_schemes: frozenset[str] = request.app.state.custom_redirect_uri_schemes
    client_is_https = False
    try:
        client_is_https = urlparse(client_id).scheme == "https"
    except ValueError:
        pass

    if not storage.client_exists(client_id) and public_registration and client_is_https:
        metadata = _fetch_client_metadata_document(client_id, allow_private_hosts=allow_private_cimd)
        if metadata is None:
            return JSONResponse({"error": "unauthorized_client", "error_description": "Invalid client metadata document."}, status_code=401)

        redirect_uris = metadata.get("redirect_uris", [])
        auth_method = metadata.get("token_endpoint_auth_method", "none")
        if not isinstance(redirect_uris, list) or not redirect_uris or not all(isinstance(u, str) for u in redirect_uris) or auth_method not in _SUPPORTED_CIMD_AUTH_METHODS:
            return JSONResponse({"error": "unauthorized_client", "error_description": "CIMD metadata must declare a non-empty redirect_uris list."}, status_code=401)
        if not all(_is_valid_redirect_uri(u, custom_redirect_uri_schemes) for u in redirect_uris):
            return JSONResponse(
                {"error": "unauthorized_client", "error_description": "CIMD redirect_uris " + _redirect_uri_error_description(custom_redirect_uri_schemes)},
                status_code=401,
            )
        storage.register_client(client_id, None, redirect_uris, auth_method, metadata)

    if not storage.client_exists(client_id):
        return JSONResponse({"error": "unauthorized_client"}, status_code=401)

    if not storage.is_redirect_uri_allowed(client_id, redirect_uri):
        return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri not allowed."}, status_code=400)

    # Show consent page on GET unless auto_approve
    if request.method == "GET" and not auto_approve:
        csrf_token = secrets.token_urlsafe(32)
        return _consent_page(params, csrf_token)

    # Check approval from consent form
    if request.method == "POST":
        cookie_csrf = request.cookies.get("origo_csrf")
        form_csrf = params.get("csrf_token")
        if not cookie_csrf or not form_csrf or not secrets.compare_digest(cookie_csrf, form_csrf):
            return JSONResponse({"error": "invalid_request", "error_description": "CSRF token missing or invalid."}, status_code=400)

        approved = params.get("approved", "true")
        if approved != "true":
            try:
                redirect_url = _build_redirect(redirect_uri, {"error": "access_denied", "state": state})
            except ValueError:
                return JSONResponse({"error": "invalid_request", "error_description": "invalid redirect_uri."}, status_code=400)
            return RedirectResponse(redirect_url, status_code=302)

    code = storage.store_code(client_id, redirect_uri, code_challenge, code_challenge_method, resource=resource, scope=scope)
    try:
        redirect_url = _build_redirect(redirect_uri, {"code": code, "state": state})
    except ValueError:
        return JSONResponse({"error": "invalid_request", "error_description": "invalid redirect_uri."}, status_code=400)
    return RedirectResponse(redirect_url, status_code=302)


# --- Token ---

async def token(request: Request) -> JSONResponse:
    storage: OAuthStorage = request.app.state.storage

    form = await request.form()
    params = dict(form)

    # Also support Basic auth for client credentials
    client_id = params.get("client_id")
    client_secret = params.get("client_secret")

    if not client_id:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode()
                if ":" in decoded:
                    client_id, client_secret = decoded.split(":", 1)
            except Exception:
                return JSONResponse({"error": "invalid_request"}, status_code=400)

    code = params.get("code")
    code_verifier = params.get("code_verifier")
    grant_type = params.get("grant_type")
    redirect_uri = params.get("redirect_uri")

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    if not all([client_id, code, code_verifier, redirect_uri]):
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    client_auth_method = storage.get_client_auth_method(client_id)
    if client_auth_method is None:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    # Verify client credentials unless the client registered as a public PKCE client.
    if client_auth_method != "none":
        if not client_secret:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        stored_secret = storage.get_client_secret(client_id)
        if stored_secret is None or not hmac.compare_digest(stored_secret, client_secret):
            return JSONResponse({"error": "invalid_client"}, status_code=401)

    # Exchange code
    code_entry = storage.exchange_code(code)
    if code_entry is None:
        return JSONResponse({"error": "invalid_grant", "error_description": "Code expired or invalid."}, status_code=401)

    if code_entry["client_id"] != client_id:
        return JSONResponse({"error": "invalid_grant"}, status_code=401)

    if code_entry["redirect_uri"] != redirect_uri:
        return JSONResponse({"error": "invalid_grant"}, status_code=401)

    resource = params.get("resource")
    code_resource = code_entry.get("resource")
    if code_resource != resource:
        return JSONResponse({"error": "invalid_grant", "error_description": "resource mismatch."}, status_code=401)

    # Verify PKCE
    if not _verify_pkce(code_verifier, code_entry["code_challenge"], code_entry["code_challenge_method"]):
        return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed."}, status_code=401)

    scope = code_entry.get("scope", "")
    access_token = storage.store_token(client_id, resource=resource, scope=scope)

    response_body = {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": storage.token_ttl,
    }
    if scope:
        response_body["scope"] = scope
    if "openid" in scope.split():
        response_body["id_token"] = _unsigned_id_token(
            request.app.state.base_url,
            client_id,
            request.app.state.user_subject,
            request.app.state.user_email,
            scope,
            storage.token_ttl,
        )

    return JSONResponse(
        response_body,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
    )


async def userinfo(request: Request) -> JSONResponse:
    storage: OAuthStorage = request.app.state.storage
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse({"error": "invalid_token"}, status_code=401)

    meta = storage.verify_token(auth[7:])
    if meta is None:
        return JSONResponse({"error": "invalid_token"}, status_code=401)

    scope = set(meta.get("scope", "").split())
    if "openid" not in scope:
        return JSONResponse({"error": "insufficient_scope"}, status_code=403)

    claims = {"sub": request.app.state.user_subject}
    if request.app.state.user_email and "email" in scope:
        claims["email"] = request.app.state.user_email
        claims["email_verified"] = True
    return JSONResponse(claims, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
