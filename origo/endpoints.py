import hashlib
import hmac
import html
import http.client
import functools
import logging
from dataclasses import dataclass
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
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .oidc import IdentityError, IdentityProvider, domain_matches, s256_challenge
from .storage import FamilyRevokedError, OAuthStorage

import base64
import asyncio


logger = logging.getLogger("origo")

_SUPPORTED_AUTH_METHODS = {"none", "client_secret_post", "client_secret_basic"}
_SUPPORTED_CIMD_AUTH_METHODS = {"none"}

async def _read_body_limited(request: Request, max_bytes: int) -> None:
    """Read request body into request._body to cache it for framework parsers, enforcing a max size limit."""
    if hasattr(request, "_body"):
        return
    body_bytes = bytearray()
    async for chunk in request.stream():
        body_bytes.extend(chunk)
        if len(body_bytes) > max_bytes:
            raise ValueError("Payload too large")
    request._body = bytes(body_bytes)


@dataclass
class UserClaims:
    subject: str
    email: str | None
    scope: str
    name: str | None = None
    groups: list[str] | None = None


def _user_claims(app_state, claims: dict | None, scope: str) -> UserClaims:
    """The person a token speaks for: the signed-in identity stored with the
    grant, or — for tokens no person signed in for (approve-only consent) —
    the static user_subject/user_email configured on the provider."""
    if claims:
        return UserClaims(
            subject=claims["sub"],
            email=claims.get("email"),
            scope=scope,
            name=claims.get("name"),
            groups=claims.get("groups"),
        )
    return UserClaims(subject=app_state.user_subject, email=app_state.user_email, scope=scope)


def _add_scoped_claims(target: dict, user_claims: UserClaims) -> None:
    """Standard OIDC scope -> claim release, shared by id_token and /userinfo."""
    scopes = user_claims.scope.split()
    if user_claims.email and "email" in scopes:
        target["email"] = user_claims.email
        # Only ever set from an IdP-verified email or the operator's own
        # user_email; an unverified IdP email never reaches UserClaims.
        target["email_verified"] = True
    if user_claims.name and "profile" in scopes:
        target["name"] = user_claims.name
    if user_claims.groups is not None and "groups" in scopes:
        target["groups"] = user_claims.groups


def _safe_compare_digest(a: str, b: str) -> bool:
    try:
        if not isinstance(a, str) or not isinstance(b, str):
            return False
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False


def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "S256":
        try:
            digest = hashlib.sha256(code_verifier.encode()).digest()
        except UnicodeEncodeError:
            return False
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return _safe_compare_digest(expected, code_challenge)
    return False


# C0 controls (includes CR, LF, NUL, tab) and DEL. A raw one of these in a
# redirect URI is either a header-injection attempt (CR/LF split the Location
# response header) or malformed input no legitimate RFC 3986 URI contains —
# such characters must be percent-encoded on the wire. Kept as an explicit
# set so the intent, and the CR/LF response-splitting motivation, is legible.
_UNSAFE_URI_CHARS = frozenset(chr(c) for c in range(0x20)) | {"\x7f"}


def _uri_is_header_safe(uri: str) -> bool:
    """True if uri can be placed in a Location header without control-character
    injection or an encoding crash.

    Rejects C0/DEL control characters (CR/LF response-splitting) and any string
    that is not UTF-8 encodable (a lone surrogate, e.g. from a percent-decoded
    \\uD800, raises UnicodeEncodeError when the response layer serializes the
    header — a 500/DoS). Deliberately server-independent: origo must not depend
    on the fronting ASGI server to strip these, since not every server does.
    """
    if any(c in _UNSAFE_URI_CHARS for c in uri):
        return False
    try:
        uri.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _build_redirect(uri: str, params: dict) -> str:
    """Append params to uri, preserving any existing query string."""
    try:
        parts = urlparse(uri)
    except ValueError as e:
        raise ValueError(f"Invalid redirect URI: {e}") from e
    try:
        qs = urlencode(parse_qsl(parts.query) + list(params.items()))
    except UnicodeEncodeError as e:
        raise ValueError(f"Invalid characters in parameters: {e}") from e
    result = urlunparse(parts._replace(query=qs))
    # Belt-and-suspenders: even if a non-header-safe uri reached here (it
    # should have been rejected upstream by _is_valid_redirect_uri), refuse it
    # as a ValueError — which authorize turns into a 400 — rather than letting
    # a control char or lone surrogate reach the response layer as a 500.
    if not _uri_is_header_safe(result):
        raise ValueError("Invalid characters in redirect URI.")
    return result


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so a CIMD host can't 302 the fetch to an internal target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@functools.lru_cache(maxsize=4096)
def _is_public_ip(ip_str: str) -> bool:
    """Reject IP addresses that are loopback/private/link-local/reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if getattr(ip, 'ipv4_mapped', None):
        ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return False
    return True


def _is_public_host(hostname: str) -> bool:
    """Reject hostnames that resolve to loopback/private/link-local/reserved addresses."""
    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except OSError:
        return False
    seen_ips = set()
    for *_rest, sockaddr in addrinfo:
        ip = sockaddr[0]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        if not _is_public_ip(ip):
            return False
    return True


class _SafeHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPSConnection that verifies IP addresses at connection time to prevent DNS rebinding SSRF."""
    allow_private_hosts = False

    def connect(self):
        addrinfo = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM)
        for family, type, proto, canonname, sockaddr in addrinfo:
            if not self.allow_private_hosts and not _is_public_ip(sockaddr[0]):
                raise OSError(f"Private IP detected: {sockaddr[0]}")

            try:
                self.sock = socket.socket(family, type, proto)
                if self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    self.sock.settimeout(self.timeout)
                if self.source_address:
                    self.sock.bind(self.source_address)
                self.sock.connect(sockaddr)
                break
            except OSError:
                if self.sock is not None:
                    self.sock.close()
                    self.sock = None
                continue
        else:
            raise OSError("Could not connect to any address")

        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        tunnel_host = getattr(self, '_tunnel_host', None)
        if tunnel_host:
            self._tunnel()

        server_hostname = tunnel_host if tunnel_host else self.host
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


class _SafeHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPS handler that uses _SafeHTTPSConnection."""
    def __init__(self, allow_private_hosts=False, **kwargs):
        super().__init__(**kwargs)
        self._allow_private_hosts = allow_private_hosts

    def https_open(self, req):
        def build_conn(host, **kwargs):
            conn = _SafeHTTPSConnection(host, **kwargs)
            conn.allow_private_hosts = self._allow_private_hosts
            return conn
        return self.do_open(build_conn, req, context=self._context)


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

    opener = urllib.request.build_opener(_NoRedirectHandler, _SafeHTTPSHandler(allow_private_hosts=allow_private_hosts))
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
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, http.client.InvalidURL, ValueError):
        return None

    try:
        metadata = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    if not isinstance(metadata, dict):
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
    # Reject control characters and non-encodable input up front: urlparse
    # happily returns a scheme+hostname for "https://h/\r\nX" or a URI holding
    # a lone surrogate, so without this gate such a value would pass validation
    # and only blow up (CR/LF header injection, or a UnicodeEncodeError 500) at
    # the response layer. Applies everywhere this validator runs — dynamic
    # registration and the ANY_REDIRECT_URI wildcard path alike.
    if not _uri_is_header_safe(uri):
        return False

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


def _signed_id_token(issuer: str, client_id: str, user_claims: UserClaims, ttl: int, private_key: RSAPrivateKey) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": user_claims.subject,
        "aud": client_id,
        "iat": now,
        "exp": now + ttl,
    }
    _add_scoped_claims(claims, user_claims)

    header = {"alg": "RS256", "typ": "JWT", "kid": "origo-1"}
    msg = f"{_base64url_json(header)}.{_base64url_json(claims)}"

    sig = private_key.sign(msg.encode(), padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode('ascii')

    return f"{msg}.{sig_b64}"


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
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "client_id_metadata_document_supported": True,
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
    }
    if scopes_supported:
        data["scopes_supported"] = scopes_supported
    if public_registration and request.app.state.cimd_allowed_clients is None:
        data["registration_endpoint"] = f"{base_url}/register"
    data["jwks_uri"] = f"{base_url}/.well-known/jwks.json"
    return JSONResponse(data)


def _int_to_base64url(val: int) -> str:
    b = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode('ascii')


async def jwks(request: Request) -> JSONResponse:
    private_key: RSAPrivateKey = request.app.state.private_key
    pub = private_key.public_key().public_numbers()

    return JSONResponse({
        "keys": [
            {
                "kty": "RSA",
                "kid": "origo-1",
                "use": "sig",
                "n": _int_to_base64url(pub.n),
                "e": _int_to_base64url(pub.e)
            }
        ]
    })


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
        await _read_body_limited(request, 65536)  # 64KB max for registration
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

    if request.app.state.cimd_allowed_clients is not None:
        # DCR hands out a fresh client_id with whatever redirect_uris the
        # caller asks for, which would walk straight around the CIMD
        # allowlist. An operator who restricted self-registered clients to
        # named CIMD documents gets exactly those, and no anonymous ones.
        return JSONResponse(
            {"error": "access_denied", "error_description": "Dynamic registration is disabled; this server accepts listed CIMD clients only."},
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
    try:
        storage.register_client(client_id, client_secret, redirect_uris, token_endpoint_auth_method, body)
    except ValueError as e:
        return JSONResponse({"error": "server_error", "error_description": str(e)}, status_code=429)

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

def _form_action_source(redirect_uri: str) -> str:
    """CSP source expression for the redirect URI's origin ('' if unusable).

    A custom-scheme URI (myapp://callback) yields its scheme://host form; a
    bare-scheme URI degrades to 'scheme:', both valid CSP source expressions.

    Returns '' for any origin that is not ASCII. The result is written into the
    Content-Security-Policy response header, which Starlette serializes as
    Latin-1; a raw non-ASCII host (an IDN/IRI redirect URI like
    https://例え.テスト/cb) would otherwise raise UnicodeEncodeError and 500 the
    consent page. Because a wildcard (ANY_REDIRECT_URI) client_id is public,
    that would be a trivially reachable DoS — and a seeded exact-match client
    with such a URI reaches here without passing _is_valid_redirect_uri at all,
    so the guard lives here rather than only in the validator. Dropping the
    origin falls the CSP back to 'self'; a URI whose host is a real IDN should
    be registered in its ASCII punycode (xn--) form, which passes unchanged.
    """
    try:
        parts = urlparse(redirect_uri)
    except ValueError:
        return ""
    if parts.scheme and parts.netloc:
        source = f"{parts.scheme}://{parts.netloc}"
    elif parts.scheme:
        source = f"{parts.scheme}:"
    else:
        return ""
    if not source.isascii():
        return ""
    import re
    if re.search(r"[\s;',]", source):
        return ""
    return source


def _consent_page(params: dict, csrf_token: str) -> HTMLResponse:
    expected_params = ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "state", "resource", "scope"]
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
    response.set_cookie("__Host-origo_csrf", csrf_token, httponly=True, samesite="lax", max_age=300, secure=True, path="/")
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # form-action must include the redirect target's origin, not just 'self':
    # Chromium enforces form-action against the redirect that FOLLOWS the
    # form submission (unlike Firefox — long-standing spec dispute), so with
    # 'self' alone the 302 from POST /authorize back to the OAuth client's
    # callback is silently blocked and the consent flow dead-ends on the
    # consent page. Reproduced with real Chromium (miradeploy, 2026-08-07):
    # 'self' alone → blocked with a form-action console violation; 'self'
    # plus the callback origin → flow completes. Including the origin is
    # safe: by the time the consent page renders, redirect_uri has already
    # been validated against the client's registered allowlist (or, for an
    # ANY_REDIRECT_URI wildcard client, through _is_valid_redirect_uri's
    # scheme rules).
    redirect_source = _form_action_source(str(params.get("redirect_uri", "")))
    form_action = "'self'" + (f" {redirect_source}" if redirect_source else "")
    response.headers["Content-Security-Policy"] = (
        f"default-src 'none'; style-src 'unsafe-inline'; form-action {form_action}; frame-ancestors 'none';"
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


async def authorize(request: Request) -> Response:
    storage: OAuthStorage = request.app.state.storage
    auto_approve: bool = request.app.state.auto_approve
    allow_private_cimd: bool = request.app.state.allow_private_cimd

    if request.method == "GET":
        if len(request.query_params.multi_items()) != len(request.query_params.keys()):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        params = dict(request.query_params)
    else:
        try:
            await _read_body_limited(request, 1048576)  # 1MB max for forms
        except Exception:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        try:
            form = await request.form()
        except Exception:
            # A malformed multipart body (bad boundary, truncated part, ...)
            # raises out of python-multipart rather than returning empty
            # form data. Uncaught, that's an unhandled 500 on every bad
            # boundary an attacker cares to send.
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        if len(form.multi_items()) != len(form.keys()):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        for _, v in form.multi_items():
            if not isinstance(v, str):
                return JSONResponse({"error": "invalid_request"}, status_code=400)
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
        return JSONResponse({"error": "invalid_request", "error_description": "invalid client_id."}, status_code=400)

    # Checked before the fetch, and against clients already registered (and
    # persisted) too: narrowing the allowlist must cut off old registrations
    # — CIMD and DCR alike, whether or not public_registration is still on —
    # not only stop new ones.
    if not _dynamic_client_permitted(request.app.state, client_id):
        logger.warning("authorize: refused client %r — a self-registered client not on cimd_allowed_clients.", client_id)
        return JSONResponse({"error": "unauthorized_client", "error_description": "Client is not allowed."}, status_code=401)

    if not storage.client_exists(client_id) and public_registration and client_is_https:
        metadata = await asyncio.to_thread(_fetch_client_metadata_document, client_id, allow_private_hosts=allow_private_cimd)
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
        try:
            storage.register_client(client_id, None, redirect_uris, auth_method, metadata)
        except ValueError as e:
            return JSONResponse({"error": "server_error", "error_description": str(e)}, status_code=429)

    if not storage.client_exists(client_id):
        return JSONResponse({"error": "unauthorized_client"}, status_code=401)

    if storage.allows_any_redirect_uri(client_id):
        # ANY_REDIRECT_URI sentinel: exact matching is off for this client,
        # but scheme validation is not — the same rules dynamic registration
        # enforces (https, loopback http, declared custom schemes) apply, so
        # "any" never means javascript:, data:, or an undeclared app scheme.
        if not _is_valid_redirect_uri(redirect_uri, custom_redirect_uri_schemes):
            logger.warning(
                "authorize: rejected redirect_uri %r for wildcard client %r — "
                "%s.",
                redirect_uri,
                client_id,
                _redirect_uri_error_description(custom_redirect_uri_schemes),
            )
            return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri not allowed."}, status_code=400)
        # INFO, not DEBUG: this is the operational record of which callback
        # URLs connectors actually use, for operators running the wildcard
        # temporarily to harvest URIs for an exact allowlist.
        logger.info(
            "authorize: accepted redirect_uri %r for client %r via its "
            "any-redirect-uri wildcard.",
            redirect_uri,
            client_id,
        )
    elif not storage.is_redirect_uri_allowed(client_id, redirect_uri):
        # Log the rejected URI: when a connector's callback URL is
        # undocumented (ChatGPT, Grok, ...), this line is how an operator
        # finds the exact value to add to the client's allowlist.
        logger.warning(
            "authorize: rejected redirect_uri %r for client %r — not on the "
            "client's redirect URI allowlist. If this request came from a "
            "connector you are setting up, add this exact URI to the "
            "client's allowlist.",
            redirect_uri,
            client_id,
        )
        return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri not allowed."}, status_code=400)

    identity_provider: IdentityProvider | None = request.app.state.identity_provider
    if identity_provider is not None:
        # Upstream sign-in replaces the consent page outright. The POST
        # (consent-form) path must not survive beside it: its CSRF pair is
        # self-issued, so a script can submit "approved=true" without any
        # person being involved.
        if request.method != "GET":
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Sign in through the identity provider."},
                status_code=400,
            )
        return await _begin_upstream_login(request, identity_provider, params)

    if not request.app.state.allow_unauthenticated_consent:
        # Fail closed: with no IdP, the consent page would hand a code to
        # whoever opened this URL. Same refusal for GET and POST, so neither
        # the page nor a scripted form submission issues anything.
        logger.warning(
            "authorize: refused client %r — no identity_provider is configured and "
            "unauthenticated consent is disabled (ORIGO_ALLOW_UNAUTHENTICATED_CONSENT).",
            client_id,
        )
        return JSONResponse(
            {"error": "access_denied", "error_description": "Authorization requires sign-in, which this server has not configured."},
            status_code=403,
        )

    # Show consent page on GET unless auto_approve
    if request.method == "GET" and not auto_approve:
        csrf_token = secrets.token_urlsafe(32)
        return _consent_page(params, csrf_token)

    # Check approval from consent form
    if request.method == "POST":
        cookie_csrf = request.cookies.get("__Host-origo_csrf")
        form_csrf = params.get("csrf_token")
        if not cookie_csrf or not form_csrf or not _safe_compare_digest(cookie_csrf, form_csrf):
            return JSONResponse({"error": "invalid_request", "error_description": "CSRF token missing or invalid."}, status_code=400)

        approved = params.get("approved", "true")
        if approved != "true":
            try:
                redirect_url = _build_redirect(redirect_uri, {"error": "access_denied", "state": state})
            except ValueError:
                return JSONResponse({"error": "invalid_request", "error_description": "invalid redirect_uri."}, status_code=400)
            return RedirectResponse(redirect_url, status_code=302, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    code = storage.store_code(client_id, redirect_uri, code_challenge, code_challenge_method, resource=resource, scope=scope)
    try:
        redirect_url = _build_redirect(redirect_uri, {"code": code, "state": state})
    except ValueError:
        return JSONResponse({"error": "invalid_request", "error_description": "invalid redirect_uri."}, status_code=400)
    return RedirectResponse(redirect_url, status_code=302, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def _dynamic_client_permitted(app_state, client_id: str) -> bool:
    """With cimd_allowed_clients set, only pre-registered clients and listed
    CIMD clients may authorize or refresh. Every other self-registered client
    — a DCR client, an unlisted CIMD document, one persisted before the list
    existed — is refused: with an IdP behind origo, any such client could
    otherwise collect codes for whoever has a live IdP session.

    With an IdP and no allowlist, the allowlist counts as empty: only
    pre-registered clients pass. That case is public_registration=False
    (construction refuses the other), where the only self-registered
    clients are leftovers persisted by an earlier public deployment — and
    those must not start receiving silent SSO codes."""
    if client_id in app_state.seeded_client_ids:
        return True
    allowed: frozenset[str] | None = app_state.cimd_allowed_clients
    if allowed is None:
        if app_state.identity_provider is None:
            return True
        allowed = frozenset()
    try:
        is_https = urlparse(client_id).scheme == "https"
    except ValueError:
        return False
    return is_https and _cimd_client_allowed(client_id, allowed)


def _cimd_client_allowed(client_id: str, allowed: frozenset[str]) -> bool:
    """True if a CIMD client_id URL is on cimd_allowed_clients: an exact URL
    entry, or a host pattern ("claude.ai", "*.example.com") matching its host."""
    if client_id in allowed:
        return True
    try:
        host = urlparse(client_id).hostname
    except ValueError:
        return False
    if not host:
        return False
    return any(domain_matches(host, entry) for entry in allowed if "://" not in entry)


# Binds a pending upstream sign-in to the browser that started it. Without it,
# an attacker could start a sign-in, sign in at the IdP as themselves, and hand
# the victim the callback URL — attaching the attacker's identity to the
# victim's connector (login CSRF). One value per browser, reused across
# concurrent sign-ins so two tabs don't invalidate each other.
_LOGIN_COOKIE = "__Host-origo_login"
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _callback_url(app_state) -> str:
    return f"{app_state.base_url}/authorize/callback"


def _redirect_to_client(redirect_uri: str, params: dict) -> Response:
    try:
        url = _build_redirect(redirect_uri, params)
    except ValueError:
        return JSONResponse({"error": "invalid_request", "error_description": "invalid redirect_uri."}, status_code=400)
    return RedirectResponse(url, status_code=302, headers=_NO_STORE)


async def _begin_upstream_login(request: Request, identity_provider: IdentityProvider, params: dict) -> Response:
    """Park the validated /authorize request and send the person to the IdP."""
    storage: OAuthStorage = request.app.state.storage
    login_state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    browser_key = request.cookies.get(_LOGIN_COOKIE) or secrets.token_urlsafe(32)

    try:
        upstream_url = await identity_provider.authorization_url(
            _callback_url(request.app.state), login_state, nonce, s256_challenge(code_verifier)
        )
    except IdentityError as exc:
        logger.error("authorize: identity provider unavailable: %s", exc)
        return _redirect_to_client(params["redirect_uri"], {"error": "temporarily_unavailable", "state": params.get("state", "")})

    storage.store_pending_login(login_state, {
        # The original request, already validated above; replayed verbatim
        # into the origo code once the person is back.
        "client_id": params["client_id"],
        "redirect_uri": params["redirect_uri"],
        "code_challenge": params["code_challenge"],
        "code_challenge_method": params.get("code_challenge_method", "S256"),
        "state": params.get("state", ""),
        "resource": params.get("resource"),
        "scope": params.get("scope", ""),
        # This sign-in's secrets towards the IdP.
        "nonce": nonce,
        "code_verifier": code_verifier,
        "browser": hashlib.sha256(browser_key.encode()).hexdigest(),
    }, ttl=identity_provider.login_ttl)

    response = RedirectResponse(upstream_url, status_code=302, headers=_NO_STORE)
    # SameSite=Lax still rides along on the IdP's top-level redirect back.
    response.set_cookie(
        _LOGIN_COOKIE, browser_key, httponly=True, samesite="lax",
        max_age=identity_provider.login_ttl, secure=True, path="/",
    )
    return response


async def authorize_callback(request: Request) -> Response:
    """The IdP's redirect back: verify the sign-in, then issue the origo code."""
    identity_provider: IdentityProvider | None = request.app.state.identity_provider
    if identity_provider is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    storage: OAuthStorage = request.app.state.storage

    if len(request.query_params.multi_items()) != len(request.query_params.keys()):
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    params = dict(request.query_params)

    login_state = params.get("state")
    pending = storage.pop_pending_login(login_state) if login_state else None
    if pending is None:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Unknown or expired sign-in. Start again from the application."},
            status_code=400,
            headers=_NO_STORE,
        )

    # Popped before this check on purpose: a sign-in that arrives in the wrong
    # browser is spent, not left for a second guess. No redirect either — this
    # request is not known to come from the person the client is waiting for.
    browser_key = request.cookies.get(_LOGIN_COOKIE)
    if not browser_key or not _safe_compare_digest(hashlib.sha256(browser_key.encode()).hexdigest(), pending["browser"]):
        logger.warning("authorize: sign-in callback for client %r arrived without its browser binding.", pending["client_id"])
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Sign-in was started in a different browser."},
            status_code=400,
            headers=_NO_STORE,
        )

    redirect_uri = pending["redirect_uri"]
    client_state = pending["state"]
    client_id = pending["client_id"]

    if "error" in params:
        # The person cancelled, or the IdP refused them. Relayed as
        # access_denied; the IdP's own description stays in our log.
        logger.info("authorize: identity provider returned %r for client %r: %r",
                    params.get("error"), client_id, params.get("error_description"))
        return _redirect_to_client(redirect_uri, {"error": "access_denied", "state": client_state})

    upstream_code = params.get("code")
    if not upstream_code:
        return _redirect_to_client(redirect_uri, {"error": "access_denied", "state": client_state})

    try:
        claims = await identity_provider.complete_login(
            upstream_code, _callback_url(request.app.state), pending["code_verifier"], pending["nonce"]
        )
    except IdentityError as exc:
        logger.warning("authorize: sign-in for client %r refused: %s", client_id, exc)
        return _redirect_to_client(redirect_uri, {"error": exc.error, "state": client_state})

    # The client may have expired (client_ttl) while the person was away.
    if not storage.client_exists(client_id):
        return JSONResponse({"error": "unauthorized_client"}, status_code=401, headers=_NO_STORE)

    # When origo verified this sign-in. Refresh refuses grants older than the
    # IdP's max_grant_age, so an offboarded person loses access within it.
    claims["auth_time"] = int(time.time())
    logger.info("authorize: %r signed in for client %r.", claims["sub"], client_id)
    code = storage.store_code(
        client_id,
        redirect_uri,
        pending["code_challenge"],
        pending["code_challenge_method"],
        resource=pending["resource"],
        scope=pending["scope"],
        claims=claims,
    )
    return _redirect_to_client(redirect_uri, {"code": code, "state": client_state})


# --- Token ---

async def token(request: Request) -> JSONResponse:
    storage: OAuthStorage = request.app.state.storage

    try:
        await _read_body_limited(request, 1048576)  # 1MB max for forms
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    try:
        form = await request.form()
    except Exception:
        # Same DoS as authorize(): a malformed multipart body raises out of
        # python-multipart instead of yielding empty form data.
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    if len(form.multi_items()) != len(form.keys()):
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    for _, v in form.multi_items():
        if not isinstance(v, str):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
    params = dict(form)

    # Also support Basic auth for client credentials
    client_id = params.get("client_id")
    client_secret = params.get("client_secret")

    if not client_id:
        auth_list = request.headers.getlist("Authorization")
        if len(auth_list) > 1:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        auth = auth_list[0] if auth_list else ""
        if auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode()
                if ":" in decoded:
                    client_id, client_secret = decoded.split(":", 1)
            except Exception:
                return JSONResponse({"error": "invalid_request"}, status_code=400)

    grant_type = params.get("grant_type")
    redirect_uri = params.get("redirect_uri")
    code = params.get("code")
    code_verifier = params.get("code_verifier")
    refresh_token = params.get("refresh_token")

    if grant_type == "authorization_code":
        if not all([client_id, code, code_verifier, redirect_uri]):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
    elif grant_type == "refresh_token":
        if not all([client_id, refresh_token]):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
    else:
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    client_auth_method = storage.get_client_auth_method(client_id)
    if client_auth_method is None:
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    if not _dynamic_client_permitted(request.app.state, client_id):
        # Same allowlist as /authorize: a grant held by a client the operator
        # has since excluded must not be refreshed into new tokens.
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    # Verify client credentials unless the client registered as a public PKCE client.
    if client_auth_method != "none":
        if not client_secret:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        if not storage.verify_client_secret(client_id, client_secret):
            return JSONResponse({"error": "invalid_client"}, status_code=401)

    if grant_type == "authorization_code":
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
        claims = code_entry.get("claims")
        # New grant: start a fresh token family. Every token rotated from this
        # grant shares the id, so refresh-token reuse can revoke them together.
        token_family = secrets.token_urlsafe(16)
    else:
        # Exchange (and rotate) refresh token
        refresh_entry = storage.exchange_refresh_token(refresh_token)
        if refresh_entry is None:
            return JSONResponse({"error": "invalid_grant", "error_description": "Refresh token expired or invalid."}, status_code=401)

        if refresh_entry["client_id"] != client_id:
            return JSONResponse({"error": "invalid_grant"}, status_code=401)

        resource = params.get("resource")
        if resource is None:
            resource = refresh_entry.get("resource")
        elif refresh_entry.get("resource") != resource:
            return JSONResponse({"error": "invalid_grant", "error_description": "resource mismatch."}, status_code=401)

        scope = refresh_entry.get("scope", "")
        token_family = refresh_entry.get("family") or secrets.token_urlsafe(16)
        # Carried forward unchanged: the identity belongs to the grant, not
        # to any one refresh token in its rotation chain.
        claims = refresh_entry.get("claims")

        identity_provider: IdentityProvider | None = request.app.state.identity_provider
        if claims is not None and identity_provider is not None:
            refusal = _refresh_refusal(identity_provider, claims)
            if refusal is not None:
                # The grant is over, not just this request: drop its live
                # tokens too, so the person's access ends here.
                logger.info("token: refresh for %r refused: %s", claims.get("sub"), refusal)
                storage.revoke_family(token_family)
                return JSONResponse({"error": "invalid_grant", "error_description": "Sign-in required."}, status_code=401)

    if claims is None and request.app.state.identity_provider is not None:
        # A grant from before the IdP was configured (persisted across the
        # upgrade). It names no person, so it can't be extended into a world
        # where every token does; the client signs in again.
        return JSONResponse({"error": "invalid_grant", "error_description": "Sign-in required."}, status_code=401)

    try:
        access_token = storage.store_token(client_id, resource=resource, scope=scope, family=token_family, claims=claims)
        new_refresh_token = storage.store_refresh_token(client_id, resource=resource, scope=scope, family=token_family, claims=claims)
    except FamilyRevokedError:
        # The family was revoked between our refresh-token exchange and the
        # replacement issuance (a concurrent replay tripped reuse detection).
        # Refuse issuance — the losing side of that race gets no live tokens.
        return JSONResponse({"error": "invalid_grant", "error_description": "Token family has been revoked."}, status_code=401)

    response_body = {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": storage.token_ttl,
        "refresh_token": new_refresh_token,
    }
    if scope:
        response_body["scope"] = scope
    if "openid" in scope.split():
        user_claims = _user_claims(request.app.state, claims, scope)
        response_body["id_token"] = _signed_id_token(
            request.app.state.base_url,
            client_id,
            user_claims,
            storage.token_ttl,
            request.app.state.private_key,
        )

    return JSONResponse(
        response_body,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
    )


def _refresh_refusal(identity_provider: IdentityProvider, claims: dict) -> str | None:
    """Why a person's grant may no longer be refreshed, or None.

    Refresh never goes back to the IdP, so without these a grant would slide
    forward forever (every rotation restarts refresh_token_ttl) and outlive
    the person's account. The grant is bounded by max_grant_age from the
    sign-in, after which the client sends the person back through /authorize
    (silent with a live IdP session, refused for a disabled account), and the
    allow gate is re-applied against the current configuration, so narrowing
    allowed_groups/allowed_email_domains takes effect at the next refresh.
    """
    auth_time = claims.get("auth_time")
    if not isinstance(auth_time, (int, float)) or time.time() - auth_time > identity_provider.max_grant_age:
        return "grant is older than max_grant_age"
    if not str(claims.get("sub", "")).startswith(f"{identity_provider.issuer}|"):
        return "grant was issued by a different identity provider"
    try:
        identity_provider.check_gate(claims, claims)
    except IdentityError as exc:
        return str(exc)
    return None


async def userinfo(request: Request) -> JSONResponse:
    storage: OAuthStorage = request.app.state.storage
    auth_list = request.headers.getlist("Authorization")
    if len(auth_list) > 1:
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    auth = auth_list[0] if auth_list else ""
    if not auth.startswith("Bearer "):
        return JSONResponse({"error": "invalid_token"}, status_code=401)

    meta = storage.verify_token(auth[7:])
    if meta is None:
        return JSONResponse({"error": "invalid_token"}, status_code=401)

    stored_claims = meta.get("claims")
    if not stored_claims and request.app.state.identity_provider is not None:
        # Same rule as OAuthProvider.verify_token: with an IdP, a token that
        # names no person is not a valid token.
        return JSONResponse({"error": "invalid_token"}, status_code=401)

    scope = meta.get("scope", "")
    if "openid" not in scope.split():
        return JSONResponse({"error": "insufficient_scope"}, status_code=403)

    user_claims = _user_claims(request.app.state, stored_claims, scope)
    claims = {"sub": user_claims.subject}
    _add_scoped_claims(claims, user_claims)
    return JSONResponse(claims, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
