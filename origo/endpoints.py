import hashlib
import hmac
import html
import json
import secrets
from base64 import urlsafe_b64decode
from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .storage import OAuthStorage

import base64

def _b64decode(s: str) -> bytes:
    """URL-safe base64 decode with padding."""
    s += "=" * (-len(s) % 4)
    return urlsafe_b64decode(s)


def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode()).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return hmac.compare_digest(expected, code_challenge)
    elif method == "plain":
        return hmac.compare_digest(code_verifier, code_challenge)
    return False


# --- Discovery ---

async def oauth_metadata(request: Request) -> JSONResponse:
    base_url: str = request.app.state.base_url
    return JSONResponse({
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "registration_endpoint": f"{base_url}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
    })


async def protected_resource_metadata(request: Request) -> JSONResponse:
    base_url: str = request.app.state.base_url
    mcp_path: str = request.app.state.mcp_path
    return JSONResponse({
        "resource": f"{base_url}{mcp_path}",
        "authorization_servers": [base_url],
        "bearer_methods_supported": ["header"],
    })


# --- Registration ---

async def register(request: Request) -> JSONResponse:
    storage: OAuthStorage = request.app.state.storage
    public_registration: bool = request.app.state.public_registration

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    redirect_uris = body.get("redirect_uris", [])
    if not redirect_uris:
        return JSONResponse({"error": "invalid_request", "error_description": "redirect_uris required"}, status_code=400)

    if not public_registration:
        # In private mode, only pre-registered clients are allowed.
        # We still respond with a valid DCR response using a generated
        # client_id, but mark it as unverified — it will fail at /authorize.
        # Better: just reject.
        return JSONResponse(
            {"error": "access_denied", "error_description": "Dynamic registration is disabled."},
            status_code=400,
        )

    client_id = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)
    storage.register_client(client_id, client_secret)

    return JSONResponse({
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
    }, status_code=201)


# --- Authorize ---

def _consent_page(params: dict) -> HTMLResponse:
    hidden = "\n".join(
        f'<input type="hidden" name="{html.escape(str(k))}" value="{html.escape(str(v))}">'
        for k, v in params.items()
    )
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
    return HTMLResponse(page_html)


async def authorize(request: Request) -> Response:
    storage: OAuthStorage = request.app.state.storage
    auto_approve: bool = request.app.state.auto_approve

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

    if not all([client_id, redirect_uri, code_challenge]):
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    if not storage.client_exists(client_id):
        return JSONResponse({"error": "unauthorized_client"}, status_code=401)

    # Show consent page on GET unless auto_approve
    if request.method == "GET" and not auto_approve:
        return _consent_page(params)

    # Check approval from consent form
    if request.method == "POST":
        approved = params.get("approved", "true")
        if approved != "true":
            qs = urlencode({"error": "access_denied", "state": state})
            return RedirectResponse(f"{redirect_uri}?{qs}", status_code=302)

    code = storage.store_code(client_id, redirect_uri, code_challenge, code_challenge_method)
    qs = urlencode({"code": code, "state": state})
    return RedirectResponse(f"{redirect_uri}?{qs}", status_code=302)


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

    if not all([client_id, client_secret, code, code_verifier, redirect_uri]):
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    # Verify client credentials
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

    # Verify PKCE
    if not _verify_pkce(code_verifier, code_entry["code_challenge"], code_entry["code_challenge_method"]):
        return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed."}, status_code=401)

    access_token = storage.store_token(client_id)

    return JSONResponse({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": storage.token_ttl,
    })