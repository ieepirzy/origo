import json

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import anyio

from origo import OAuthMiddleware, OAuthProvider
from origo.middleware import _is_client_disconnect
from tests.conftest import make_pkce_pair


async def _protected(request: Request):
    return JSONResponse({"ok": True})


def _make_app(provider: OAuthProvider):
    inner = Starlette(routes=[Route("/mcp", _protected)])
    inner.add_middleware(OAuthMiddleware, provider=provider)
    return inner


@pytest.fixture
def provider():
    return OAuthProvider(
        base_url="http://testserver",
        clients={"c": "s"}, client_redirect_uris={"c": ["https://example.com/cb"]},
        auto_approve=True,
    )


@pytest.mark.asyncio
async def test_jwks_path_is_public(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/.well-known/jwks.json")
        assert resp.status_code != 401


@pytest.mark.asyncio
async def test_public_paths_bypass_well_known(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # /.well-known/ routes are served by the OAuth app, not the inner app,
        # but the middleware should not block them at all.
        resp = await client.get("/.well-known/oauth-authorization-server")
        assert resp.status_code != 401


@pytest.mark.asyncio
async def test_protected_path_without_token_returns_401(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/mcp")
        assert resp.status_code == 401
        body = resp.json()
        assert body["error"] == "unauthorized"
        assert "WWW-Authenticate" in resp.headers


@pytest.mark.asyncio
async def test_protected_path_with_invalid_token_returns_401(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/mcp", headers={"Authorization": "Bearer bogus-token"})
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"


@pytest.mark.asyncio
async def test_protected_path_with_valid_token_passes(provider):
    token = provider.storage.store_token("c")
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


@pytest.mark.asyncio
async def test_valid_token_exposes_client_identity_to_protected_app(provider):
    async def identity(request: Request):
        return JSONResponse({
            "client_id": request.state.client_id,
            "oauth_scope": request.state.oauth_scope,
        })

    token = provider.storage.store_token("c", scope="bookings:write")
    app = Starlette(routes=[Route("/mcp", identity)])
    app.add_middleware(OAuthMiddleware, provider=provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"client_id": "c", "oauth_scope": "bookings:write"}


@pytest.mark.asyncio
async def test_authorize_path_is_public(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        _, challenge = make_pkce_pair()
        resp = await client.get("/authorize", params={
            "client_id": "c",
            "redirect_uri": "https://example.com/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }, follow_redirects=False)
        assert resp.status_code != 401


@pytest.mark.asyncio
async def test_token_path_is_public(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post("/token", data={
            "grant_type": "authorization_code",
            "client_id": "c",
            "client_secret": "s",
            "code": "fake",
            "code_verifier": "fake",
        })
        # Should get an auth error, not 401 unauthorized from middleware
        assert resp.status_code != 401 or resp.json().get("error") != "unauthorized"


@pytest.mark.asyncio
async def test_www_authenticate_header_includes_realm(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/mcp")
        assert "testserver" in resp.headers.get("WWW-Authenticate", "")


@pytest.mark.asyncio
async def test_www_authenticate_header_includes_configured_scope():
    scoped_provider = OAuthProvider(
        base_url="http://testserver",
        public_registration=True,
        scopes_supported=["bookings:write"],
    )
    app = _make_app(scoped_provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/mcp")
    assert 'scope="bookings:write"' in resp.headers["WWW-Authenticate"]


try:
    ExceptionGroup  # type: ignore
except NameError:
    class ExceptionGroup(Exception):
        def __init__(self, message, exceptions):
            self.exceptions = exceptions


def test_is_client_disconnect():
    assert _is_client_disconnect(anyio.ClosedResourceError()) is True
    assert _is_client_disconnect(Exception()) is False
    assert _is_client_disconnect(ValueError()) is False

    assert _is_client_disconnect(ExceptionGroup("msg", [anyio.ClosedResourceError()])) is True
    assert _is_client_disconnect(ExceptionGroup("msg", [anyio.ClosedResourceError(), anyio.ClosedResourceError()])) is True

    assert _is_client_disconnect(ExceptionGroup("msg", [anyio.ClosedResourceError(), ValueError()])) is False

    assert _is_client_disconnect(ExceptionGroup("msg", [
        anyio.ClosedResourceError(),
        ExceptionGroup("msg2", [anyio.ClosedResourceError()])
    ])) is True

    assert _is_client_disconnect(ExceptionGroup("msg", [
        anyio.ClosedResourceError(),
        ExceptionGroup("msg2", [anyio.ClosedResourceError(), ValueError()])
    ])) is False


@pytest.mark.asyncio
async def test_non_http_scope_passes_through(provider):
    passed = []

    async def inner(scope, receive, send):
        passed.append(scope["type"])

    mw = OAuthMiddleware(inner, provider=provider)
    await mw({"type": "lifespan"}, None, None)
    assert passed == ["lifespan"]


@pytest.mark.asyncio
async def test_client_disconnect_swallowed(provider):
    async def inner(scope, receive, send):
        raise anyio.ClosedResourceError()

    token = provider.storage.store_token("c")
    mw = OAuthMiddleware(inner, provider=provider)
    scope = {
        "type": "http",
        "path": "/mcp",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
    }
    await mw(scope, None, None)  # must not raise


@pytest.mark.asyncio
async def test_non_disconnect_exception_propagates(provider):
    async def inner(scope, receive, send):
        raise RuntimeError("boom")

    token = provider.storage.store_token("c")
    mw = OAuthMiddleware(inner, provider=provider)
    scope = {
        "type": "http",
        "path": "/mcp",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
    }
    with pytest.raises(RuntimeError, match="boom"):
        await mw(scope, None, None)

@pytest.mark.asyncio
async def test_websocket_missing_token_returns_close(provider):
    app = _make_app(provider)

    passed_events = []

    async def inner(scope, receive, send):
        pass # we should never reach here

    mw = OAuthMiddleware(inner, provider=provider)

    scope = {
        "type": "websocket",
        "path": "/ws",
        "headers": [],
    }

    async def receive():
        return {"type": "websocket.connect"}

    async def send(msg):
        passed_events.append(msg)

    await mw(scope, receive, send)

    assert len(passed_events) == 1
    assert passed_events[0] == {"type": "websocket.close", "code": 1008}

@pytest.mark.asyncio
async def test_websocket_invalid_token_returns_close(provider):
    app = _make_app(provider)

    passed_events = []

    async def inner(scope, receive, send):
        pass # we should never reach here

    mw = OAuthMiddleware(inner, provider=provider)

    scope = {
        "type": "websocket",
        "path": "/ws",
        "headers": [(b"authorization", b"Bearer bogus-token")],
    }

    async def receive():
        return {"type": "websocket.connect"}

    async def send(msg):
        passed_events.append(msg)

    await mw(scope, receive, send)

    assert len(passed_events) == 1
    assert passed_events[0] == {"type": "websocket.close", "code": 1008}

@pytest.mark.asyncio
async def test_www_authenticate_header_includes_resource_metadata(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/mcp")
    header = resp.headers.get("WWW-Authenticate", "")
    assert 'resource_metadata="http://testserver/.well-known/oauth-protected-resource"' in header


@pytest.mark.asyncio
async def test_token_with_wrong_resource_is_rejected_by_middleware(provider):
    token = provider.storage.store_token("c", resource="https://wrong.example/mcp")
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"


@pytest.mark.asyncio
async def test_security_multiple_auth_headers_smuggling(provider):
    token = provider.storage.store_token("c")
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # Client sends multiple Authorization headers to attempt bypassing auth/smuggling
        resp = await client.get("/mcp", headers=[
            ("Authorization", "Bearer ADMIN_FORGED_TOKEN_123"),
            ("Authorization", f"Bearer {token}")
        ])
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert "Multiple Authorization headers" in resp.json()["error_description"]
