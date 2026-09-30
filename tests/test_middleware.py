import contextlib
import json
import logging

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


# --- debug mode ---

def test_debug_defaults_off(provider):
    mw = OAuthMiddleware(lambda scope, receive, send: None, provider=provider)
    assert mw.debug is False


@pytest.mark.asyncio
async def test_debug_off_emits_no_log_records(provider, caplog):
    app = _make_app(provider)  # debug not passed -> False
    with caplog.at_level("DEBUG", logger="origo"):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            await client.get("/mcp", headers={"Authorization": "Bearer bogus-token"})
    assert caplog.records == []


@pytest.mark.asyncio
async def test_debug_logs_authenticated_request(provider, caplog):
    token = provider.storage.store_token("c", scope="bookings:write")
    inner = Starlette(routes=[Route("/mcp", _protected)])
    inner.add_middleware(OAuthMiddleware, provider=provider, debug=True)
    with caplog.at_level("DEBUG", logger="origo"):
        async with AsyncClient(transport=ASGITransport(app=inner), base_url="http://testserver") as client:
            resp = await client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    joined = "\n".join(r.message for r in caplog.records)
    assert "AUTHENTICATED client_id=c" in joined
    assert "scope='bookings:write'" in joined
    assert "downstream app responded 200" in joined
    # the raw token must never appear in full in a log line
    assert token not in joined


@pytest.mark.asyncio
async def test_debug_logs_multiple_auth_headers_without_leaking_tokens(provider, caplog):
    token = provider.storage.store_token("c")
    inner = Starlette(routes=[Route("/mcp", _protected)])
    inner.add_middleware(OAuthMiddleware, provider=provider, debug=True)
    with caplog.at_level("DEBUG", logger="origo"):
        async with AsyncClient(transport=ASGITransport(app=inner), base_url="http://testserver") as client:
            resp = await client.get("/mcp", headers=[
                ("Authorization", "Bearer ADMIN_FORGED_TOKEN_123456789"),
                ("Authorization", f"Bearer {token}"),
            ])
    assert resp.status_code == 400
    joined = "\n".join(r.message for r in caplog.records)
    assert "multiple_authorization_headers" in joined
    assert "ADMIN_FORGED_TOKEN_123456789" not in joined
    assert token not in joined


@pytest.mark.asyncio
async def test_debug_diagnoses_resource_mismatch(provider, caplog):
    token = provider.storage.store_token("c", resource="https://wrong.example/mcp")
    inner = Starlette(routes=[Route("/mcp", _protected)])
    inner.add_middleware(OAuthMiddleware, provider=provider, debug=True)
    with caplog.at_level("DEBUG", logger="origo"):
        async with AsyncClient(transport=ASGITransport(app=inner), base_url="http://testserver") as client:
            resp = await client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    joined = "\n".join(r.message for r in caplog.records)
    assert "resource mismatch" in joined
    assert "https://wrong.example/mcp" in joined
    assert token not in joined


@pytest.mark.asyncio
async def test_debug_diagnoses_no_such_token(provider, caplog):
    inner = Starlette(routes=[Route("/mcp", _protected)])
    inner.add_middleware(OAuthMiddleware, provider=provider, debug=True)
    with caplog.at_level("DEBUG", logger="origo"):
        async with AsyncClient(transport=ASGITransport(app=inner), base_url="http://testserver") as client:
            resp = await client.get("/mcp", headers={"Authorization": "Bearer nope-not-a-real-token"})
    assert resp.status_code == 401
    joined = "\n".join(r.message for r in caplog.records)
    assert "no such token, or expired" in joined


def test_redact_never_returns_full_short_secret():
    from origo.middleware import _redact
    assert _redact("") == "<empty>"
    assert "5 chars" in _redact("short")
    assert "short" not in _redact("short")
    long_token = "a" * 71
    preview = _redact(long_token)
    assert long_token not in preview
    assert "71 chars" in preview
    assert _redact(b"\xff\xfe\x00") .startswith("<")  # undecodable bytes handled


# Uppercase letters outside A-F: none of them can appear in a lowercase-hex
# fingerprint or in the fixed wording of the preview, so any of them showing
# up in the output is a character of the secret leaking through.
_NON_HEX_ALPHABET = "GHJKLMNPQRSTUVWXYZ"


@pytest.mark.parametrize("length", [1, 4, 12, 13, 14, 16, 20, 32, 71, 200])
def test_redact_reveals_no_characters_of_the_value_at_any_length(length):
    """A 13-char value used to come back with 12 of its characters showing
    (8 leading + 4 trailing), leaving one to guess. Nothing of the value may
    appear in the preview, at any length."""
    from origo.middleware import _redact
    secret = (_NON_HEX_ALPHABET * 20)[:length]
    for value in (secret, secret.encode()):
        preview = _redact(value)
        leaked = sorted({c for c in preview if c in _NON_HEX_ALPHABET})
        assert leaked == [], f"{length}-char value leaked {leaked!r} into {preview!r}"
        assert f"{length} chars" in preview


def test_redact_fingerprint_correlates_equal_values_and_separates_different_ones():
    """What debug mode needs from a preview: tell "the same token retried"
    apart from "a second, different token" -- including two values that share
    their first 8 and last 4 characters, which the old preview conflated."""
    from origo.middleware import _redact
    a = "GHJKLMNP" + "QRST" + "WXYZ"
    b = "GHJKLMNP" + "UVQR" + "WXYZ"
    assert _redact(a) == _redact(a)
    assert _redact(a) == _redact(a.encode())
    assert _redact(a) != _redact(b)


@pytest.mark.asyncio
async def test_debug_logs_non_bearer_scheme_without_the_credential(provider, caplog):
    """The scheme name is the useful part of a rejected non-Bearer header; the
    credential after it must not be logged."""
    inner = Starlette(routes=[Route("/mcp", _protected)])
    inner.add_middleware(OAuthMiddleware, provider=provider, debug=True)
    with caplog.at_level("DEBUG", logger="origo"):
        async with AsyncClient(transport=ASGITransport(app=inner), base_url="http://testserver") as client:
            resp = await client.get("/mcp", headers={"Authorization": "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="})
            resp2 = await client.get("/mcp", headers={"Authorization": "SECRETVALUEXYZ QWxhZGRpbjpv"})
            resp3 = await client.get("/mcp", headers={"Authorization": "bearer QWxhZGRpbjpv"})
    assert resp.status_code == resp2.status_code == resp3.status_code == 401
    joined = "\n".join(r.message for r in caplog.records)
    assert "scheme=Basic" in joined
    # Logged as sent: the wrong case is the whole diagnosis here.
    assert "scheme=bearer" in joined
    assert "QWxh" not in joined
    # An unrecognized first word may itself be a secret: never echoed.
    assert "SECRET" not in joined
    assert "scheme=<unrecognized>" in joined


@contextlib.contextmanager
def _isolated_logging():
    """Snapshot and restore every piece of global logging state debug mode
    touches, so these tests neither see nor leave behind other tests' setup.

    Used inside the test body, not as a fixture: pytest attaches its capture
    handlers to the root logger per phase (setup/call/teardown), so a
    fixture's snapshot would be of the wrong phase's handlers.
    """
    origo_logger = logging.getLogger("origo")
    root = logging.getLogger()
    saved_origo = (list(origo_logger.handlers), origo_logger.level, origo_logger.propagate)
    saved_root = (list(root.handlers), root.level)
    for h in saved_origo[0]:
        origo_logger.removeHandler(h)
    origo_logger.setLevel(logging.NOTSET)
    origo_logger.propagate = True
    # Detach pytest's handlers so "the app configured the root logger" is the
    # test's own handler alone, and "nothing is configured" really is nothing.
    for h in saved_root[0]:
        root.removeHandler(h)
    try:
        yield origo_logger, root
    finally:
        for h in list(origo_logger.handlers):
            origo_logger.removeHandler(h)
        for h in list(root.handlers):
            root.removeHandler(h)
        for h in saved_origo[0]:
            origo_logger.addHandler(h)
        origo_logger.setLevel(saved_origo[1])
        origo_logger.propagate = saved_origo[2]
        for h in saved_root[0]:
            root.addHandler(h)
        root.setLevel(saved_root[1])


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.mark.asyncio
async def test_debug_respects_handlers_inherited_from_the_root_logger(provider):
    """An app that configures logging on the root logger (logging.basicConfig)
    and nothing on "origo" must get each debug record once, through its own
    handler -- not a second copy from a StreamHandler debug mode bolted on."""
    with _isolated_logging() as (origo_logger, root):
        app_handler = _ListHandler()
        root.addHandler(app_handler)

        inner = Starlette(routes=[Route("/mcp", _protected)])
        inner.add_middleware(OAuthMiddleware, provider=provider, debug=True)
        async with AsyncClient(transport=ASGITransport(app=inner), base_url="http://testserver") as client:
            await client.get("/mcp", headers={"Authorization": "Bearer nope-not-a-real-token"})

        assert origo_logger.handlers == [], "debug mode must not add a handler when root already has one"
        rejected = [r for r in app_handler.records if "REJECTED 401 invalid_token" in r.getMessage()]
        assert len(rejected) == 1


def test_debug_installs_fallback_handler_only_when_nothing_is_configured(provider):
    with _isolated_logging() as (origo_logger, root):
        assert not origo_logger.hasHandlers()
        OAuthMiddleware(lambda scope, receive, send: None, provider=provider, debug=True)
        fallback = [h for h in origo_logger.handlers if isinstance(h, logging.StreamHandler)]
        assert len(fallback) == 1
        # A second debug middleware in the same process does not stack another one.
        OAuthMiddleware(lambda scope, receive, send: None, provider=provider, debug=True)
        assert origo_logger.handlers == fallback
