"""
Regression tests for the path-prefix authorization bypass vulnerability.

Vulnerability class: CWE-863 / authorization bypass via naive startswith() matching.

OAuthMiddleware previously used path.startswith(tuple_of_prefixes) to decide
which requests skip Bearer-token auth. Any path that merely began with a public
prefix — /token_info, /authorize_admin, /register_anything, /.well-known-decoy/x —
bypassed authentication entirely, even though none of those are real OAuth routes.

Fix: All public paths are now enumerated as an exact-match set (_PUBLIC_PATHS)
derived directly from the route table in OAuthProvider. No prefix matching.

These tests pin the correct behavior so a future "simplification" of the matching
logic (e.g. switching back to startswith, glob matching, or a regex) cannot
silently reintroduce the vulnerability.
"""
import pytest
from httpx import ASGITransport, AsyncClient

from origo import OAuthMiddleware, OAuthProvider
from origo.middleware import _PUBLIC_PATHS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _always_200(scope, receive, send):
    """Catch-all ASGI handler that always returns 200.

    Using this instead of a Starlette router gives a clean signal:
      200  →  middleware passed the request through
      401  →  middleware blocked it (auth required)
    A real router would return 404 for unregistered paths, which would
    ambiguously look like "not blocked by middleware."
    """
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"ok", "more_body": False})


@pytest.fixture
def provider():
    return OAuthProvider(
        base_url="http://testserver",
        clients={"c": "s"}, client_redirect_uris={"c": ["https://example.com/cb"]},
        auto_approve=True,
    )


def _make_app(provider: OAuthProvider):
    return OAuthMiddleware(_always_200, provider=provider)


# ---------------------------------------------------------------------------
# _PUBLIC_PATHS set sanity check
#
# If routes are added/removed in OAuthProvider._build_app, this test will fail
# and remind you to keep _PUBLIC_PATHS in sync with the route table.
# ---------------------------------------------------------------------------

def test_public_paths_set_contents():
    assert _PUBLIC_PATHS == {
        "/register",
        "/authorize",
        "/token",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-protected-resource",
        "/.well-known/jwks.json",
    }


# ---------------------------------------------------------------------------
# Exact legitimate public paths — must bypass auth
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/register",
    "/authorize",
    "/token",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-protected-resource",
])
@pytest.mark.asyncio
async def test_exact_public_paths_bypass_auth(provider, path):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(path)
        assert resp.status_code == 200, (
            f"Expected {path!r} to bypass auth unauthenticated, got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# Prefix-confusion attack paths — must be rejected with 401
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    # /token variants
    "/token_info",
    "/tokens",
    "/token/123",
    "/tokenx",
    # /authorize variants
    "/authorize_admin",
    "/authorized",
    "/authorize/extra",
    # /register variants
    "/register_new_user",
    "/registered",
    "/registry",
])
@pytest.mark.asyncio
async def test_prefix_confusion_paths_require_auth(provider, path):
    """Paths that share a prefix with a public route must not bypass auth."""
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(path)
        assert resp.status_code == 401, f"Expected 401 for attack path {path!r}, got {resp.status_code}"
        assert resp.json()["error"] == "unauthorized"


# ---------------------------------------------------------------------------
# Trailing-slash variants — must require auth
#
# /register/, /authorize/, /token/ are not registered routes. Exact matching
# means these are distinct paths and must not bypass auth. Even if Starlette
# would normally redirect trailing-slash requests (redirect_slashes=True), the
# middleware evaluates scope["path"] before any routing occurs, so it blocks them.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/register/",
    "/authorize/",
    "/token/",
])
@pytest.mark.asyncio
async def test_trailing_slash_variants_require_auth(provider, path):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(path)
        assert resp.status_code == 401, (
            f"{path!r} must require auth — trailing-slash paths are not in _PUBLIC_PATHS"
        )


# ---------------------------------------------------------------------------
# Case-sensitivity — uppercase/mixed-case must require auth
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/Token", "/TOKEN",
    "/Authorize", "/AUTHORIZE",
    "/Register", "/REGISTER",
])
@pytest.mark.asyncio
async def test_case_variants_require_auth(provider, path):
    """Path matching is case-sensitive; uppercase variants must not bypass auth."""
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(path)
        assert resp.status_code == 401, f"Expected 401 for {path!r}, got {resp.status_code}"


# ---------------------------------------------------------------------------
# /.well-known edge cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    # No trailing slash — not a member of _PUBLIC_PATHS
    "/.well-known",
    # Trailing slash only — also not a member
    # (Note: with the old startswith("/.well-known/") vulnerability this WOULD bypass auth.
    # With exact matching it does not, because "/.well-known/" != any member.)
    "/.well-known/",
    # Arbitrary unknown path under /.well-known/
    "/.well-known/anything",
    # Decoy: shares "/.well-known" as a substring but is a different prefix.
    # The old prefix vulnerability would NOT have exposed this (since the prefix was
    # "/.well-known/" with slash), but it verifies exact matching is anchored.
    "/.well-known-but-not-really/whatever",
])
@pytest.mark.asyncio
async def test_well_known_non_public_paths_require_auth(provider, path):
    """Only registered /.well-known/ OAuth/OIDC paths are public; all others require auth."""
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(path)
        assert resp.status_code == 401, (
            f"Expected 401 for {path!r} — only registered /.well-known/ paths are in _PUBLIC_PATHS"
        )


# ---------------------------------------------------------------------------
# RFC 9728 §3.1 path-inserted metadata URL
#
# Not in _PUBLIC_PATHS because it depends on the provider's configurable
# mcp_path; matched separately against provider.protected_resource_metadata_path.
# Discovery metadata that requires a token to read tells a client to
# authenticate in order to learn how to authenticate, which is what production
# was doing before this bypass existed.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rfc9728_path_inserted_metadata_bypasses_auth(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(provider.protected_resource_metadata_path)
        assert resp.status_code == 200, (
            "the RFC 9728 §3.1 metadata URL must be readable without a token"
        )


@pytest.mark.asyncio
async def test_path_inserted_bypass_is_exact_not_prefix(provider):
    """The extra comparison must not open the whole subtree beneath it."""
    app = _make_app(provider)
    base = provider.protected_resource_metadata_path
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        for path in (f"{base}/extra", f"{base}x", f"{base}/../secret"):
            resp = await client.get(path)
            assert resp.status_code == 401, f"{path!r} must still require auth"


# ---------------------------------------------------------------------------
# Substring / embedded public-path strings — must require auth
#
# Verifies that matching is anchored to the full path, not "contains".
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/api/v1/token",
    "/foo/authorize",
    "/v2/register",
    "/internal/.well-known/oauth-authorization-server",
])
@pytest.mark.asyncio
async def test_embedded_public_path_strings_require_auth(provider, path):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(path)
        assert resp.status_code == 401, (
            f"{path!r} contains a public path as a substring but must still require auth"
        )


# ---------------------------------------------------------------------------
# Root / empty path — must require auth
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_root_path_requires_auth(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_empty_path_requires_auth(provider):
    """scope["path"] == "" is not in _PUBLIC_PATHS and must require auth."""
    status = []

    async def _capture(event):
        if event["type"] == "http.response.start":
            status.append(event["status"])

    mw = OAuthMiddleware(_always_200, provider=provider)
    await mw({"type": "http", "path": "", "headers": []}, None, _capture)
    assert status == [401]


# ---------------------------------------------------------------------------
# Happy path: valid token grants access to a protected route
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_valid_token_grants_access(provider):
    token = provider.storage.store_token("c")
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Auth-failure behavior: correct status + WWW-Authenticate header
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_missing_token_returns_401_with_www_authenticate(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/protected")
        assert resp.status_code == 401
        assert resp.json()["error"] == "unauthorized"
        assert "WWW-Authenticate" in resp.headers
        assert "Bearer" in resp.headers["WWW-Authenticate"]
        assert "testserver" in resp.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_invalid_token_returns_401_with_www_authenticate(provider):
    app = _make_app(provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/protected", headers={"Authorization": "Bearer bogus-token"})
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"
        assert "WWW-Authenticate" in resp.headers


# ---------------------------------------------------------------------------
# Application-declared public paths
#
# The middleware protects everything it wraps, which is right for the MCP
# endpoint and wrong for a landing document or a liveness probe. Without a way
# to say so, an origo-protected service answers a bare 401 at its root to every
# visitor and every scanner.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_declared_public_path_bypasses_auth():
    from origo import OAuthProvider

    p = OAuthProvider(base_url="http://testserver", clients={"c": "s"}, public_paths={"/"})
    app = _make_app(p)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.get("/")).status_code != 401


@pytest.mark.asyncio
async def test_declared_public_paths_are_exact_not_prefixes():
    """Same anchoring as _PUBLIC_PATHS: a prefix rule would turn "/docs" into a
    bypass for "/docs/../secret" and for anything merely starting with it."""
    from origo import OAuthProvider

    p = OAuthProvider(base_url="http://testserver", clients={"c": "s"}, public_paths={"/docs"})
    app = _make_app(p)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        for path in ("/docs/extra", "/docsx", "/docs/../secret", "/adocs"):
            assert (await client.get(path)).status_code == 401, f"{path!r} must still require auth"


@pytest.mark.asyncio
async def test_undeclared_paths_still_require_auth():
    from origo import OAuthProvider

    p = OAuthProvider(base_url="http://testserver", clients={"c": "s"}, public_paths={"/"})
    app = _make_app(p)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.get("/anything-else")).status_code == 401


def test_public_paths_refuses_the_mcp_endpoint():
    """The one genuinely dangerous entry: exempting the MCP path would serve
    the whole protected resource unauthenticated."""
    from origo import OAuthProvider

    with pytest.raises(ValueError, match="protected resource"):
        OAuthProvider(base_url="http://testserver", clients={"c": "s"},
                      mcp_path="/mcp", public_paths={"/mcp"})
    # Also caught when written with a trailing slash.
    with pytest.raises(ValueError, match="protected resource"):
        OAuthProvider(base_url="http://testserver", clients={"c": "s"},
                      mcp_path="/mcp", public_paths={"/mcp/"})


@pytest.mark.parametrize("bad", ["relative", "", "no-slash/x"])
def test_public_paths_requires_absolute_paths(bad):
    from origo import OAuthProvider

    with pytest.raises(ValueError, match="absolute"):
        OAuthProvider(base_url="http://testserver", clients={"c": "s"}, public_paths={bad})


def test_public_paths_rejects_non_strings():
    from origo import OAuthProvider

    with pytest.raises(TypeError):
        OAuthProvider(base_url="http://testserver", clients={"c": "s"}, public_paths={42})


def test_public_paths_defaults_to_empty():
    from origo import OAuthProvider

    p = OAuthProvider(base_url="http://testserver", clients={"c": "s"})
    assert p.public_paths == frozenset()
