import base64
import hashlib
import secrets

import pytest

from tests.conftest import make_pkce_pair


# --- Discovery ---

@pytest.mark.asyncio
async def test_oauth_metadata(client_private):
    client, provider = client_private
    resp = await client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    data = resp.json()
    assert data["issuer"] == "http://testserver"
    assert data["authorization_endpoint"] == "http://testserver/authorize"
    assert data["token_endpoint"] == "http://testserver/token"
    assert "authorization_code" in data["grant_types_supported"]
    assert "S256" in data["code_challenge_methods_supported"]


@pytest.mark.asyncio
async def test_protected_resource_metadata(client_private):
    client, provider = client_private
    resp = await client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    data = resp.json()
    assert "resource" in data
    assert "authorization_servers" in data
    assert data["bearer_methods_supported"] == ["header"]


# --- Registration ---

@pytest.mark.asyncio
async def test_register_public_mode(client_public):
    client, provider = client_public
    resp = await client.post("/register", json={"redirect_uris": ["https://example.com/cb"]})
    assert resp.status_code == 201
    data = resp.json()
    assert "client_id" in data
    assert "client_secret" in data
    assert provider.storage.client_exists(data["client_id"])


@pytest.mark.asyncio
async def test_register_private_mode_rejected(client_private):
    client, provider = client_private
    resp = await client.post("/register", json={"redirect_uris": ["https://example.com/cb"]})
    assert resp.status_code == 400
    assert resp.json()["error"] == "access_denied"


@pytest.mark.asyncio
async def test_register_missing_redirect_uris(client_public):
    client, _ = client_public
    resp = await client.post("/register", json={})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_register_invalid_json(client_public):
    client, _ = client_public
    resp = await client.post("/register", content=b"not-json", headers={"content-type": "application/json"})
    assert resp.status_code == 400


# --- Authorize ---

@pytest.mark.asyncio
async def test_authorize_auto_approve_redirects(client_private):
    client, _ = client_private
    verifier, challenge = make_pkce_pair()
    resp = await client.get("/authorize", params={
        "client_id": "test-client",
        "redirect_uri": "https://example.com/cb",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "mystate",
    }, follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "code=" in location
    assert "state=mystate" in location


@pytest.mark.asyncio
async def test_authorize_shows_consent_page(client_public):
    # public provider has auto_approve=True in our fixture; test manual consent with auto_approve=False
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        clients={"c": "s"},
        auto_approve=False,
    )
    verifier, challenge = make_pkce_pair()
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/authorize", params={
            "client_id": "c",
            "redirect_uri": "https://example.com/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
    assert resp.status_code == 200
    assert b"<form" in resp.content


@pytest.mark.asyncio
async def test_authorize_unknown_client(client_private):
    client, _ = client_private
    verifier, challenge = make_pkce_pair()
    resp = await client.get("/authorize", params={
        "client_id": "nobody",
        "redirect_uri": "https://example.com/cb",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthorized_client"


@pytest.mark.asyncio
async def test_authorize_missing_params(client_private):
    client, _ = client_private
    resp = await client.get("/authorize", params={"client_id": "test-client"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_authorize_post_denial_redirects_error(client_public):
    # Register a client first
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        clients={"c": "s"},
        auto_approve=False,
    )
    verifier, challenge = make_pkce_pair()
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.post("/authorize", data={
            "client_id": "c",
            "redirect_uri": "https://example.com/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "s1",
            "approved": "false",
        }, follow_redirects=False)
    assert resp.status_code == 302
    assert "error=access_denied" in resp.headers["location"]


@pytest.mark.asyncio
async def test_authorize_preserves_state(client_private):
    client, _ = client_private
    verifier, challenge = make_pkce_pair()
    resp = await client.get("/authorize", params={
        "client_id": "test-client",
        "redirect_uri": "https://example.com/cb",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "unique-state-xyz",
    }, follow_redirects=False)
    assert "state=unique-state-xyz" in resp.headers["location"]


# --- Token ---

@pytest.mark.asyncio
async def test_token_exchange_s256(client_private):
    client, provider = client_private
    verifier, challenge = make_pkce_pair()
    code = provider.storage.store_code("test-client", "https://example.com/cb", challenge, "S256")
    resp = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://example.com/cb",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "expires_in" in data


@pytest.mark.asyncio
async def test_token_exchange_plain(client_private):
    client, provider = client_private
    verifier = secrets.token_urlsafe(32)
    code = provider.storage.store_code("test-client", "https://example.com/cb", verifier, "plain")
    resp = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://example.com/cb",
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_token_invalid_pkce(client_private):
    client, provider = client_private
    verifier, challenge = make_pkce_pair()
    code = provider.storage.store_code("test-client", "https://example.com/cb", challenge, "S256")
    resp = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code": code,
        "code_verifier": "wrong-verifier",
        "redirect_uri": "https://example.com/cb",
    })
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_token_expired_code(client_private):
    from unittest.mock import patch
    client, provider = client_private
    verifier, challenge = make_pkce_pair()
    code = provider.storage.store_code("test-client", "https://example.com/cb", challenge, "S256")
    with patch("origo.storage._now", return_value=9999999999.0):
        resp = await client.post("/token", data={
            "grant_type": "authorization_code",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "https://example.com/cb",
        })
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_token_invalid_client_secret(client_private):
    client, provider = client_private
    verifier, challenge = make_pkce_pair()
    code = provider.storage.store_code("test-client", "https://example.com/cb", challenge, "S256")
    resp = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "wrong-secret",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://example.com/cb",
    })
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_token_basic_auth(client_private):
    client, provider = client_private
    verifier, challenge = make_pkce_pair()
    code = provider.storage.store_code("test-client", "https://example.com/cb", challenge, "S256")
    credentials = base64.b64encode(b"test-client:test-secret").decode()
    resp = await client.post("/token",
        data={"grant_type": "authorization_code", "code": code, "code_verifier": verifier, "redirect_uri": "https://example.com/cb"},
        headers={"Authorization": f"Basic {credentials}"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_token_invalid_redirect_uri(client_private):
    client, provider = client_private
    verifier, challenge = make_pkce_pair()
    code = provider.storage.store_code("test-client", "https://example.com/cb", challenge, "S256")
    resp = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://wrong.com/cb",
    })
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_token_wrong_grant_type(client_private):
    client, _ = client_private
    resp = await client.post("/token", data={
        "grant_type": "client_credentials",
        "client_id": "test-client",
        "client_secret": "test-secret",
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"


@pytest.mark.asyncio
async def test_token_missing_params(client_private):
    client, _ = client_private
    resp = await client.post("/token", data={"grant_type": "authorization_code"})
    assert resp.status_code == 400

# --- Utilities ---

def test_b64decode():
    from origo.endpoints import _b64decode

    # Test cases with different lengths to hit different padding scenarios
    # "a" -> "YQ==" (needs 2 pads)
    # "ab" -> "YWI=" (needs 1 pad)
    # "abc" -> "YWJj" (needs 0 pads)
    # "abcd" -> "YWJjZA==" (needs 2 pads)

    assert _b64decode("YQ") == b"a"
    assert _b64decode("YQ==") == b"a"

    assert _b64decode("YWI") == b"ab"
    assert _b64decode("YWI=") == b"ab"

    assert _b64decode("YWJj") == b"abc"

    assert _b64decode("YWJjZA") == b"abcd"
    assert _b64decode("YWJjZA==") == b"abcd"

    # URL-safe characters
    # b"\xfb\xff" -> "-_8="
    assert _b64decode("-_8") == b"\xfb\xff"
    assert _b64decode("-_8=") == b"\xfb\xff"
