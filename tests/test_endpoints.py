import base64
import hashlib
import secrets
import warnings

import pytest

from tests.conftest import make_pkce_pair

from origo.endpoints import _verify_pkce

def test_verify_pkce_unsupported_method():
    """Test that _verify_pkce returns False for an unsupported method."""
    assert _verify_pkce("test-verifier", "test-challenge", "unsupported") is False


def test_verify_pkce_invalid_utf8_verifier():
    """Test that _verify_pkce handles UnicodeEncodeError and returns False."""
    assert _verify_pkce("\ud800", "some-challenge", "S256") is False


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
    assert "refresh_token" in data["grant_types_supported"]
    assert data["code_challenge_methods_supported"] == ["S256"]
    assert "plain" not in data["code_challenge_methods_supported"]
    assert "registration_endpoint" not in data


@pytest.mark.asyncio
async def test_oauth_metadata_public_includes_registration_endpoint(client_public):
    client, _ = client_public
    resp = await client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    assert resp.json()["registration_endpoint"] == "http://testserver/register"


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
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"
    data = resp.json()
    assert "client_id" in data
    assert "client_secret" in data
    assert provider.storage.client_exists(data["client_id"])


@pytest.mark.asyncio
async def test_register_respects_max_dynamic_clients_cap():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient

    p = OAuthProvider(base_url="http://testserver", public_registration=True, max_dynamic_clients=2)
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        client_ids = []
        for _ in range(3):
            resp = await c.post("/register", json={"redirect_uris": ["https://example.com/cb"]})
            assert resp.status_code == 201
            client_ids.append(resp.json()["client_id"])

    # Oldest registration should have been evicted to stay within the cap.
    assert not p.storage.client_exists(client_ids[0])
    assert p.storage.client_exists(client_ids[1])
    assert p.storage.client_exists(client_ids[2])


@pytest.mark.asyncio
async def test_register_dynamic_client_expires_after_ttl(monkeypatch):
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient

    p = OAuthProvider(base_url="http://testserver", public_registration=True, client_ttl=1)
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.post("/register", json={"redirect_uris": ["https://example.com/cb"]})
        client_id = resp.json()["client_id"]

    assert p.storage.client_exists(client_id)
    monkeypatch.setattr("origo.storage._now", lambda: 9999999999.0)
    assert p.storage.client_exists(client_id) is False


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


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_uri", [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "http://example.com/cb",
    "http://evil.com/cb",
    "https://example.com/cb#fragment",
    "https://user:pass@example.com/cb",
    "https://:8080/cb",
])
async def test_register_rejects_unsafe_redirect_uri_scheme(client_public, bad_uri):
    client, _ = client_public
    resp = await client.post("/register", json={"redirect_uris": [bad_uri]})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


@pytest.mark.asyncio
async def test_register_allows_http_loopback_redirect_uri(client_public):
    client, _ = client_public
    resp = await client.post("/register", json={"redirect_uris": ["http://127.0.0.1:8080/cb"]})
    assert resp.status_code == 201


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_redirect_uris", [5, True, {"a": "https://example.com/cb"}, "https://example.com/cb"])
async def test_register_rejects_non_list_redirect_uris(client_public, bad_redirect_uris):
    client, _ = client_public
    resp = await client.post("/register", json={"redirect_uris": bad_redirect_uris})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


@pytest.mark.asyncio
async def test_register_rejects_custom_scheme_by_default(client_public):
    client, _ = client_public
    resp = await client.post("/register", json={"redirect_uris": ["myapp://callback"]})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


@pytest.mark.asyncio
async def test_register_allows_custom_scheme_when_configured():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        public_registration=True,
        auto_approve=True,
        custom_redirect_uri_schemes=["myapp"],
    )
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.post("/register", json={"redirect_uris": ["myapp://callback"]})
    assert resp.status_code == 201
    assert resp.json()["redirect_uris"] == ["myapp://callback"]


@pytest.mark.asyncio
async def test_register_custom_scheme_matching_is_case_insensitive():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        public_registration=True,
        auto_approve=True,
        custom_redirect_uri_schemes=["MyApp"],
    )
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.post("/register", json={"redirect_uris": ["myapp://callback"]})
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_register_custom_scheme_sanitizes_trailing_colon_and_slashes():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        public_registration=True,
        auto_approve=True,
        custom_redirect_uri_schemes=["myapp://", "otherapp:"],
    )
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp1 = await c.post("/register", json={"redirect_uris": ["myapp://callback"]})
        resp2 = await c.post("/register", json={"redirect_uris": ["otherapp://callback"]})
    assert resp1.status_code == 201
    assert resp2.status_code == 201


def test_custom_redirect_uri_schemes_rejects_bare_string():
    from origo import OAuthProvider
    with pytest.raises(TypeError):
        OAuthProvider(
            base_url="http://testserver",
            public_registration=True,
            custom_redirect_uri_schemes="myapp",
        )


def test_custom_redirect_uri_schemes_rejects_non_string_elements():
    from origo import OAuthProvider
    with pytest.raises(TypeError):
        OAuthProvider(
            base_url="http://testserver",
            public_registration=True,
            custom_redirect_uri_schemes=["myapp", 5],
        )


@pytest.mark.asyncio
async def test_register_only_declared_custom_scheme_allowed():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        public_registration=True,
        auto_approve=True,
        custom_redirect_uri_schemes=["myapp"],
    )
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.post("/register", json={"redirect_uris": ["otherapp://callback"]})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


@pytest.mark.asyncio
async def test_full_flow_with_custom_scheme_redirect_uri():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    provider = OAuthProvider(
        base_url="http://testserver",
        public_registration=True,
        auto_approve=True,
        custom_redirect_uri_schemes=["myapp"],
    )
    async with AsyncClient(transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver") as c:
        reg = await c.post("/register", json={"redirect_uris": ["myapp://callback"]})
        assert reg.status_code == 201
        cid = reg.json()["client_id"]
        csecret = reg.json()["client_secret"]

        verifier, challenge = make_pkce_pair()
        resp = await c.get("/authorize", params={
            "client_id": cid,
            "redirect_uri": "myapp://callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "state": "xyz",
        }, follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith("myapp://callback")
        code = dict(p.split("=") for p in location.split("?", 1)[1].split("&"))["code"]

        resp = await c.post("/token", data={
            "grant_type": "authorization_code",
            "client_id": cid,
            "client_secret": csecret,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "myapp://callback",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()


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
        "response_type": "code",
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
        clients={"c": "s"}, client_redirect_uris={"c": ["https://example.com/cb", "https://example.com/callback", "myapp://callback"]},
        auto_approve=False,
    )
    verifier, challenge = make_pkce_pair()
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/authorize", params={
            "client_id": "c",
            "redirect_uri": "https://example.com/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
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
        "response_type": "code",
    })
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthorized_client"


@pytest.mark.asyncio
async def test_authorize_invalid_redirect_uri(client_public):
    client, _ = client_public
    # Register a client with a specific redirect_uri, then try a different one
    reg = await client.post("/register", json={"redirect_uris": ["https://example.com/cb"]})
    assert reg.status_code == 201
    cid = reg.json()["client_id"]
    _, challenge = make_pkce_pair()
    resp = await client.get("/authorize", params={
        "client_id": cid,
        "redirect_uri": "https://evil.com/steal",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "response_type": "code",
    }, follow_redirects=False)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


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
        clients={"c": "s"}, client_redirect_uris={"c": ["https://example.com/cb", "https://example.com/callback", "myapp://callback"]},
        auto_approve=False,
    )
    verifier, challenge = make_pkce_pair()
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        # First GET to get CSRF token
        get_resp = await c.get("/authorize", params={
            "client_id": "c",
            "redirect_uri": "https://example.com/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "state": "s1",
        })
        csrf_token = get_resp.cookies.get("origo_csrf")

        resp = await c.post("/authorize", data={
            "client_id": "c",
            "redirect_uri": "https://example.com/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "state": "s1",
            "approved": "false",
            "csrf_token": csrf_token,
        }, cookies={"origo_csrf": csrf_token}, follow_redirects=False)
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
        "response_type": "code",
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
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "expires_in" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_plain_pkce_rejected_at_authorize(client_private):
    client, _ = client_private
    _, challenge = make_pkce_pair()
    resp = await client.get("/authorize", params={
        "client_id": "test-client",
        "redirect_uri": "https://example.com/cb",
        "code_challenge": challenge,
        "code_challenge_method": "plain",
        "response_type": "code",
    }, follow_redirects=False)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


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


@pytest.mark.asyncio
async def test_token_basic_auth_malformed_base64(client_private):
    client, _ = client_private
    # b"\xff\xfe" is valid base64 but not valid UTF-8, triggering the except branch
    bad_b64 = base64.b64encode(b"\xff\xfe").decode()
    resp = await client.post("/token",
        data={"grant_type": "authorization_code", "code": "x", "code_verifier": "x", "redirect_uri": "https://example.com/cb"},
        headers={"Authorization": f"Basic {bad_b64}"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_token_client_id_mismatch():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        clients={"client-a": "secret-a", "client-b": "secret-b"}, client_redirect_uris={"client-a": ["https://example.com/cb"], "client-b": ["https://example.com/cb"]},
        auto_approve=True,
    )
    verifier, challenge = make_pkce_pair()
    code = p.storage.store_code("client-a", "https://example.com/cb", challenge)
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.post("/token", data={
            "grant_type": "authorization_code",
            "client_id": "client-b",
            "client_secret": "secret-b",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "https://example.com/cb",
        })
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_grant"


def test_no_clients_warning():
    from origo import OAuthProvider
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        OAuthProvider(base_url="http://testserver")
    assert len(w) == 1
    assert issubclass(w[0].category, UserWarning)
    assert "no clients" in str(w[0].message).lower()


def test_middleware_method():
    import functools
    from origo import OAuthProvider, OAuthMiddleware
    p = OAuthProvider(base_url="http://testserver", clients={"c": "s"}, client_redirect_uris={"c": ["https://example.com/cb", "https://example.com/callback", "myapp://callback"]})
    mw = p.middleware()
    assert isinstance(mw, functools.partial)
    assert mw.func is OAuthMiddleware
    assert mw.keywords.get("provider") is p


@pytest.mark.asyncio
async def test_authorize_unsupported_response_type(client_private):
    client, _ = client_private
    _, challenge = make_pkce_pair()
    resp = await client.get("/authorize", params={
        "client_id": "test-client",
        "redirect_uri": "https://example.com/cb",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "response_type": "token",
    }, follow_redirects=False)
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_response_type"


@pytest.mark.asyncio
async def test_authorize_redirect_uri_with_existing_query_params(client_private):
    client, _ = client_private
    _, challenge = make_pkce_pair()
    resp = await client.get("/authorize", params={
        "client_id": "test-client",
        "redirect_uri": "https://example.com/cb?existing=1",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "response_type": "code",
        "state": "s",
    }, follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "existing=1" in location
    assert "code=" in location
    assert "?" in location
    assert location.count("?") == 1


def test_cleanup_expired_codes_and_tokens():
    from unittest.mock import patch
    from origo.storage import OAuthStorage
    s = OAuthStorage()
    s.seed_clients({"c": "s"}, {"c": ["https://example.com/cb"]})
    code = s.store_code("c", "https://example.com", "challenge")
    token = s.store_token("c")
    assert code in s._codes
    assert token in s._tokens
    with patch("origo.storage._now", return_value=9999999999.0):
        s.store_code("c", "https://example.com", "challenge2")
    assert code not in s._codes
    assert token not in s._tokens

@pytest.mark.asyncio
async def test_register_public_client_with_none_auth_method(client_public):
    client, provider = client_public
    resp = await client.post("/register", json={
        "redirect_uris": ["https://chatgpt.com/connector/oauth/callback-id"],
        "token_endpoint_auth_method": "none",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in data
    assert provider.storage.get_client_auth_method(data["client_id"]) == "none"


@pytest.mark.asyncio
async def test_register_rejects_unsupported_auth_method(client_public):
    client, _ = client_public
    resp = await client.post("/register", json={
        "redirect_uris": ["https://example.com/cb"],
        "token_endpoint_auth_method": "client_secret_jwt",
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_auth_method", [["client_secret_post"], {"a": "b"}, 5, True, None])
async def test_register_rejects_non_string_auth_method(client_public, bad_auth_method):
    client, _ = client_public
    resp = await client.post("/register", json={
        "redirect_uris": ["https://example.com/cb"],
        "token_endpoint_auth_method": bad_auth_method,
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


@pytest.mark.asyncio
async def test_token_exchange_public_pkce_client_with_resource(client_public):
    client, provider = client_public
    reg = await client.post("/register", json={
        "redirect_uris": ["https://chatgpt.com/connector/oauth/callback-id"],
        "token_endpoint_auth_method": "none",
    })
    client_id = reg.json()["client_id"]
    verifier, challenge = make_pkce_pair()
    resource = "http://testserver/mcp"

    auth = await client.get("/authorize", params={
        "client_id": client_id,
        "redirect_uri": "https://chatgpt.com/connector/oauth/callback-id",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "response_type": "code",
        "resource": resource,
    }, follow_redirects=False)
    assert auth.status_code == 302
    code = dict(part.split("=", 1) for part in auth.headers["location"].split("?", 1)[1].split("&"))["code"]

    token_resp = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://chatgpt.com/connector/oauth/callback-id",
        "resource": resource,
    })
    assert token_resp.status_code == 200
    meta = provider.verify_token(token_resp.json()["access_token"])
    assert meta["resource"] == resource


@pytest.mark.asyncio
async def test_token_exchange_rejects_resource_mismatch(client_private):
    client, provider = client_private
    verifier, challenge = make_pkce_pair()
    code = provider.storage.store_code(
        "test-client",
        "https://example.com/cb",
        challenge,
        "S256",
        resource="http://testserver/mcp",
    )
    resp = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://example.com/cb",
        "resource": "https://other.example/mcp",
    })
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_grant"


# --- Refresh token ---

@pytest.mark.asyncio
async def test_token_refresh_grant_issues_new_access_token(client_private):
    client, provider = client_private
    verifier, challenge = make_pkce_pair()
    code = provider.storage.store_code("test-client", "https://example.com/cb", challenge, "S256")
    first = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://example.com/cb",
    })
    assert first.status_code == 200
    refresh_token = first.json()["refresh_token"]

    second = await client.post("/token", data={
        "grant_type": "refresh_token",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "refresh_token": refresh_token,
    })
    assert second.status_code == 200
    data = second.json()
    assert "access_token" in data
    assert data["access_token"] != first.json()["access_token"]
    assert provider.verify_token(data["access_token"]) is not None
    # Rotated: a new refresh token is issued and the old one is single-use.
    assert data["refresh_token"] != refresh_token


@pytest.mark.asyncio
async def test_token_refresh_grant_preserves_resource(client_private):
    client, provider = client_private
    verifier, challenge = make_pkce_pair()
    resource = "http://testserver/mcp"
    code = provider.storage.store_code("test-client", "https://example.com/cb", challenge, "S256", resource=resource)
    first = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://example.com/cb",
        "resource": resource,
    })
    assert first.status_code == 200
    refresh_token = first.json()["refresh_token"]

    # Refresh without passing the resource parameter explicitly
    second = await client.post("/token", data={
        "grant_type": "refresh_token",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "refresh_token": refresh_token,
    })
    assert second.status_code == 200
    data = second.json()
    assert "access_token" in data
    meta = provider.verify_token(data["access_token"])
    assert meta is not None
    assert meta["resource"] == resource


@pytest.mark.asyncio
async def test_token_refresh_grant_rotates_and_invalidates_old_token(client_private):
    client, provider = client_private
    verifier, challenge = make_pkce_pair()
    code = provider.storage.store_code("test-client", "https://example.com/cb", challenge, "S256")
    first = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://example.com/cb",
    })
    refresh_token = first.json()["refresh_token"]

    reused = await client.post("/token", data={
        "grant_type": "refresh_token",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "refresh_token": refresh_token,
    })
    assert reused.status_code == 200

    reused_again = await client.post("/token", data={
        "grant_type": "refresh_token",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "refresh_token": refresh_token,
    })
    assert reused_again.status_code == 401
    assert reused_again.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_token_refresh_grant_wrong_client(client_private):
    client, provider = client_private
    refresh_token = provider.storage.store_refresh_token("test-client")
    provider.storage.seed_clients({"other-client": "other-secret"}, {"other-client": ["https://example.com/cb"]})
    resp = await client.post("/token", data={
        "grant_type": "refresh_token",
        "client_id": "other-client",
        "client_secret": "other-secret",
        "refresh_token": refresh_token,
    })
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_token_refresh_grant_missing_token(client_private):
    client, _ = client_private
    resp = await client.post("/token", data={
        "grant_type": "refresh_token",
        "client_id": "test-client",
        "client_secret": "test-secret",
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_token_refresh_grant_invalid_token(client_private):
    client, _ = client_private
    resp = await client.post("/token", data={
        "grant_type": "refresh_token",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "refresh_token": "bogus",
    })
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_oauth_metadata_includes_cimd_and_oidc_fields():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        public_registration=True,
        scopes_supported=["openid", "email", "files:read"],
    )
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    data = resp.json()
    assert data["client_id_metadata_document_supported"] is True
    assert "userinfo_endpoint" in data
    assert data["scopes_supported"] == ["openid", "email", "files:read"]


@pytest.mark.asyncio
async def test_protected_resource_metadata_includes_scopes_and_docs():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        public_registration=True,
        scopes_supported=["files:read"],
        resource_documentation="https://example.com/docs/mcp",
    )
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    data = resp.json()
    assert data["resource"] == "http://testserver/mcp"
    assert data["scopes_supported"] == ["files:read"]
    assert data["resource_documentation"] == "https://example.com/docs/mcp"


@pytest.mark.asyncio
async def test_authorize_accepts_cimd_client_metadata_document(monkeypatch):
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    client_id = "https://chatgpt.com/oauth/test-client.json"
    redirect_uri = "https://chatgpt.com/connector/oauth/callback-id"

    def fake_fetch(url, allow_private_hosts=False):
        assert url == client_id
        return {
            "client_id": client_id,
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
        }

    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fake_fetch)
    p = OAuthProvider(base_url="http://testserver", public_registration=True, auto_approve=True)
    verifier, challenge = make_pkce_pair()
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        auth = await c.get("/authorize", params={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }, follow_redirects=False)
        assert auth.status_code == 302
        code = dict(part.split("=", 1) for part in auth.headers["location"].split("?", 1)[1].split("&"))["code"]
        token_resp = await c.post("/token", data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
        })
    assert token_resp.status_code == 200
    assert p.storage.get_client_auth_method(client_id) == "none"


@pytest.mark.asyncio
async def test_authorize_cimd_registration_respects_max_dynamic_clients_cap(monkeypatch):
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient

    def fake_fetch(url, allow_private_hosts=False):
        return {
            "client_id": url,
            "redirect_uris": ["https://example.com/callback"],
            "token_endpoint_auth_method": "none",
        }

    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fake_fetch)
    p = OAuthProvider(base_url="http://testserver", public_registration=True, auto_approve=True, max_dynamic_clients=2)
    verifier, challenge = make_pkce_pair()
    client_ids = [f"https://cimd.example.com/doc-{i}.json" for i in range(3)]
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        for cid in client_ids:
            await c.get("/authorize", params={
                "client_id": cid,
                "redirect_uri": "https://example.com/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "response_type": "code",
            }, follow_redirects=False)

    # Oldest CIMD-registered client should have been evicted to stay within the cap.
    assert not p.storage.client_exists(client_ids[0])
    assert p.storage.client_exists(client_ids[1])
    assert p.storage.client_exists(client_ids[2])


@pytest.mark.asyncio
async def test_authorize_cimd_registration_expires_after_ttl(monkeypatch):
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient

    client_id = "https://cimd.example.com/doc.json"

    def fake_fetch(url, allow_private_hosts=False):
        return {
            "client_id": client_id,
            "redirect_uris": ["https://example.com/callback"],
            "token_endpoint_auth_method": "none",
        }

    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fake_fetch)
    p = OAuthProvider(base_url="http://testserver", public_registration=True, auto_approve=True, client_ttl=1)
    verifier, challenge = make_pkce_pair()
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        await c.get("/authorize", params={
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }, follow_redirects=False)

    assert p.storage.client_exists(client_id)
    monkeypatch.setattr("origo.storage._now", lambda: 9999999999.0)
    assert p.storage.client_exists(client_id) is False


@pytest.mark.asyncio
async def test_preregistered_clients_not_evicted_by_dynamic_registration_cap_or_ttl(monkeypatch):
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient

    p = OAuthProvider(
        base_url="http://testserver",
        clients={"preseeded-client": "preseeded-secret"}, client_redirect_uris={"preseeded-client": ["https://example.com/callback"]},
        public_registration=True,
        max_dynamic_clients=1,
        client_ttl=1,
    )
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        for _ in range(3):
            resp = await c.post("/register", json={"redirect_uris": ["https://example.com/cb"]})
            assert resp.status_code == 201

    assert p.storage.client_exists("preseeded-client")
    monkeypatch.setattr("origo.storage._now", lambda: 9999999999.0)
    assert p.storage.client_exists("preseeded-client")
    assert p.storage.get_client_secret("preseeded-client") == "preseeded-secret"


def test_is_public_host_rejects_private_and_loopback_targets():
    from origo.endpoints import _is_public_host
    assert _is_public_host("localhost") is False
    assert _is_public_host("127.0.0.1") is False
    assert _is_public_host("10.0.0.5") is False
    assert _is_public_host("169.254.169.254") is False  # cloud metadata endpoint
    assert _is_public_host("::1") is False


@pytest.mark.asyncio
async def test_authorize_rejects_cimd_client_id_pointing_at_private_host():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    client_id = "https://127.0.0.1/cimd.json"
    verifier, challenge = make_pkce_pair()
    p = OAuthProvider(base_url="http://testserver", public_registration=True, auto_approve=True)
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/authorize", params={
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }, follow_redirects=False)
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthorized_client"


def test_fetch_client_metadata_document_allow_private_hosts_skips_host_check(monkeypatch):
    """allow_private_hosts=True is an explicit opt-in for colocated deployments
    (e.g. an agent and origo sharing a private network) — it must bypass only the
    host check, never the redirect protection."""
    from origo import endpoints

    class _FakeResponse:
        status = 200
        headers = {"content-type": "application/json"}

        def read(self, _n):
            return b'{"client_id": "https://10.0.0.5/cimd.json", "redirect_uris": ["https://10.0.0.5/cb"], "token_endpoint_auth_method": "none"}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _FakeOpener:
        def open(self, request, timeout):
            return _FakeResponse()

    monkeypatch.setattr(endpoints.urllib.request, "build_opener", lambda *a: _FakeOpener())

    # Default: private host rejected before any fetch attempt.
    assert endpoints._fetch_client_metadata_document("https://10.0.0.5/cimd.json") is None

    # Opt-in: private host allowed through to the (still redirect-refusing) fetch.
    metadata = endpoints._fetch_client_metadata_document("https://10.0.0.5/cimd.json", allow_private_hosts=True)
    assert metadata is not None
    assert metadata["client_id"] == "https://10.0.0.5/cimd.json"


@pytest.mark.asyncio
async def test_authorize_allow_private_cimd_wires_through_from_provider(monkeypatch):
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient

    client_id = "https://10.0.0.5/cimd.json"
    redirect_uri = "https://10.0.0.5/callback"
    seen = {}

    def fake_fetch(url, allow_private_hosts=False):
        seen["allow_private_hosts"] = allow_private_hosts
        return {"client_id": client_id, "redirect_uris": [redirect_uri], "token_endpoint_auth_method": "none"}

    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fake_fetch)
    verifier, challenge = make_pkce_pair()
    p = OAuthProvider(base_url="http://testserver", public_registration=True, auto_approve=True, allow_private_cimd=True)
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/authorize", params={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }, follow_redirects=False)
    assert resp.status_code == 302
    assert seen["allow_private_hosts"] is True


@pytest.mark.asyncio
async def test_authorize_rejects_cimd_metadata_without_redirect_uris(monkeypatch):
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    client_id = "https://chatgpt.com/oauth/empty-redirects.json"

    def fake_fetch(url, allow_private_hosts=False):
        return {"client_id": client_id, "token_endpoint_auth_method": "none", "redirect_uris": []}

    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fake_fetch)
    verifier, challenge = make_pkce_pair()
    p = OAuthProvider(base_url="http://testserver", public_registration=True, auto_approve=True)
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/authorize", params={
            "client_id": client_id,
            "redirect_uri": "https://evil.example/anywhere",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }, follow_redirects=False)
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthorized_client"
    # Must not have been registered with an "allow any redirect_uri" state.
    assert not p.storage.client_exists(client_id) or not p.storage.is_redirect_uri_allowed(client_id, "https://evil.example/anywhere")


@pytest.mark.asyncio
async def test_authorize_rejects_cimd_metadata_with_unsafe_redirect_uri_scheme(monkeypatch):
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    client_id = "https://chatgpt.com/oauth/javascript-redirect.json"

    def fake_fetch(url, allow_private_hosts=False):
        return {"client_id": client_id, "token_endpoint_auth_method": "none", "redirect_uris": ["javascript:alert(1)"]}

    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fake_fetch)
    verifier, challenge = make_pkce_pair()
    p = OAuthProvider(base_url="http://testserver", public_registration=True, auto_approve=True)
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/authorize", params={
            "client_id": client_id,
            "redirect_uri": "javascript:alert(1)",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }, follow_redirects=False)
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthorized_client"
    assert not p.storage.client_exists(client_id)


@pytest.mark.asyncio
async def test_authorize_allows_cimd_custom_scheme_when_configured(monkeypatch):
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    client_id = "https://chatgpt.com/oauth/native-redirect.json"

    def fake_fetch(url, allow_private_hosts=False):
        return {"client_id": client_id, "token_endpoint_auth_method": "none", "redirect_uris": ["myapp://callback"]}

    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fake_fetch)
    verifier, challenge = make_pkce_pair()
    p = OAuthProvider(
        base_url="http://testserver",
        public_registration=True,
        auto_approve=True,
        custom_redirect_uri_schemes=["myapp"],
    )
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/authorize", params={
            "client_id": client_id,
            "redirect_uri": "myapp://callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }, follow_redirects=False)
    assert resp.status_code == 302
    assert p.storage.client_exists(client_id)


@pytest.mark.asyncio
async def test_openid_userinfo_and_id_token():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        clients={"c": "s"}, client_redirect_uris={"c": ["https://example.com/cb", "https://example.com/callback", "myapp://callback"]},
        auto_approve=True,
        scopes_supported=["openid", "email"],
        user_email="user@example.com",
    )
    verifier, challenge = make_pkce_pair()
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        auth = await c.get("/authorize", params={
            "client_id": "c",
            "redirect_uri": "https://example.com/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "scope": "openid email",
        }, follow_redirects=False)
        assert auth.status_code == 302
        code = dict(part.split("=", 1) for part in auth.headers["location"].split("?", 1)[1].split("&"))["code"]
        token_resp = await c.post("/token", data={
            "grant_type": "authorization_code",
            "client_id": "c",
            "client_secret": "s",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "https://example.com/cb",
        })
        assert token_resp.status_code == 200
        token_data = token_resp.json()
        assert token_data["scope"] == "openid email"
        assert "id_token" in token_data
        userinfo = await c.get("/userinfo", headers={"Authorization": f"Bearer {token_data['access_token']}"})
    assert userinfo.status_code == 200
    assert userinfo.json()["email"] == "user@example.com"


@pytest.mark.asyncio
async def test_authorize_rejects_unsupported_scope():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        clients={"c": "s"}, client_redirect_uris={"c": ["https://example.com/cb", "https://example.com/callback", "myapp://callback"]},
        auto_approve=True,
        scopes_supported=["files:read"],
    )
    _, challenge = make_pkce_pair()
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/authorize", params={
            "client_id": "c",
            "redirect_uri": "https://example.com/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "scope": "files:write",
        }, follow_redirects=False)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"

@pytest.mark.asyncio
async def test_preregistered_client_redirect_uri_allowlist():
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    p = OAuthProvider(
        base_url="http://testserver",
        clients={"c": "s"},
        client_redirect_uris={"c": ["https://allowed.example/cb"]},
        auto_approve=True,
    )
    _, challenge = make_pkce_pair()
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/authorize", params={
            "client_id": "c",
            "redirect_uri": "https://blocked.example/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }, follow_redirects=False)
    assert resp.status_code == 400
    assert resp.json()["error_description"] == "redirect_uri not allowed."

@pytest.mark.asyncio
async def test_authorize_rejects_cimd_when_public_registration_false(monkeypatch):
    from origo import OAuthProvider
    from httpx import ASGITransport, AsyncClient
    client_id = "https://chatgpt.com/oauth/test-client.json"

    def fake_fetch(url, allow_private_hosts=False):
        raise AssertionError("Should not be called when public_registration=False")

    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fake_fetch)
    p = OAuthProvider(base_url="http://testserver", public_registration=False, auto_approve=True, clients={"existing": "secret"}, client_redirect_uris={"existing": ["https://example.com/cb"]})
    verifier, challenge = make_pkce_pair()
    async with AsyncClient(transport=ASGITransport(app=p.asgi_app()), base_url="http://testserver") as c:
        resp = await c.get("/authorize", params={
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }, follow_redirects=False)
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthorized_client"
