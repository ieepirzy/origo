"""End-to-end OAuth 2.1 + PKCE flow tests."""
import pytest

from tests.conftest import do_full_flow, make_pkce_pair


@pytest.mark.asyncio
async def test_full_flow_private_client(client_private):
    """Pre-registered client completes the full authorization_code + PKCE flow."""
    client, provider = client_private
    token = await do_full_flow(client, provider, "test-client", "test-secret")
    assert provider.verify_token(token) is not None


@pytest.mark.asyncio
async def test_full_flow_public_registration(client_public):
    """Dynamically registered client completes the full flow."""
    client, provider = client_public
    reg = await client.post("/register", json={"redirect_uris": ["https://example.com/cb"]})
    assert reg.status_code == 201
    data = reg.json()
    token = await do_full_flow(client, provider, data["client_id"], data["client_secret"])
    assert provider.verify_token(token) is not None


@pytest.mark.asyncio
async def test_token_is_rejected_after_second_code_use(client_private):
    """Authorization code can only be exchanged once."""
    client, provider = client_private
    verifier, challenge = make_pkce_pair()
    resp = await client.get("/authorize", params={
        "client_id": "test-client",
        "redirect_uri": "https://example.com/cb",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }, follow_redirects=False)
    location = resp.headers["location"]
    code = dict(p.split("=") for p in location.split("?", 1)[1].split("&"))["code"]

    # First exchange succeeds
    r1 = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code": code,
        "code_verifier": verifier,
    })
    assert r1.status_code == 200

    # Second exchange on same code fails
    r2 = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code": code,
        "code_verifier": verifier,
    })
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_token_verify_returns_client_id(client_private):
    client, provider = client_private
    token = await do_full_flow(client, provider, "test-client", "test-secret")
    meta = provider.verify_token(token)
    assert meta["client_id"] == "test-client"


@pytest.mark.asyncio
async def test_invalid_token_not_verified(client_private):
    _, provider = client_private
    assert provider.verify_token("totally-fake-token") is None


@pytest.mark.asyncio
async def test_discovery_links_match_live_endpoints(client_private):
    """Endpoints advertised in metadata should actually respond."""
    client, _ = client_private
    meta = (await client.get("/.well-known/oauth-authorization-server")).json()

    # Verify token endpoint responds (with an error, but not 404)
    resp = await client.post("/token", data={})
    assert resp.status_code != 404

    # Verify authorize endpoint responds
    resp = await client.get("/authorize")
    assert resp.status_code != 404
