import base64
import hashlib
import secrets

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from origo import OAuthProvider


@pytest.fixture
def provider_private():
    return OAuthProvider(
        base_url="http://testserver",
        clients={"test-client": "test-secret"},
        client_redirect_uris={"test-client": ["https://example.com/cb", "https://example.com/cb?existing=1"]},
        auto_approve=True,
    )


@pytest.fixture
def provider_public():
    return OAuthProvider(
        base_url="http://testserver",
        public_registration=True,
        auto_approve=True,
    )


@pytest_asyncio.fixture
async def client_private(provider_private):
    async with AsyncClient(
        transport=ASGITransport(app=provider_private.asgi_app()),
        base_url="http://testserver",
    ) as client:
        yield client, provider_private


@pytest_asyncio.fixture
async def client_public(provider_public):
    async with AsyncClient(
        transport=ASGITransport(app=provider_public.asgi_app()),
        base_url="http://testserver",
    ) as client:
        yield client, provider_public


def make_pkce_pair():
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


async def do_full_flow(client, provider, client_id, client_secret, redirect_uri="https://example.com/cb"):
    verifier, challenge = make_pkce_pair()
    resp = await client.get("/authorize", params={
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "xyz",
        "response_type": "code",
    }, follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    code = dict(p.split("=") for p in location.split("?", 1)[1].split("&"))["code"]

    resp = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
    })
    assert resp.status_code == 200
    return resp.json()["access_token"]
