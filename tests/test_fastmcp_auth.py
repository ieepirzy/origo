import pytest

fastmcp = pytest.importorskip("fastmcp", reason="requires the fastmcp extra")

from origo.provider import OAuthProvider
from origo.fastmcp_auth import OrigoTokenVerifier


def _provider() -> OAuthProvider:
    return OAuthProvider(
        base_url="https://mirarun.example.com",
        clients={"operator-client": "operator-secret"},
    )


def _issue(provider: OAuthProvider, *, resource=None, scope: str = "") -> str:
    # store_token is the same call /token uses to mint the access token —
    # issuing through storage keeps these tests off the full authorization
    # code dance, which test_endpoints.py already covers.
    return provider.storage.store_token("operator-client", resource=resource, scope=scope)


@pytest.mark.anyio
async def test_valid_token_verifies_with_origo_claims():
    provider = _provider()
    token = _issue(provider, resource=provider.resource_identifier, scope="read")
    access = await OrigoTokenVerifier(provider).verify_token(token)
    assert access is not None
    assert access.client_id == "operator-client"
    assert access.scopes == ["read"]
    # The raw origo metadata rides along; note what is NOT here — no
    # routine/run identifiers — which is how a composing host tells this
    # credential class apart from its own.
    assert access.claims["client_id"] == "operator-client"
    assert "routine_id" not in access.claims


@pytest.mark.anyio
async def test_unknown_token_is_rejected():
    provider = _provider()
    assert await OrigoTokenVerifier(provider).verify_token("not-a-token") is None


@pytest.mark.anyio
async def test_token_minted_for_a_different_resource_is_rejected():
    # Same check OAuthMiddleware enforces: a token issued for another
    # resource URI must not open this one.
    provider = _provider()
    token = _issue(provider, resource="https://other.example.com/mcp")
    assert await OrigoTokenVerifier(provider).verify_token(token) is None


@pytest.mark.anyio
async def test_resourceless_token_is_accepted():
    # provider.verify_token treats a token with no stored resource as valid
    # for any resource (the pre-registered-client flow can mint these);
    # the adapter must not be stricter than the middleware it mirrors.
    provider = _provider()
    token = _issue(provider, resource=None)
    assert await OrigoTokenVerifier(provider).verify_token(token) is not None
