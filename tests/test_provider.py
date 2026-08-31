import functools
import warnings

import pytest
from starlette.applications import Starlette

from origo.provider import OAuthProvider
from origo.middleware import OAuthMiddleware


def test_provider_initialization_warnings():
    with pytest.warns(UserWarning, match="public_registration=False but no clients provided"):
        OAuthProvider(base_url="http://example.com")


def test_provider_initialization_no_warning():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        OAuthProvider(base_url="http://example.com", public_registration=True)
        OAuthProvider(
            base_url="http://example.com",
            clients={"client": "secret"},
            client_redirect_uris={"client": ["https://example.com/cb"]}
        )


def test_custom_redirect_uri_schemes_type_error():
    with pytest.raises(TypeError, match="custom_redirect_uri_schemes must be a list of strings, not a single string"):
        OAuthProvider(base_url="http://example.com", custom_redirect_uri_schemes="myapp")

    with pytest.raises(TypeError, match="custom_redirect_uri_schemes must contain only strings"):
        OAuthProvider(base_url="http://example.com", custom_redirect_uri_schemes=["myapp", 123])


def test_custom_redirect_uri_schemes_sanitization():
    provider = OAuthProvider(
        base_url="http://example.com",
        public_registration=True,
        custom_redirect_uri_schemes=["MyApp", "scheme://", "valid-scheme:", "", "/"]
    )
    assert provider.custom_redirect_uri_schemes == {"myapp", "scheme", "valid-scheme"}


def test_provider_properties():
    provider = OAuthProvider(base_url="http://example.com/", mcp_path="/api/mcp", public_registration=True)
    assert provider.base_url == "http://example.com"
    assert provider.protected_resource_metadata_url == "http://example.com/.well-known/oauth-protected-resource"
    assert provider.resource_identifier == "http://example.com/api/mcp"


def test_asgi_app():
    provider = OAuthProvider(base_url="http://example.com", public_registration=True)
    app = provider.asgi_app()
    assert isinstance(app, Starlette)
    assert app is provider._app


def test_middleware():
    provider = OAuthProvider(base_url="http://example.com", public_registration=True)
    middleware_partial = provider.middleware()
    assert isinstance(middleware_partial, functools.partial)
    assert middleware_partial.func is OAuthMiddleware
    assert middleware_partial.keywords == {"provider": provider}


def test_verify_token():
    provider = OAuthProvider(base_url="http://example.com", public_registration=True)

    # Mocking storage.verify_token to simulate different scenarios
    # Scenario 1: Invalid token
    provider.storage.verify_token = lambda token: None
    assert provider.verify_token("invalid_token") is None

    # Scenario 2: Valid token, no resource constraint in provider call, no resource in token
    meta1 = {"client_id": "test"}
    provider.storage.verify_token = lambda token: meta1
    assert provider.verify_token("valid_token") == meta1

    # Scenario 3: Valid token, no resource constraint in provider call, resource in token
    meta2 = {"client_id": "test", "resource": "res1"}
    provider.storage.verify_token = lambda token: meta2
    assert provider.verify_token("valid_token") == meta2

    # Scenario 4: Valid token, resource constraint in provider call, resource matches token
    assert provider.verify_token("valid_token", resource="res1") == meta2

    # Scenario 5: Valid token, resource constraint in provider call, resource mismatch with token
    assert provider.verify_token("valid_token", resource="res2") is None

    # Scenario 6: Valid token, resource constraint in provider call, token has no resource
    meta3 = {"client_id": "test"}
    provider.storage.verify_token = lambda token: meta3
    assert provider.verify_token("valid_token", resource="res1") == meta3

@pytest.mark.asyncio
async def test_authorize_duplicate_parameters(client_public):
    """Test that requests with duplicate parameters are rejected."""
    client, provider = client_public
    # Duplicate code_challenge
    response = await client.get("/authorize?client_id=c&redirect_uri=https://example.com/cb&response_type=code&code_challenge=xyz&code_challenge=abc&code_challenge_method=S256")
    assert response.status_code == 400
    assert response.json()["error_description"] == "Duplicate parameters are not allowed."

@pytest.mark.asyncio
async def test_token_duplicate_parameters(client_public):
    """Test that token requests with duplicate parameters are rejected."""
    client, provider = client_public
    response = await client.post(
        "/token",
        content=b"grant_type=authorization_code&code=testcode&redirect_uri=https://example.com/cb&client_id=c&client_id=c2",
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 400
    assert response.json()["error_description"] == "Duplicate parameters are not allowed."
