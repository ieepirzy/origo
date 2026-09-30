import pytest
from starlette.testclient import TestClient
from origo.provider import OAuthProvider

def test_http_parameter_pollution_duplicate_keys_authorize_get():
    provider = OAuthProvider(
        base_url="https://example.com",
        auto_approve=True,
        clients={"my_client": "my_secret"},
        client_redirect_uris={"my_client": ["https://example.com/callback"]}
    )
    client = TestClient(provider.asgi_app())

    # Send a request with duplicate 'client_id' parameter in URL query
    response = client.get("/authorize?client_id=my_client&client_id=other_client&redirect_uri=https://example.com/callback&response_type=code&code_challenge=xyz")

    # We expect a 400 Bad Request error if parameter pollution is prevented.
    assert response.status_code == 400
    assert "invalid_request" in response.text.lower()


def test_http_parameter_pollution_duplicate_keys_authorize_post():
    provider = OAuthProvider(
        base_url="https://example.com",
        auto_approve=True,
        clients={"my_client": "my_secret"},
        client_redirect_uris={"my_client": ["https://example.com/callback"]}
    )
    client = TestClient(provider.asgi_app())

    # Need a valid csrf token to get past the csrf check if we got that far, but we should fail early anyway
    response = client.post("/authorize", content="client_id=my_client&client_id=other_client&redirect_uri=https://example.com/callback&response_type=code&code_challenge=xyz", headers={"Content-Type": "application/x-www-form-urlencoded"})

    assert response.status_code == 400
    assert "invalid_request" in response.text.lower()


def test_http_parameter_pollution_duplicate_keys_token_post():
    provider = OAuthProvider(
        base_url="https://example.com",
        auto_approve=True,
        clients={"my_client": "my_secret"},
        client_redirect_uris={"my_client": ["https://example.com/callback"]}
    )
    client = TestClient(provider.asgi_app())

    response = client.post("/token", content="grant_type=authorization_code&client_id=my_client&client_id=other_client&code=xyz", headers={"Content-Type": "application/x-www-form-urlencoded"})

    assert response.status_code == 400
    assert "invalid_request" in response.text.lower()
