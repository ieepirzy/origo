import pytest
from starlette.testclient import TestClient
from origo.provider import OAuthProvider

def test_token_endpoint_rejects_multiple_auth_methods():
    provider = OAuthProvider(
        base_url="https://example.com",
        auto_approve=True,
        clients={"my_client": "my_secret"},
        client_redirect_uris={"my_client": ["https://example.com/callback"]}
    )
    client = TestClient(provider.asgi_app())
    response = client.post(
        "/token",
        content="grant_type=authorization_code&client_id=my_client&client_secret=my_secret&code=xyz&redirect_uri=https://example.com/callback",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic bXlfY2xpZW50Om15X3NlY3JldA=="
        }
    )
    assert response.status_code == 400
    assert "invalid_request" in response.text.lower()
