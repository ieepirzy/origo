import pytest
from starlette.testclient import TestClient
from origo.provider import OAuthProvider

def test_authorize_invalidurl_crash_prevention():
    provider = OAuthProvider(base_url="https://example.com", public_registration=True)
    client = TestClient(provider.asgi_app())

    # Send a request with a client_id containing \r to trigger http.client.InvalidURL
    # in _fetch_client_metadata_document
    response = client.get(
        "/authorize?client_id=https://example.com/test%0d&redirect_uri=https://example.com/cb&response_type=code&code_challenge=abc"
    )

    # We expect a 401 error or similar API error from the endpoint itself,
    # rather than a 500 Internal Server Error due to unhandled InvalidURL.
    assert response.status_code == 401
    assert "error" in response.json()
