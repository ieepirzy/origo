import pytest
from starlette.testclient import TestClient
from origo.provider import OAuthProvider

def test_authorize_urlparse_crash_prevention():
    provider = OAuthProvider(base_url="https://example.com", public_registration=True)
    client = TestClient(provider.asgi_app())

    # Send a request with a client_id that will crash urlparse with ValueError
    # URL parse crashes on URLs starting with "https://]"
    response = client.get(
        "/authorize?client_id=https://]&redirect_uri=https://example.com/cb&response_type=code&code_challenge=abc"
    )

    # With the fix, we expect a 400 Bad Request error from the endpoint itself,
    # rather than a 500 error due to unhandled ValueError.
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_request", "error_description": "invalid client_id."}
