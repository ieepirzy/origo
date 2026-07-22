import pytest
from starlette.testclient import TestClient
from origo.provider import OAuthProvider

def test_compare_digest_dos_csrf():
    provider = OAuthProvider(base_url="https://example.com", auto_approve=False)
    provider.storage.register_client("any", "any", ["https://example.com/callback"], "none", {})
    client = TestClient(provider.asgi_app())
    response = client.post("/authorize", data={
        "client_id": "any",
        "redirect_uri": "https://example.com/callback",
        "code_challenge": "any",
        "response_type": "code",
        "csrf_token": "äbc"  # non-ascii
    }, cookies={"__Host-origo_csrf": "abc"})
    assert response.status_code == 400
    assert "CSRF token missing or invalid" in response.text

def test_compare_digest_dos_token():
    provider = OAuthProvider(base_url="https://example.com")
    provider.storage.register_client("my_client", "my_secret", ["https://example.com/callback"], "client_secret_post", {})
    client = TestClient(provider.asgi_app())
    response = client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "my_client",
        "client_secret": "my_s\u00e9cret",  # non-ascii
        "code": "any_code",
        "code_verifier": "any_verifier",
        "redirect_uri": "https://example.com/callback"
    })
    assert response.status_code == 401
    assert "invalid_client" in response.text
