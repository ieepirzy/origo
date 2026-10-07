import pytest
from starlette.testclient import TestClient
from origo.provider import OAuthProvider

def test_csp_injection_prevention():
    provider = OAuthProvider(
        base_url="https://example.com",
        public_registration=True
    )
    client = TestClient(provider.asgi_app())

    # Create a dynamic client with a maliciously crafted redirect_uri
    # The URL has no path, so the semicolon is parsed as part of the netloc.
    # urlparse("https://example.com; frame-ancestors 'self'") parses to netloc="example.com; frame-ancestors 'self'"
    malicious_uri = "https://example.com; frame-ancestors 'self'"

    reg_resp = client.post(
        "/register",
        json={
            "redirect_uris": [malicious_uri],
            "token_endpoint_auth_method": "none"
        }
    )
    assert reg_resp.status_code == 201
    client_id = reg_resp.json()["client_id"]

    auth_resp = client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": malicious_uri,
            "response_type": "code",
            "code_challenge": "abc",
            "code_challenge_method": "S256",
            "state": "123",
            "resource": "https://example.com",
            "scope": "openid"
        }
    )

    assert auth_resp.status_code == 200
    csp = auth_resp.headers["Content-Security-Policy"]
    assert "frame-ancestors 'self'" not in csp
    assert "form-action 'self';" in csp
