import pytest
from starlette.testclient import TestClient
from origo.provider import OAuthProvider
import base64

def test_token_rejects_multiple_auth_methods():
    provider = OAuthProvider(base_url="https://example.com")
    provider.storage.register_client("my_client", "my_secret", ["https://example.com/callback"], "client_secret_basic", {})
    client = TestClient(provider.asgi_app())

    credentials = base64.b64encode(b"my_client:my_secret").decode()

    response = client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "my_client",
        "client_secret": "my_secret",
        "code": "any_code",
        "code_verifier": "any_verifier",
        "redirect_uri": "https://example.com/callback"
    }, headers={
        "Authorization": f"Basic {credentials}"
    })

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
