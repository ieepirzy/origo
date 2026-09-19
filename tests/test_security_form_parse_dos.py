import pytest
from starlette.testclient import TestClient
from origo import OAuthProvider

def test_token_malformed_multipart_dos():
    app = OAuthProvider(base_url="http://localhost", clients={"a": "b"}, client_redirect_uris={"a": ["https://example.com/cb"]})
    client = TestClient(app.asgi_app())

    response = client.post(
        "/token",
        headers={"Content-Type": "multipart/form-data; boundary=invalid"},
        content=b"not a valid multipart body",
    )
    assert response.status_code == 400

def test_authorize_malformed_multipart_dos():
    app = OAuthProvider(base_url="http://localhost", clients={"a": "b"}, client_redirect_uris={"a": ["https://example.com/cb"]})
    client = TestClient(app.asgi_app())

    response = client.post(
        "/authorize",
        headers={"Content-Type": "multipart/form-data; boundary=invalid"},
        content=b"not a valid multipart body",
    )
    assert response.status_code == 400
