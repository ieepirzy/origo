import pytest
from starlette.testclient import TestClient
from origo.provider import OAuthProvider

@pytest.fixture
def client_public():
    provider = OAuthProvider(base_url="http://localhost")
    return TestClient(provider.asgi_app())

def test_token_malformed_multipart_returns_400(client_public):
    response = client_public.post(
        "/token",
        data=b"not a multipart body",
        headers={"Content-Type": "multipart/form-data; boundary=boundary"}
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_request"}

def test_authorize_malformed_multipart_returns_400(client_public):
    response = client_public.post(
        "/authorize",
        data=b"not a multipart body",
        headers={"Content-Type": "multipart/form-data; boundary=boundary"}
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_request"}
