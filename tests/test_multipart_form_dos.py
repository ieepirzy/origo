from starlette.testclient import TestClient

from origo.provider import OAuthProvider


def _client() -> TestClient:
    provider = OAuthProvider(
        base_url="https://example.com",
        auto_approve=True,
        clients={"my_client": "my_secret"},
        client_redirect_uris={"my_client": ["https://example.com/callback"]},
    )
    return TestClient(provider.asgi_app())


def test_malformed_multipart_form_dos_authorize_post():
    response = _client().post(
        "/authorize",
        content=b"malformed data",
        headers={"Content-Type": "multipart/form-data; boundary=bound"},
    )
    assert response.status_code == 400


def test_malformed_multipart_form_dos_token_post():
    response = _client().post(
        "/token",
        content=b"malformed data",
        headers={"Content-Type": "multipart/form-data; boundary=bound"},
    )
    assert response.status_code == 400
