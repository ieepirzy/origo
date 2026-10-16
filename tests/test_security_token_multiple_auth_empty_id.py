import pytest
from httpx import AsyncClient, ASGITransport
from origo import OAuthProvider
import base64

@pytest.mark.asyncio
async def test_token_rejects_multiple_auth_methods_empty_string_body():
    provider = OAuthProvider(
        base_url="https://test.example",
        clients={"client_id": "client_secret"},
        client_redirect_uris={"client_id": ["https://test.example/cb"]}
    )
    transport = ASGITransport(app=provider.asgi_app())
    async with AsyncClient(transport=transport, base_url="https://test.example") as client:
        auth_header = "Basic " + base64.b64encode(b"client_id:client_secret").decode()
        response = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "dummy_code",
                "code_verifier": "dummy_verifier",
                "client_id": "", # explicitly pass empty string
                "redirect_uri": "https://test.example/cb"
            },
            headers={"Authorization": auth_header}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"
