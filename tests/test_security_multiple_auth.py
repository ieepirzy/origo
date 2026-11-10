import pytest
from httpx import AsyncClient, ASGITransport
from origo.provider import OAuthProvider
import base64

@pytest.mark.asyncio
async def test_token_rejects_multiple_auth_methods():
    provider = OAuthProvider(
        base_url="https://example.com",
        clients={"client1": "secret1"},
        client_redirect_uris={"client1": ["https://example.com/cb"]}
    )
    transport = ASGITransport(app=provider.asgi_app())
    async with AsyncClient(transport=transport, base_url="https://example.com") as client:
        basic_auth = base64.b64encode(b"client1:secret1").decode()
        response = await client.post(
            "/token",
            data={
                "client_id": "client1",
                "client_secret": "secret1",
                "grant_type": "authorization_code",
                "code": "dummy",
                "code_verifier": "dummy",
                "redirect_uri": "https://example.com/cb"
            },
            headers={"Authorization": f"Basic {basic_auth}"}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"
        assert "Multiple client authentication methods are not allowed" in response.json()["error_description"]
