import pytest
from httpx import AsyncClient, ASGITransport
from origo.provider import OAuthProvider

@pytest.mark.asyncio
async def test_multiple_client_auth_methods_rejected():
    provider = OAuthProvider(base_url="http://testserver", clients={"c": "s"})
    transport = ASGITransport(app=provider.asgi_app())
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Include both form body credentials and Basic Auth
        response = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "somecode",
                "code_verifier": "someverifier",
                "redirect_uri": "https://example.com/cb",
                "client_id": "c",
                "client_secret": "s",
            },
            headers={"Authorization": "Basic Yzpz"} # c:s base64 encoded
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"
