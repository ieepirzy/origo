import pytest
from httpx import ASGITransport, AsyncClient
from origo import OAuthProvider
import base64

@pytest.mark.asyncio
async def test_token_rejects_multiple_client_auth_methods():
    provider = OAuthProvider(base_url="https://example.com", clients={"c": "s"}, client_redirect_uris={"c": ["https://example.com/cb"]})
    async with AsyncClient(transport=ASGITransport(app=provider.asgi_app()), base_url="https://example.com") as client:
        credentials = base64.b64encode(b"c:s").decode()
        resp = await client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "c",
                "client_secret": "s"
            },
            headers={"Authorization": f"Basic {credentials}"}
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"
