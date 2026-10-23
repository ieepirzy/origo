import pytest
from httpx import AsyncClient, ASGITransport
from origo.provider import OAuthProvider

@pytest.mark.asyncio
async def test_token_rejects_multiple_auth_methods():
    provider = OAuthProvider(
        base_url="http://testserver",
        clients={"client1": "secret1"},
        client_redirect_uris={"client1": ["http://localhost/callback"]},
    )
    transport = ASGITransport(app=provider.asgi_app())
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Both form and basic auth
        response = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "somcode",
                "redirect_uri": "http://localhost/callback",
                "client_id": "client1",
                "client_secret": "secret1",
            },
            headers={"Authorization": "Basic Y2xpZW50MTpzZWNyZXQx"} # client1:secret1
        )
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request", "error_description": "Multiple client authentication methods are not allowed."}

        # form client_id and basic auth
        response2 = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "somcode",
                "redirect_uri": "http://localhost/callback",
                "client_id": "client1",
            },
            headers={"Authorization": "Basic Y2xpZW50MTpzZWNyZXQx"} # client1:secret1
        )
        assert response2.status_code == 400
        assert response2.json() == {"error": "invalid_request", "error_description": "Multiple client authentication methods are not allowed."}

        # Just Basic auth should be fine
        response3 = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "somcode",
                "redirect_uri": "http://localhost/callback",
            },
            headers={"Authorization": "Basic Y2xpZW50MTpzZWNyZXQx"} # client1:secret1
        )
        # It shouldn't be 400 invalid_request due to multiple methods, it might be invalid_grant
        assert response3.json() != {"error": "invalid_request", "error_description": "Multiple client authentication methods are not allowed."}
