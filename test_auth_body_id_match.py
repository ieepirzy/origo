import pytest
from httpx import AsyncClient, ASGITransport
from origo.provider import OAuthProvider

@pytest.mark.asyncio
async def test_auth_body_id_match():
    provider = OAuthProvider(base_url="http://localhost", clients={"client_A": "secret_A"}, client_redirect_uris={"client_A": ["http://localhost/cb"]})
    transport = ASGITransport(app=provider.asgi_app())
    async with AsyncClient(transport=transport, base_url="http://localhost") as client:
        import base64
        auth = base64.b64encode(b"client_A:secret_A").decode()
        resp = await client.post(
            "/token",
            data={
                "client_id": "client_A",
                "grant_type": "authorization_code",
                "code": "123",
                "code_verifier": "abc",
                "redirect_uri": "http://localhost/cb",
            },
            headers={"Authorization": f"Basic {auth}"}
        )
        print("Status code:", resp.status_code)
        print("Response:", resp.json())

import asyncio
asyncio.run(test_auth_body_id_match())
