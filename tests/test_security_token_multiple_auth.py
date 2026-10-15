import pytest
from httpx import AsyncClient, ASGITransport
from origo.provider import OAuthProvider

@pytest.mark.asyncio
async def test_token_rejects_multiple_auth_methods():
    provider = OAuthProvider(
        base_url="https://example.com",
        clients={"client1": "secret1"},
    )
    transport = ASGITransport(app=provider.asgi_app())
    async with AsyncClient(transport=transport, base_url="https://example.com") as client:
        import base64
        basic_auth = base64.b64encode(b"client1:secret1").decode()

        # Test basic auth works alone
        resp = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "dummy",
                "code_verifier": "dummy",
                "redirect_uri": "https://dummy"
            },
            headers={"Authorization": f"Basic {basic_auth}"},
        )
        # Should be invalid_grant since dummy code is invalid, not invalid_request
        assert resp.json().get("error") != "invalid_request"

        # Test body auth works alone
        resp2 = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "client1",
                "client_secret": "secret1",
                "code": "dummy",
                "code_verifier": "dummy",
                "redirect_uri": "https://dummy"
            },
        )
        assert resp2.json().get("error") != "invalid_request"

        # Test both basic auth and client_id in body
        resp3 = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "client1",
                "code": "dummy",
                "code_verifier": "dummy",
                "redirect_uri": "https://dummy"
            },
            headers={"Authorization": f"Basic {basic_auth}"},
        )
        assert resp3.status_code == 400
        assert resp3.json().get("error") == "invalid_request"
        assert "Multiple client authentication methods" in resp3.json().get("error_description", "")
