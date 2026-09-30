import os
import sqlite3
import stat
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from origo import OAuthProvider
from origo.sqlite_storage import SQLiteOAuthStorage
from origo.storage import OAuthStorage

from .conftest import do_full_flow


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "origo.db")


@pytest.fixture(params=["memory", "sqlite"])
def storage(request, db_path):
    if request.param == "memory":
        return OAuthStorage(token_ttl=3600)
    return SQLiteOAuthStorage(db_path, token_ttl=3600)


# --- Interface parity: the same behavioral contract as OAuthStorage ---


def test_store_and_exchange_code(storage):
    code = storage.store_code("c", "https://example.com/cb", "challenge123")
    entry = storage.exchange_code(code)
    assert entry is not None
    assert entry["client_id"] == "c"
    assert entry["redirect_uri"] == "https://example.com/cb"
    assert entry["code_challenge"] == "challenge123"
    assert entry["code_challenge_method"] == "S256"
    assert storage.exchange_code(code) is None  # single-use


def test_exchange_expired_code(storage):
    code = storage.store_code("c", "https://example.com/cb", "challenge")
    with patch("origo.storage._now", return_value=9999999999.0):
        assert storage.exchange_code(code) is None


def test_store_and_verify_token(storage):
    token = storage.store_token("my-client", resource="https://example.com/mcp", scope="a b")
    entry = storage.verify_token(token)
    assert entry is not None
    assert entry["client_id"] == "my-client"
    assert entry["resource"] == "https://example.com/mcp"
    assert entry["scope"] == "a b"
    assert storage.verify_token("bogus") is None


def test_verify_expired_token(storage):
    token = storage.store_token("client")
    with patch("origo.storage._now", return_value=9999999999.0):
        assert storage.verify_token(token) is None


def test_refresh_token_round_trip(storage):
    token = storage.store_refresh_token("my-client", resource="https://example.com/mcp", scope="a b")
    entry = storage.exchange_refresh_token(token)
    assert entry is not None
    assert entry["client_id"] == "my-client"
    assert entry["resource"] == "https://example.com/mcp"
    assert entry["scope"] == "a b"
    assert entry["family"]
    assert storage.exchange_refresh_token(token) is None  # single-use


def test_exchange_expired_refresh_token(storage):
    token = storage.store_refresh_token("my-client")
    with patch("origo.storage._now", return_value=9999999999.0):
        assert storage.exchange_refresh_token(token) is None


def test_register_and_verify_client(storage):
    storage.register_client("new-client", "new-secret", ["https://example.com/cb"])
    assert storage.client_exists("new-client")
    assert storage.get_client_auth_method("new-client") == "client_secret_post"
    assert storage.verify_client_secret("new-client", "new-secret") is True
    assert storage.verify_client_secret("new-client", "wrong") is False
    assert storage.verify_client_secret("nobody", "new-secret") is False
    assert storage.is_redirect_uri_allowed("new-client", "https://example.com/cb")
    assert not storage.is_redirect_uri_allowed("new-client", "https://evil.example/cb")


def test_public_client_has_no_secret(storage):
    storage.register_client("pkce-client", None, ["https://example.com/cb"], token_endpoint_auth_method="none")
    assert storage.get_client_auth_method("pkce-client") == "none"
    assert storage.verify_client_secret("pkce-client", "") is False


def test_seeded_client_verify_and_fail_closed(storage):
    storage.seed_clients({"alice": "s1"}, {"alice": ["https://example.com/cb"]})
    assert storage.client_exists("alice")
    assert storage.verify_client_secret("alice", "s1") is True
    assert storage.verify_client_secret("alice", "nope") is False
    assert storage.get_client_secret("alice") == "s1"
    assert storage.is_redirect_uri_allowed("alice", "https://example.com/cb")


def test_register_client_rejects_past_cap(db_path):
    bounded = SQLiteOAuthStorage(db_path, max_dynamic_clients=2)
    bounded.register_client("client-1", "s1")
    bounded.register_client("client-2", "s2")
    with pytest.raises(ValueError, match="Maximum number of dynamic clients reached"):
        bounded.register_client("client-3", "s3")
    # Re-registering an existing id does not count against the cap.
    bounded.register_client("client-1", "s1-updated")
    assert bounded.verify_client_secret("client-1", "s1-updated")


def test_client_ttl_expires_dynamic_client(db_path):
    storage = SQLiteOAuthStorage(db_path, client_ttl=1)
    storage.register_client("dynamic-client", "secret")
    assert storage.client_exists("dynamic-client")
    with patch("origo.storage._now", return_value=9999999999.0):
        assert storage.client_exists("dynamic-client") is False
        assert storage.get_client_auth_method("dynamic-client") is None


def test_get_client_metadata(storage):
    storage.register_client("meta-client", "secret", client_metadata={"client_name": "Test App"})
    assert storage.get_client_metadata("meta-client")["client_name"] == "Test App"
    assert storage.get_client_metadata("nonexistent") is None


# --- Persistence: what the in-memory backend cannot do ---


def test_tokens_survive_restart(db_path):
    storage = SQLiteOAuthStorage(db_path)
    token = storage.store_token("c", resource="https://example.com/mcp", scope="s")
    refresh = storage.store_refresh_token("c", resource="https://example.com/mcp", scope="s")
    storage.close()

    reopened = SQLiteOAuthStorage(db_path)
    assert reopened.verify_token(token)["client_id"] == "c"
    entry = reopened.exchange_refresh_token(refresh)
    assert entry is not None
    assert entry["resource"] == "https://example.com/mcp"


def test_dynamic_clients_survive_restart(db_path):
    storage = SQLiteOAuthStorage(db_path)
    storage.register_client("dyn", "secret", ["https://example.com/cb"])
    storage.close()

    reopened = SQLiteOAuthStorage(db_path)
    assert reopened.client_exists("dyn")
    assert reopened.verify_client_secret("dyn", "secret")
    assert reopened.is_redirect_uri_allowed("dyn", "https://example.com/cb")


def test_dynamic_client_cap_enforced_across_restarts(db_path):
    storage = SQLiteOAuthStorage(db_path, max_dynamic_clients=1)
    storage.register_client("dyn-1", "s1")
    storage.close()
    reopened = SQLiteOAuthStorage(db_path, max_dynamic_clients=1)
    with pytest.raises(ValueError, match="Maximum number of dynamic clients reached"):
        reopened.register_client("dyn-2", "s2")


def test_seeded_clients_are_not_persisted(db_path):
    storage = SQLiteOAuthStorage(db_path)
    storage.seed_clients({"alice": "s1"}, {"alice": ["https://example.com/cb"]})
    storage.close()

    reopened = SQLiteOAuthStorage(db_path)
    # Config is the source of truth for seeded clients: absent until re-seeded.
    assert reopened.client_exists("alice") is False
    reopened.seed_clients({"alice": "s1"}, {"alice": ["https://example.com/cb"]})
    assert reopened.client_exists("alice")


def test_seeded_client_shadows_persisted_dynamic_client(db_path):
    storage = SQLiteOAuthStorage(db_path)
    storage.register_client("shared-id", "dynamic-secret", ["https://dyn.example/cb"])
    storage.seed_clients({"shared-id": "seeded-secret"}, {"shared-id": ["https://example.com/cb"]})
    assert storage.verify_client_secret("shared-id", "seeded-secret")
    assert storage.verify_client_secret("shared-id", "dynamic-secret") is False
    storage.close()
    # The shadowed dynamic entry was removed, not left to resurface on restart.
    reopened = SQLiteOAuthStorage(db_path)
    assert reopened.client_exists("shared-id") is False


# --- At-rest properties of the database file ---


def test_no_plaintext_credentials_on_disk(db_path):
    storage = SQLiteOAuthStorage(db_path)
    storage.seed_clients({"alice": "seeded-secret-value"}, {"alice": ["https://example.com/cb"]})
    code = storage.store_code("c", "https://example.com/cb", "challenge")
    token = storage.store_token("c")
    refresh = storage.store_refresh_token("c")
    storage.register_client("dyn", "dynamic-secret-value", ["https://example.com/cb"])
    storage.close()

    conn = sqlite3.connect(db_path)
    dump = "\n".join(conn.iterdump())
    conn.close()
    for secret in (code, token, refresh, "dynamic-secret-value", "seeded-secret-value"):
        assert secret not in dump


def test_db_file_permissions(db_path):
    storage = SQLiteOAuthStorage(db_path)
    storage.store_token("c")
    assert stat.S_IMODE(os.stat(db_path).st_mode) == 0o600
    storage.close()


# --- Provider integration: the actual drop-in path ---


async def test_provider_tokens_survive_provider_restart(db_path):
    def make_provider():
        return OAuthProvider(
            base_url="http://testserver",
            clients={"test-client": "test-secret"},
            client_redirect_uris={"test-client": ["https://example.com/cb"]},
            auto_approve=True,
            storage_path=db_path,
        )

    provider = make_provider()
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        access_token = await do_full_flow(client, provider, "test-client", "test-secret")
    assert provider.verify_token(access_token) is not None

    # Simulate a restart: brand-new provider instance over the same file.
    provider.storage.close()
    restarted = make_provider()
    meta = restarted.verify_token(access_token)
    assert meta is not None
    assert meta["client_id"] == "test-client"


async def test_provider_refresh_grant_survives_provider_restart(db_path):
    def make_provider():
        return OAuthProvider(
            base_url="http://testserver",
            clients={"test-client": "test-secret"},
            client_redirect_uris={"test-client": ["https://example.com/cb"]},
            auto_approve=True,
            storage_path=db_path,
        )

    provider = make_provider()
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        resp = await do_full_flow_json(client, "test-client", "test-secret")
        refresh_token = resp["refresh_token"]

    provider.storage.close()
    restarted = make_provider()
    async with AsyncClient(
        transport=ASGITransport(app=restarted.asgi_app()), base_url="http://testserver"
    ) as client:
        resp = await client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "refresh_token": refresh_token,
        })
        assert resp.status_code == 200
        body = resp.json()
        assert restarted.verify_token(body["access_token"]) is not None
        assert body["refresh_token"] != refresh_token  # rotated


async def do_full_flow_json(client, client_id, client_secret, redirect_uri="https://example.com/cb"):
    """Like conftest.do_full_flow but returns the whole /token JSON body."""
    from .conftest import make_pkce_pair

    verifier, challenge = make_pkce_pair()
    resp = await client.get("/authorize", params={
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "xyz",
        "response_type": "code",
    }, follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    code = dict(p.split("=") for p in location.split("?", 1)[1].split("&"))["code"]

    resp = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
    })
    assert resp.status_code == 200
    return resp.json()


def test_provider_warns_on_persistent_public_registration_without_client_ttl(db_path):
    with pytest.warns(UserWarning, match="client_ttl"):
        OAuthProvider(
            base_url="http://testserver",
            public_registration=True,
            storage_path=db_path,
        )

def test_hash_surrogate_handling(db_path):
    storage = SQLiteOAuthStorage(db_path)
    storage.register_client("c", "s")

    # Should not raise UnicodeEncodeError
    assert storage.verify_token("secret\ud800") is None
    assert storage.exchange_code("secret\ud800") is None
    assert storage.exchange_refresh_token("secret\ud800") is None
    assert storage.verify_client_secret("c", "secret\ud800") is False

    storage.close()
