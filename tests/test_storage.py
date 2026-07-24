from unittest.mock import patch

import pytest

from origo.storage import OAuthStorage


@pytest.fixture
def storage():
    return OAuthStorage(token_ttl=3600)


def test_seed_clients(storage):
    storage.seed_clients({"alice": "secret1", "bob": "secret2"}, {"alice": ["https://example.com"], "bob": ["https://example.com/cb"]})
    assert storage.client_exists("alice")
    assert storage.client_exists("bob")
    assert not storage.client_exists("charlie")


def test_register_client(storage):
    storage.register_client("new-client", "new-secret")
    assert storage.client_exists("new-client")
    assert storage.get_client_secret("new-client") == "new-secret"


def test_get_client_secret_unknown(storage):
    assert storage.get_client_secret("nobody") is None


def test_store_and_exchange_code(storage):
    storage.seed_clients({"c": "s"}, {"c": ["https://example.com/cb"]})
    code = storage.store_code("c", "https://example.com/cb", "challenge123")
    entry = storage.exchange_code(code)
    assert entry is not None
    assert entry["client_id"] == "c"
    assert entry["redirect_uri"] == "https://example.com/cb"
    assert entry["code_challenge"] == "challenge123"
    assert entry["code_challenge_method"] == "S256"


def test_exchange_code_consumed_only_once(storage):
    storage.seed_clients({"c": "s"}, {"c": ["https://example.com/cb"]})
    code = storage.store_code("c", "https://example.com/cb", "challenge123")
    assert storage.exchange_code(code) is not None
    assert storage.exchange_code(code) is None


def test_exchange_unknown_code(storage):
    assert storage.exchange_code("nonexistent") is None


def test_exchange_expired_code(storage):
    storage.seed_clients({"c": "s"}, {"c": ["https://example.com/cb"]})
    code = storage.store_code("c", "https://example.com/cb", "challenge")
    # Simulate expiry by patching _now to return a future time
    with patch("origo.storage._now", return_value=9999999999.0):
        assert storage.exchange_code(code) is None


def test_store_and_verify_token(storage):
    token = storage.store_token("my-client")
    entry = storage.verify_token(token)
    assert entry is not None
    assert entry["client_id"] == "my-client"


def test_verify_unknown_token(storage):
    assert storage.verify_token("bogus") is None


def test_verify_expired_token(storage):
    token = storage.store_token("client")
    with patch("origo.storage._now", return_value=9999999999.0):
        assert storage.verify_token(token) is None
    # Token should have been removed
    assert token not in storage._tokens


def test_token_ttl_respected(storage):
    short_storage = OAuthStorage(token_ttl=1)
    token = short_storage.store_token("c")
    assert short_storage.verify_token(token) is not None
    with patch("origo.storage._now", return_value=9999999999.0):
        assert short_storage.verify_token(token) is None


def test_is_redirect_uri_allowed_unknown_client(storage):
    assert storage.is_redirect_uri_allowed("nonexistent", "https://example.com") is False


def test_store_and_exchange_refresh_token(storage):
    token = storage.store_refresh_token("my-client", resource="https://example.com/mcp", scope="a b")
    entry = storage.exchange_refresh_token(token)
    assert entry is not None
    assert entry["client_id"] == "my-client"
    assert entry["resource"] == "https://example.com/mcp"
    assert entry["scope"] == "a b"


def test_exchange_refresh_token_consumed_only_once(storage):
    token = storage.store_refresh_token("my-client")
    assert storage.exchange_refresh_token(token) is not None
    assert storage.exchange_refresh_token(token) is None


def test_exchange_unknown_refresh_token(storage):
    assert storage.exchange_refresh_token("nonexistent") is None


def test_exchange_expired_refresh_token(storage):
    token = storage.store_refresh_token("my-client")
    with patch("origo.storage._now", return_value=9999999999.0):
        assert storage.exchange_refresh_token(token) is None


def test_refresh_token_ttl_respected():
    short_storage = OAuthStorage(refresh_token_ttl=1)
    token = short_storage.store_refresh_token("c")
    with patch("origo.storage._now", return_value=9999999999.0):
        assert short_storage.exchange_refresh_token(token) is None


# --- Dynamic client registration bound/TTL (DCR + CIMD both go through register_client) ---


def test_register_client_rejects_past_cap():
    bounded_storage = OAuthStorage(max_dynamic_clients=2)
    bounded_storage.register_client("client-1", "s1")
    bounded_storage.register_client("client-2", "s2")

    with pytest.raises(ValueError, match="Maximum number of dynamic clients reached"):
        bounded_storage.register_client("client-3", "s3")

    assert bounded_storage.client_exists("client-1")
    assert bounded_storage.client_exists("client-2")
    assert not bounded_storage.client_exists("client-3")


def test_register_client_cap_does_not_evict_when_re_registering_same_id():
    bounded_storage = OAuthStorage(max_dynamic_clients=2)
    bounded_storage.register_client("client-1", "s1")
    bounded_storage.register_client("client-2", "s2")
    # Re-registering an existing client_id should not count as a new entry against the cap.
    bounded_storage.register_client("client-1", "s1-updated")

    assert bounded_storage.client_exists("client-1")
    assert bounded_storage.client_exists("client-2")
    assert bounded_storage.get_client_secret("client-1") == "s1-updated"


def test_register_client_ttl_expires_dynamic_client():
    storage = OAuthStorage(client_ttl=1)
    storage.register_client("dynamic-client", "secret")
    assert storage.client_exists("dynamic-client")
    with patch("origo.storage._now", return_value=9999999999.0):
        assert storage.client_exists("dynamic-client") is False
        assert storage.get_client_secret("dynamic-client") is None


def test_register_client_no_ttl_by_default(storage):
    storage.register_client("dynamic-client", "secret")
    with patch("origo.storage._now", return_value=9999999999.0):
        assert storage.client_exists("dynamic-client")


def test_seeded_clients_survive_dynamic_client_ttl_expiry():
    storage = OAuthStorage(client_ttl=1)
    storage.seed_clients({"permanent-client": "s"}, {"permanent-client": ["https://example.com/cb"]})
    storage.register_client("dynamic-client", "secret")
    with patch("origo.storage._now", return_value=9999999999.0):
        assert storage.client_exists("permanent-client")
        assert storage.get_client_secret("permanent-client") == "s"
        assert storage.client_exists("dynamic-client") is False


def test_seeded_clients_do_not_count_against_dynamic_cap():
    bounded_storage = OAuthStorage(max_dynamic_clients=1)
    bounded_storage.seed_clients({"permanent-1": "s1", "permanent-2": "s2"}, {"permanent-1": ["https://example.com/cb"], "permanent-2": ["https://example.com/cb"]})
    bounded_storage.register_client("dynamic-1", "s3")
    with pytest.raises(ValueError, match="Maximum number of dynamic clients reached"):
        bounded_storage.register_client("dynamic-2", "s4")

    assert bounded_storage.client_exists("permanent-1")
    assert bounded_storage.client_exists("permanent-2")
    assert bounded_storage.client_exists("dynamic-1")
    assert not bounded_storage.client_exists("dynamic-2")


def test_seeded_clients_are_never_evicted_by_cap_overflow():
    bounded_storage = OAuthStorage(max_dynamic_clients=0)
    bounded_storage.seed_clients({"permanent-client": "s"}, {"permanent-client": ["https://example.com/cb"]})
    for i in range(5):
        with pytest.raises(ValueError, match="Maximum number of dynamic clients reached"):
            bounded_storage.register_client(f"dynamic-{i}", "secret")

    assert bounded_storage.client_exists("permanent-client")

def test_get_client_auth_method_unknown(storage):
    assert storage.get_client_auth_method("nobody") is None

def test_get_client_auth_method_default(storage):
    storage.register_client("new-client", "new-secret")
    assert storage.get_client_auth_method("new-client") == "client_secret_post"

def test_get_client_auth_method_custom(storage):
    storage.register_client("new-client", "new-secret", token_endpoint_auth_method="none")
    assert storage.get_client_auth_method("new-client") == "none"
