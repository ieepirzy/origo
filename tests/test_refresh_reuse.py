"""Refresh-token rotation reuse detection (OAuth 2.1 §4.3.1 / BCP).

Replaying a rotated-out refresh token is evidence the token leaked: someone
other than the party holding the newest token in the chain is presenting an
old one. On detection the whole family — every refresh AND access token
descended from the same grant — is revoked, so the thief's rotated chain
dies with the replay instead of living on unnoticed.
"""

import pytest

from origo import OAuthProvider
from origo.sqlite_storage import SQLiteOAuthStorage
from origo.storage import OAuthStorage

from .conftest import make_pkce_pair


@pytest.fixture(params=["memory", "sqlite"])
def storage(request, tmp_path):
    if request.param == "memory":
        return OAuthStorage()
    return SQLiteOAuthStorage(str(tmp_path / "origo.db"))


def test_replay_of_consumed_refresh_token_revokes_family(storage):
    old = storage.store_refresh_token("c", scope="s")
    entry = storage.exchange_refresh_token(old)
    family = entry["family"]
    new = storage.store_refresh_token("c", scope="s", family=family)
    access = storage.store_token("c", scope="s", family=family)

    # Replay of the consumed token: rejected, and the whole family dies.
    assert storage.exchange_refresh_token(old) is None
    assert storage.exchange_refresh_token(new) is None
    assert storage.verify_token(access) is None


def test_replay_does_not_touch_other_families(storage):
    victim_old = storage.store_refresh_token("c")
    victim_family = storage.exchange_refresh_token(victim_old)["family"]
    victim_new = storage.store_refresh_token("c", family=victim_family)

    bystander_refresh = storage.store_refresh_token("c2")
    bystander_access = storage.store_token("c2", family="other-family")

    assert storage.exchange_refresh_token(victim_old) is None  # triggers revocation
    assert storage.exchange_refresh_token(victim_new) is None  # family dead

    assert storage.exchange_refresh_token(bystander_refresh) is not None
    assert storage.verify_token(bystander_access) is not None


def test_revoked_family_refuses_new_issuance(storage):
    """The revoked-family marker closes the exchange/issuance race: a caller
    that exchanged a refresh token before a concurrent replay revoked the
    family must not be able to mint replacements afterwards."""
    from origo.storage import FamilyRevokedError

    old = storage.store_refresh_token("c")
    family = storage.exchange_refresh_token(old)["family"]
    storage.revoke_family(family)

    with pytest.raises(FamilyRevokedError):
        storage.store_token("c", family=family)
    with pytest.raises(FamilyRevokedError):
        storage.store_refresh_token("c", family=family)
    # Unrelated (and family-less) issuance is unaffected.
    assert storage.store_token("c", family="other")
    assert storage.store_token("c")


def test_sqlite_cross_process_race_cannot_outlive_revocation(tmp_path):
    """Two connections on one file, interleaved like two processes: A
    exchanges, B replays the same token (reuse -> family revoked), then A
    tries to mint replacements — A must fail, not resurrect the family."""
    from origo.storage import FamilyRevokedError

    db = str(tmp_path / "origo.db")
    proc_a = SQLiteOAuthStorage(db)
    proc_b = SQLiteOAuthStorage(db)

    stolen = proc_a.store_refresh_token("c")
    entry = proc_a.exchange_refresh_token(stolen)  # A wins the exchange
    assert proc_b.exchange_refresh_token(stolen) is None  # B replays -> revokes family
    with pytest.raises(FamilyRevokedError):
        proc_a.store_refresh_token("c", family=entry["family"])
    with pytest.raises(FamilyRevokedError):
        proc_a.store_token("c", family=entry["family"])


def test_unknown_refresh_token_revokes_nothing(storage):
    live = storage.store_refresh_token("c")
    assert storage.exchange_refresh_token("never-issued") is None
    assert storage.exchange_refresh_token(live) is not None


async def test_endpoint_maps_family_revoked_to_401(monkeypatch):
    """If the family is revoked between exchange and issuance, /token answers
    401 invalid_grant, not a 500."""
    from origo.storage import FamilyRevokedError
    from httpx import ASGITransport, AsyncClient

    provider = OAuthProvider(
        base_url="http://testserver",
        clients={"test-client": "test-secret"},
        client_redirect_uris={"test-client": ["https://example.com/cb"]},
        auto_approve=True,
    )
    storage = provider.storage
    real_exchange = storage.exchange_refresh_token

    def exchange_then_lose_race(token):
        entry = real_exchange(token)
        if entry is not None:
            storage.revoke_family(entry["family"])  # concurrent replay wins
        return entry

    monkeypatch.setattr(storage, "exchange_refresh_token", exchange_then_lose_race)

    refresh_token = storage.store_refresh_token("test-client")
    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        resp = await client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "refresh_token": refresh_token,
        })
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_grant"


async def test_endpoint_refresh_reuse_revokes_family():
    provider = OAuthProvider(
        base_url="http://testserver",
        clients={"test-client": "test-secret"},
        client_redirect_uris={"test-client": ["https://example.com/cb"]},
        auto_approve=True,
    )
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(
        transport=ASGITransport(app=provider.asgi_app()), base_url="http://testserver"
    ) as client:
        verifier, challenge = make_pkce_pair()
        resp = await client.get("/authorize", params={
            "client_id": "test-client",
            "redirect_uri": "https://example.com/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }, follow_redirects=False)
        code = dict(
            p.split("=") for p in resp.headers["location"].split("?", 1)[1].split("&")
        )["code"]
        resp = await client.post("/token", data={
            "grant_type": "authorization_code",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "https://example.com/cb",
        })
        first = resp.json()

        # Legitimate rotation.
        resp = await client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "refresh_token": first["refresh_token"],
        })
        assert resp.status_code == 200
        second = resp.json()

        # Replay of the rotated-out token.
        resp = await client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "refresh_token": first["refresh_token"],
        })
        assert resp.status_code == 401

        # The rotated chain and both access tokens are dead too.
        resp = await client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "refresh_token": second["refresh_token"],
        })
        assert resp.status_code == 401
        assert provider.verify_token(first["access_token"]) is None
        assert provider.verify_token(second["access_token"]) is None
