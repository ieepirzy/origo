"""recheck_on_refresh: every origo refresh first refreshes at the IdP.

Builds on test_oidc's FakeIdP, extended into an IdP that issues refresh
tokens, rotates them strictly (a spent one is invalid_grant, so a test only
passes if origo kept the rotated one), and can disable a person, change their
groups, or go down.
"""

import os
import sqlite3
import time

import pytest

from origo import IdentityError, IdentityProvider, OAuthProvider, TokenSealer
from tests.test_oidc import (
    BASE,
    CLIENT_REDIRECT,
    ISSUER,
    FakeIdP,
    _no_consent_opt_in,  # noqa: F401  (autouse fixture)
    _refresh,
    client_redirect_params,
    full_sign_in,
    http,  # noqa: F401  (fixture)
    sign_in,
)

KEY_A = bytes(range(32))
KEY_B = bytes(range(32, 64))


class RefreshingIdP(FakeIdP):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.live_refresh: dict[str, dict] = {}  # IdP refresh token -> grant
        self.issued_refresh: list[str] = []
        self.disabled: set[str] = set()
        self.user_claims: dict[str, dict] = {}  # sub -> claims overriding the sign-in's
        self.down = False
        self.issue_refresh_tokens = True
        self.id_token_on_refresh = True
        self.refresh_calls = 0

    def _new_refresh(self, grant: dict) -> str:
        token = f"idp-rt-{os.urandom(12).hex()}"
        self.live_refresh[token] = grant
        self.issued_refresh.append(token)
        return token

    def fetch_json(self, url, form=None, headers=None):
        if url == f"{self.issuer}/protocol/openid-connect/token" and form and form.get("grant_type") == "refresh_token":
            self.requests.append(url)
            self.refresh_calls += 1
            if self.down:
                raise IdentityError("fake IdP: connection refused", error="server_error")
            grant = self.live_refresh.pop(form["refresh_token"], None)
            if grant is None or grant["claims"]["sub"] in self.disabled:
                raise IdentityError("fake IdP: HTTP 400", error="server_error", status=400, oauth_error="invalid_grant")
            grant = {**grant, "claims": {**grant["claims"], **self.user_claims.get(grant["claims"]["sub"], {})}}
            body = {"access_token": "upstream-at-2", "token_type": "Bearer", "refresh_token": self._new_refresh(grant)}
            if self.id_token_on_refresh:
                body["id_token"] = self.make_id_token(grant)
            return body
        if url == f"{self.issuer}/protocol/openid-connect/token":
            code_grant = self.grants.get(form["code"])
            body = super().fetch_json(url, form, headers)
            if self.issue_refresh_tokens and code_grant is not None:
                body["refresh_token"] = self._new_refresh(code_grant)
            return body
        if url == f"{self.issuer}/.well-known/openid-configuration":
            doc = super().fetch_json(url, form, headers)
            doc["userinfo_endpoint"] = f"{self.issuer}/protocol/openid-connect/userinfo"
            return doc
        if url == f"{self.issuer}/protocol/openid-connect/userinfo":
            self.requests.append(url)
            assert (headers or {}).get("Authorization") == "Bearer upstream-at-2"
            grant = next(iter(self.live_refresh.values()))
            return {k: v for k, v in grant["claims"].items()}
        return super().fetch_json(url, form, headers)


def make_recheck_provider(fake, storage_path=None, keys=(KEY_A,), **idp_kwargs) -> OAuthProvider:
    idp = IdentityProvider(
        issuer=fake.issuer, client_id=fake.client_id, client_secret=fake.client_secret,
        recheck_on_refresh=True, token_keys=list(keys), **idp_kwargs,
    )
    idp.fetch_json = fake.fetch_json
    return OAuthProvider(
        base_url=BASE,
        clients={"test-client": "test-secret"},
        client_redirect_uris={"test-client": [CLIENT_REDIRECT]},
        identity_provider=idp,
        storage_path=storage_path,
    )


@pytest.fixture
def idp():
    return RefreshingIdP()


# --- Configuration ---

def test_recheck_needs_a_key():
    with pytest.raises(ValueError, match="token_keys or token_key_files"):
        IdentityProvider(issuer=ISSUER, client_id="origo", recheck_on_refresh=True)


def test_key_files_accept_raw_hex_and_base64(tmp_path):
    import base64
    encodings = [KEY_A, KEY_A.hex().encode() + b"\n", base64.b64encode(KEY_A), base64.urlsafe_b64encode(KEY_A).rstrip(b"=")]
    for i, raw in enumerate(encodings):
        path = tmp_path / f"k{i}"
        path.write_bytes(raw)
        sealer = TokenSealer.from_files([str(path)])
        assert TokenSealer([KEY_A]).open(sealer.seal("x", "here"), "here") == "x"
    bad = tmp_path / "short"
    bad.write_bytes(b"too short")
    with pytest.raises(ValueError, match="32-byte"):
        TokenSealer.from_files([str(bad)])


def test_sealer_binds_value_to_place_and_rotates_keys():
    old = TokenSealer([KEY_A])
    sealed = old.seal("secret-value", "family:f1")
    assert "secret-value" not in sealed
    assert old.open(sealed, "family:f2") is None  # copied to another grant: doesn't open
    assert old.open(sealed[:-2] + "AA", "family:f1") is None  # tampered
    rotated = TokenSealer([KEY_B, KEY_A])
    assert rotated.open(sealed, "family:f1") == "secret-value"  # old key still opens
    assert TokenSealer([KEY_A]).open(rotated.seal("v", "p"), "p") is None  # new values use KEY_B
    assert TokenSealer([KEY_B]).open(sealed, "family:f1") is None  # old key dropped


# --- Refresh re-checks the IdP ---

async def test_refresh_rotates_and_keeps_the_idp_token(idp, http):
    provider = make_recheck_provider(idp)
    client = await http(provider)
    tokens = await full_sign_in(client, idp)
    for _ in range(3):
        # The fake spends each IdP token on use: a second refresh only
        # succeeds if origo stored the rotated one.
        resp = await _refresh(client, tokens["refresh_token"])
        assert resp.status_code == 200, resp.text
        tokens = resp.json()
    assert idp.refresh_calls == 3
    assert provider.verify_token(tokens["access_token"])["sub"] == f"{ISSUER}|user-1"


async def test_fresh_claims_reach_the_grant(idp, http):
    provider = make_recheck_provider(idp)
    client = await http(provider)
    tokens = await full_sign_in(client, idp)
    idp.user_claims["user-1"] = {"name": "Ada King", "groups": ["/staff", "/leads"]}
    resp = await _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 200, resp.text
    meta = provider.verify_token(resp.json()["access_token"])
    assert meta["name"] == "Ada King"
    assert meta["groups"] == ["/staff", "/leads"]


async def test_disabled_person_is_refused_and_the_grant_revoked(idp, http):
    provider = make_recheck_provider(idp)
    client = await http(provider)
    tokens = await full_sign_in(client, idp)
    assert provider.verify_token(tokens["access_token"]) is not None
    idp.disabled.add("user-1")
    resp = await _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_grant"
    # Ended server-side: the live access token is gone too, and the client's
    # refresh token can't be used again.
    assert provider.verify_token(tokens["access_token"]) is None
    idp.disabled.clear()
    assert (await _refresh(client, tokens["refresh_token"])).status_code == 401


async def test_group_removed_at_the_idp_is_refused(idp, http):
    provider = make_recheck_provider(idp, allowed_groups=["/staff"])
    client = await http(provider)
    tokens = await full_sign_in(client, idp)
    idp.user_claims["user-1"] = {"groups": ["/former"]}
    resp = await _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 401
    assert provider.verify_token(tokens["access_token"]) is None


async def test_idp_outage_is_retryable_and_keeps_the_grant(idp, http):
    provider = make_recheck_provider(idp)
    client = await http(provider)
    tokens = await full_sign_in(client, idp)
    idp.down = True
    resp = await _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 503
    assert resp.json()["error"] == "temporarily_unavailable"
    assert provider.verify_token(tokens["access_token"]) is not None
    idp.down = False
    # The same refresh token still works: it was not rotated by the failure.
    resp = await _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 200, resp.text


async def test_userinfo_fallback_without_a_refreshed_id_token(idp, http):
    idp.id_token_on_refresh = False
    provider = make_recheck_provider(idp)
    client = await http(provider)
    tokens = await full_sign_in(client, idp)
    resp = await _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 200, resp.text
    assert f"{ISSUER}/protocol/openid-connect/userinfo" in idp.requests


async def test_another_subject_from_the_idp_ends_the_grant(idp, http):
    provider = make_recheck_provider(idp)
    client = await http(provider)
    tokens = await full_sign_in(client, idp)
    idp.user_claims["user-1"] = {"sub": "user-2"}
    resp = await _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 401
    assert provider.verify_token(tokens["access_token"]) is None


async def test_max_grant_age_still_caps_the_grant(idp, http, monkeypatch):
    provider = make_recheck_provider(idp, max_grant_age=3600)
    client = await http(provider)
    tokens = await full_sign_in(client, idp)
    real_time = time.time
    monkeypatch.setattr("origo.endpoints.time.time", lambda: real_time() + 3601)
    resp = await _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 401
    assert idp.refresh_calls == 0


async def test_sign_in_without_an_idp_refresh_token_fails_closed(idp, http):
    idp.issue_refresh_tokens = False
    client = await http(make_recheck_provider(idp))
    cb, _ = await sign_in(client, idp)
    params = client_redirect_params(cb)
    assert "code" not in params and params["error"] == "server_error"


# --- At rest, and upgrades ---

async def test_the_idp_token_is_sealed_at_rest(idp, http, tmp_path):
    db = tmp_path / "origo.db"
    provider = make_recheck_provider(idp, storage_path=str(db))
    client = await http(provider)
    tokens = await full_sign_in(client, idp)
    resp = await _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 200
    rows = sqlite3.connect(db).execute("SELECT key, sealed FROM idp_tokens").fetchall()
    assert len(rows) == 1 and rows[0][0].startswith("family:")
    raw = db.read_bytes() + (tmp_path / "origo.db-wal").read_bytes() if (tmp_path / "origo.db-wal").exists() else db.read_bytes()
    for issued in idp.issued_refresh:
        assert issued not in rows[0][1]
        assert issued.encode() not in raw
    assert TokenSealer([KEY_A]).open(rows[0][1], rows[0][0]) == idp.issued_refresh[-1]


async def test_grants_from_before_recheck_need_one_sign_in(idp, http, tmp_path):
    db = str(tmp_path / "origo.db")
    before = IdentityProvider(issuer=idp.issuer, client_id=idp.client_id, client_secret=idp.client_secret)
    before.fetch_json = idp.fetch_json
    old_provider = OAuthProvider(
        base_url=BASE, clients={"test-client": "test-secret"},
        client_redirect_uris={"test-client": [CLIENT_REDIRECT]}, identity_provider=before, storage_path=db,
    )
    old_tokens = await full_sign_in(await http(old_provider), idp)
    old_provider.storage.close()

    provider = make_recheck_provider(idp, storage_path=db)
    client = await http(provider)
    resp = await _refresh(client, old_tokens["refresh_token"])
    assert resp.status_code == 401
    assert provider.verify_token(old_tokens["access_token"]) is None
    # One sign-in, and refreshes work again.
    tokens = await full_sign_in(client, idp)
    assert (await _refresh(client, tokens["refresh_token"])).status_code == 200


async def test_key_rotation_keeps_people_signed_in(idp, http, tmp_path):
    db = str(tmp_path / "origo.db")
    provider = make_recheck_provider(idp, storage_path=db, keys=(KEY_A,))
    tokens = await full_sign_in(await http(provider), idp)
    provider.storage.close()

    rotated = make_recheck_provider(idp, storage_path=db, keys=(KEY_B, KEY_A))
    client = await http(rotated)
    resp = await _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 200, resp.text
    rotated.storage.close()

    # Re-sealed under KEY_B on that refresh, so KEY_A can now be dropped.
    only_new = make_recheck_provider(idp, storage_path=db, keys=(KEY_B,))
    client = await http(only_new)
    assert (await _refresh(client, resp.json()["refresh_token"])).status_code == 200


async def test_fresh_extra_claims_replace_the_stored_ones(idp, http):
    provider = make_recheck_provider(idp, extra_claims=["kajo_organizations", "resource_access.kajo.roles"])
    client = await http(provider)
    orgs = {"acme": {"id": "0b6e1c1e-4b7a-4f7e-9d43-2a1f0c1d2e3f"}}
    tokens = await full_sign_in(client, idp, kajo_organizations=orgs, resource_access={"kajo": {"roles": ["activate"]}})
    assert provider.verify_token(tokens["access_token"])["idp_claims"]["resource_access"] == {"kajo": {"roles": ["activate"]}}
    # The role and one organization are taken away at the IdP.
    idp.user_claims["user-1"] = {"kajo_organizations": {}, "resource_access": {"kajo": {"roles": []}}}
    resp = await _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 200, resp.text
    assert provider.verify_token(resp.json()["access_token"])["idp_claims"] == {
        "kajo_organizations": {},
        "resource_access": {"kajo": {"roles": []}},
    }
    # Gone from the id_token altogether (the fake leaves out None claims):
    # the stored copy goes too, nothing stale stays.
    idp.user_claims["user-1"] = {"kajo_organizations": None, "resource_access": None}
    resp = await _refresh(client, resp.json()["refresh_token"])
    assert resp.status_code == 200, resp.text
    assert "idp_claims" not in provider.verify_token(resp.json()["access_token"])
