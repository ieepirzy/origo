"""Managed sign-in: the ID-JAG jwt-bearer grant (origo/idjag.py).

FakeIssuer plays claude.ai's Claude-issued identity (discovery + JWKS, ES256
assertions); FakeKeycloak plays the realm (client-credentials token, admin
user search and groups). Both replace fetch_json, so nothing touches the
network. claude.ai's client metadata document is the real one's shape.
Every refusal test is built to pass on the happy path except for the one
thing it changes.
"""

import base64
import json
import secrets
import time

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from urllib.parse import parse_qs, urlparse

from httpx import ASGITransport, AsyncClient

from origo import IdentityError, IdentityProvider, ManagedSignIn, OAuthProvider

BASE = "https://testserver"
KC_ISSUER = "https://auth.example/realms/staff"
JAG_ISSUER = "https://identity.example/issuers/iss_test"
CLAUDE = "https://claude.ai/oauth/mcp-oauth-client-metadata"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
CLAUDE_CIMD = {
    "client_id": CLAUDE,
    "client_name": "Claude",
    "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
    "grant_types": ["authorization_code", "refresh_token", JWT_BEARER],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64json(obj) -> str:
    return _b64(json.dumps(obj).encode())


def _int_b64(value: int, size: int = 32) -> str:
    return _b64(value.to_bytes(size, "big"))


class FakeIssuer:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid = "jag-1"
        self.requests: list[str] = []

    def jwk(self) -> dict:
        pub = self.key.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "kid": self.kid, "use": "sig", "alg": "ES256",
                "x": _int_b64(pub.x), "y": _int_b64(pub.y)}

    def assertion(self, header=None, drop=(), key=None, **claims) -> str:
        now = int(time.time())
        body = {
            "iss": JAG_ISSUER, "sub": "claude-user-1", "aud": BASE, "client_id": CLAUDE,
            "jti": secrets.token_urlsafe(12), "iat": now, "exp": now + 300,
            "email": "ada@muutto365.fi", "scope": "mcp",
            **claims,
        }
        for name in drop:
            body.pop(name, None)
        head = {"alg": "ES256", "typ": "oauth-id-jag+jwt", "kid": self.kid, **(header or {})}
        signing_input = f"{_b64json(head)}.{_b64json(body)}".encode()
        der = (key or self.key).sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return f"{signing_input.decode()}.{_b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def fetch_json(self, url, form=None, headers=None, allow_list=False):
        self.requests.append(url)
        if url == f"{JAG_ISSUER}/.well-known/openid-configuration":
            return {"issuer": JAG_ISSUER, "jwks_uri": f"{JAG_ISSUER}/jwks.json"}
        if url == f"{JAG_ISSUER}/jwks.json":
            return {"keys": [self.jwk()]}
        raise AssertionError(f"unexpected issuer request {url}")


class FakeKeycloak:
    def __init__(self):
        self.users = [{
            "id": "kc-ada", "username": "ada", "email": "ada@muutto365.fi", "emailVerified": True,
            "enabled": True, "firstName": "Ada", "lastName": "Lovelace",
        }]
        self.groups = {"kc-ada": [{"name": "staff", "path": "/staff"}]}
        self.token_requests = 0
        self.searches: list[str] = []
        self.down = False
        self.locked: set[str] = set()

    def fetch_json(self, url, form=None, headers=None, allow_list=False):
        if self.down:
            raise IdentityError("keycloak down", error="server_error")
        if url == f"{KC_ISSUER}/.well-known/openid-configuration":
            return {"issuer": KC_ISSUER, "authorization_endpoint": f"{KC_ISSUER}/auth",
                    "token_endpoint": f"{KC_ISSUER}/token", "jwks_uri": f"{KC_ISSUER}/certs"}
        if url == f"{KC_ISSUER}/token":
            assert form["grant_type"] == "client_credentials"
            expected = base64.b64encode(b"origo:idp-secret").decode()
            assert (headers or {}).get("Authorization") == f"Basic {expected}"
            self.token_requests += 1
            return {"access_token": "kc-admin-token", "expires_in": 300}
        admin = "https://auth.example/admin/realms/staff"
        assert (headers or {}).get("Authorization") == "Bearer kc-admin-token"
        if url.startswith(f"{admin}/users?"):
            self.searches.append(url)
            assert "exact=true" in url
            # As Keycloak: the decoded search value, lowercased, exact.
            wanted = parse_qs(urlparse(url).query)["email"][0].lower()
            return [u for u in self.users if u["email"].lower() == wanted]
        if url.startswith(f"{admin}/attack-detection/brute-force/users/"):
            uid = url.rsplit("/", 1)[1]
            return {"disabled": uid in self.locked, "numFailures": 0}
        if url.startswith(f"{admin}/users/") and url.endswith("/groups"):
            return self.groups.get(url[len(f"{admin}/users/"):-len("/groups")], [])
        raise AssertionError(f"unexpected Keycloak request {url}")


@pytest.fixture
def issuer():
    return FakeIssuer()


@pytest.fixture
def keycloak():
    return FakeKeycloak()


@pytest.fixture(autouse=True)
def _claude_cimd(monkeypatch):
    def fetch(client_id, allow_private_hosts=False):
        return dict(CLAUDE_CIMD) if client_id == CLAUDE else None
    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fetch)


def make_provider(issuer, keycloak, tenant=None, idp_kwargs=None, managed=True, group_paths=False, **kwargs):
    idp = IdentityProvider(issuer=KC_ISSUER, client_id="origo", client_secret="idp-secret", **(idp_kwargs or {}))
    idp.fetch_json = keycloak.fetch_json
    msi = None
    if managed:
        msi = ManagedSignIn(issuer=JAG_ISSUER, tenant=tenant, group_paths=group_paths)
        msi.fetch_json = lambda url, form=None, headers=None, allow_list=False: (
            issuer.fetch_json(url, form, headers, allow_list) if url.startswith(JAG_ISSUER)
            else keycloak.fetch_json(url, form, headers, allow_list)
        )
    kwargs.setdefault("storage_path", None)
    kwargs.setdefault("public_registration", True)
    kwargs.setdefault("cimd_allowed_clients", ["claude.ai"])
    kwargs.setdefault("scopes_supported", ["mcp"])
    return OAuthProvider(base_url=BASE, identity_provider=idp, managed_sign_in=msi, **kwargs)


@pytest_asyncio.fixture
async def http():
    clients = []

    async def _open(provider):
        client = AsyncClient(transport=ASGITransport(app=provider.asgi_app()), base_url=BASE)
        clients.append(client)
        return client

    yield _open
    for client in clients:
        await client.aclose()


async def grant(client, assertion, **extra):
    return await client.post("/token", data={
        "grant_type": JWT_BEARER, "client_id": CLAUDE, "assertion": assertion, **extra,
    })


# --- The happy path ---

async def test_assertion_is_exchanged_for_the_keycloak_users_token(http, issuer, keycloak):
    provider = make_provider(issuer, keycloak)
    client = await http(provider)
    resp = await grant(client, issuer.assertion())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "bearer" and body["scope"] == "mcp"
    assert "refresh_token" not in body
    assert resp.headers["cache-control"] == "no-store"
    meta = provider.storage.verify_token(body["access_token"])
    # The same subject an interactive Keycloak sign-in gets: the person's data
    # is theirs however they connected.
    assert meta["claims"]["sub"] == f"{KC_ISSUER}|kc-ada"
    assert meta["claims"]["email"] == "ada@muutto365.fi"
    assert meta["claims"]["name"] == "Ada Lovelace"
    # Names, as the realm's mapper emits them (full.path false): one form only.
    assert meta["claims"]["groups"] == ["staff"]
    assert meta["client_id"] == CLAUDE


async def test_metadata_advertises_the_grant_only_when_configured(http, issuer, keycloak):
    on = await (await http(make_provider(issuer, keycloak))).get("/.well-known/oauth-authorization-server")
    assert JWT_BEARER in on.json()["grant_types_supported"]
    off = await (await http(make_provider(issuer, keycloak, managed=False))).get("/.well-known/oauth-authorization-server")
    assert JWT_BEARER not in off.json()["grant_types_supported"]


async def test_without_managed_sign_in_the_grant_is_unsupported(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak, managed=False))
    resp = await grant(client, issuer.assertion())
    assert resp.status_code == 400 and resp.json()["error"] == "unsupported_grant_type"


# --- The assertion ---

@pytest.mark.parametrize("change", [
    {"iss": "https://identity.example/issuers/iss_other"},
    {"aud": "https://other.example"},
    {"aud": [BASE, "https://other.example"]},
    {"client_id": "https://evil.example/cimd"},
    {"exp": int(time.time()) - 600},
    {"iat": int(time.time()) + 600},
    {"iat": int(time.time()) - 3600},
    {"nbf": int(time.time()) + 600},
    {"jti": ""},
    {"jti": "x" * 300},
    {"exp": "soon"},
])
async def test_a_bad_claim_is_refused(http, issuer, keycloak, change):
    client = await http(make_provider(issuer, keycloak))
    resp = await grant(client, issuer.assertion(**change))
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant", change


@pytest.mark.parametrize("missing", ["jti", "exp", "iat", "sub", "email"])
async def test_a_missing_claim_is_refused(http, issuer, keycloak, missing):
    client = await http(make_provider(issuer, keycloak))
    resp = await grant(client, issuer.assertion(drop=(missing,)))
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant", missing


@pytest.mark.parametrize("header", [
    {"typ": "JWT"},                 # an id_token from the same issuer
    {"typ": None},
    {"alg": "none"},
    {"alg": "HS256"},
    {"crit": ["exp"]},
    {"kid": "unknown"},
])
async def test_a_bad_header_is_refused(http, issuer, keycloak, header):
    client = await http(make_provider(issuer, keycloak))
    resp = await grant(client, issuer.assertion(header=header))
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant", header


async def test_hs256_signed_with_the_public_key_is_refused(http, issuer, keycloak):
    """The classic confusion attack: HMAC keyed with the issuer's public JWK."""
    client = await http(make_provider(issuer, keycloak))
    now = int(time.time())
    head = _b64json({"alg": "HS256", "typ": "oauth-id-jag+jwt", "kid": issuer.kid})
    body = _b64json({"iss": JAG_ISSUER, "sub": "x", "aud": BASE, "client_id": CLAUDE, "jti": "j",
                     "iat": now, "exp": now + 300, "email": "ada@muutto365.fi"})
    mac = crypto_hmac.HMAC(json.dumps(issuer.jwk()).encode(), hashes.SHA256())
    mac.update(f"{head}.{body}".encode())
    resp = await grant(client, f"{head}.{body}.{_b64(mac.finalize())}")
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant"


async def test_a_signature_by_another_key_is_refused(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak))
    resp = await grant(client, issuer.assertion(key=ec.generate_private_key(ec.SECP256R1())))
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant"


async def test_a_tampered_payload_is_refused(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak))
    head, body, sig = issuer.assertion().split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["email"] = "boss@muutto365.fi"
    resp = await grant(client, f"{head}.{_b64json(claims)}.{sig}")
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant"


async def test_another_issuer_is_never_fetched(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak))
    await grant(client, issuer.assertion(iss="https://attacker.example"))
    assert not any("attacker" in u for u in issuer.requests)


async def test_a_replayed_assertion_is_refused(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak))
    assertion = issuer.assertion()
    assert (await grant(client, assertion)).status_code == 200
    again = await grant(client, assertion)
    assert again.status_code == 400 and again.json()["error"] == "invalid_grant"


async def test_replay_is_refused_across_a_restart(http, issuer, keycloak, tmp_path):
    path = str(tmp_path / "origo.db")
    assertion = issuer.assertion()
    first = await http(make_provider(issuer, keycloak, storage_path=path))
    assert (await grant(first, assertion)).status_code == 200
    second = await http(make_provider(issuer, keycloak, storage_path=path))
    assert (await grant(second, assertion)).status_code == 400


async def test_the_tenant_is_checked_when_configured(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak, tenant="muutto365"))
    assert (await grant(client, issuer.assertion(aud_tenant="other"))).status_code == 400
    assert (await grant(client, issuer.assertion())).status_code == 400
    assert (await grant(client, issuer.assertion(aud_tenant="muutto365"))).status_code == 200


# --- The client ---

async def test_only_an_allowlisted_cimd_client_may_present_assertions(http, issuer, keycloak):
    provider = make_provider(issuer, keycloak, clients={"seeded": "s3cret"})
    client = await http(provider)
    seeded = await client.post("/token", data={
        "grant_type": JWT_BEARER, "client_id": "seeded", "client_secret": "s3cret",
        "assertion": issuer.assertion(client_id="seeded"),
    })
    assert seeded.status_code == 401
    other = "https://evil.example/cimd"
    resp = await client.post("/token", data={
        "grant_type": JWT_BEARER, "client_id": other, "assertion": issuer.assertion(client_id=other),
    })
    assert resp.status_code == 401


async def test_an_unlisted_cimd_client_is_refused_even_with_a_valid_document(http, issuer, keycloak, monkeypatch):
    """Only the allowlist stands in the way here: the document is well formed
    and declares the grant, and the assertion names this client."""
    other = "https://evil.example/cimd"

    def fetch(client_id, allow_private_hosts=False):
        return {**CLAUDE_CIMD, "client_id": client_id}
    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fetch)
    client = await http(make_provider(issuer, keycloak))
    resp = await client.post("/token", data={
        "grant_type": JWT_BEARER, "client_id": other, "assertion": issuer.assertion(client_id=other),
    })
    assert resp.status_code == 401 and resp.json()["error"] == "unauthorized_client"


async def test_a_client_that_does_not_declare_the_grant_is_refused(http, issuer, keycloak, monkeypatch):
    def fetch(client_id, allow_private_hosts=False):
        return {**CLAUDE_CIMD, "grant_types": ["authorization_code", "refresh_token"]}
    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fetch)
    client = await http(make_provider(issuer, keycloak))
    resp = await grant(client, issuer.assertion())
    assert resp.status_code == 401 and resp.json()["error"] == "unauthorized_client"


def test_construction_requires_an_identity_provider_and_an_allowlist(issuer, keycloak):
    with pytest.raises(ValueError, match="identity_provider"):
        OAuthProvider(base_url=BASE, storage_path=None, managed_sign_in=ManagedSignIn(issuer=JAG_ISSUER),
                      cimd_allowed_clients=["claude.ai"])
    with pytest.raises(ValueError, match="cimd_allowed_clients"):
        make_provider(issuer, keycloak, public_registration=False, cimd_allowed_clients=None)
    with pytest.raises(ValueError):
        ManagedSignIn(issuer="http://identity.example/issuers/x")


# --- The person ---

@pytest.mark.parametrize("user_change", [
    {"enabled": False},
    {"emailVerified": False},
    {"email": "someone.else@muutto365.fi"},
])
async def test_no_eligible_keycloak_user_means_no_token(http, issuer, keycloak, user_change):
    keycloak.users[0].update(user_change)
    client = await http(make_provider(issuer, keycloak))
    resp = await grant(client, issuer.assertion())
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant", user_change


async def test_two_keycloak_users_with_the_email_is_ambiguous_and_refused(http, issuer, keycloak):
    keycloak.users.append({**keycloak.users[0], "id": "kc-ada-2"})
    client = await http(make_provider(issuer, keycloak))
    assert (await grant(client, issuer.assertion())).status_code == 400


async def test_the_allow_gate_applies(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak, idp_kwargs={"allowed_groups": ["admins"]}))
    assert (await grant(client, issuer.assertion())).status_code == 400
    keycloak.groups["kc-ada"].append({"name": "admins", "path": "/admins"})
    assert (await grant(client, issuer.assertion())).status_code == 200


async def test_the_domain_gate_applies(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak, idp_kwargs={"allowed_email_domains": ["example.org"]}))
    assert (await grant(client, issuer.assertion())).status_code == 400


async def test_keycloak_unreachable_is_retryable_not_a_refusal(http, issuer, keycloak):
    keycloak.down = True
    client = await http(make_provider(issuer, keycloak))
    resp = await grant(client, issuer.assertion())
    assert resp.status_code == 503 and resp.json()["error"] == "temporarily_unavailable"


async def test_the_admin_token_is_reused(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak))
    for _ in range(3):
        assert (await grant(client, issuer.assertion())).status_code == 200
    assert keycloak.token_requests == 1


# --- Scope and resource ---

async def test_a_requested_scope_beyond_the_assertion_is_refused(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak, scopes_supported=["mcp", "admin"]))
    resp = await grant(client, issuer.assertion(scope="mcp"), scope="mcp admin")
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_scope"


async def test_the_resource_binds_the_token(http, issuer, keycloak):
    provider = make_provider(issuer, keycloak)
    client = await http(provider)
    resp = await grant(client, issuer.assertion(resource=f"{BASE}/mcp"))
    assert resp.status_code == 200
    assert provider.storage.verify_token(resp.json()["access_token"])["resource"] == f"{BASE}/mcp"
    mismatch = await grant(client, issuer.assertion(resource=f"{BASE}/mcp"), resource="https://other.example/mcp")
    assert mismatch.status_code == 400


# --- Review findings (origo#149) ---

async def test_a_non_string_alg_is_refused_not_a_500(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak))
    head = _b64json({"alg": ["ES256"], "typ": "oauth-id-jag+jwt"})
    resp = await grant(client, f"{head}.{_b64json({'iss': JAG_ISSUER})}.AA")
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant"


@pytest.mark.parametrize("change", [
    {"iat": float("nan")}, {"exp": float("inf")}, {"exp": float("nan")},
])
async def test_non_finite_times_are_refused(http, issuer, keycloak, change):
    client = await http(make_provider(issuer, keycloak))
    resp = await grant(client, issuer.assertion(**change))
    assert resp.status_code == 400, change


async def test_the_replay_record_is_capped_but_covers_the_acceptance_window(issuer):
    msi = ManagedSignIn(issuer=JAG_ISSUER)
    now = time.time()
    _, ttl = msi.replay_key({"jti": "j", "exp": now + 10 * 365 * 86400, "iat": now})
    assert msi.max_assertion_age <= ttl <= msi.max_assertion_age + 2 * msi.clock_skew


async def test_a_sender_constrained_assertion_is_refused(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak))
    resp = await grant(client, issuer.assertion(cnf={"jkt": "abc"}))
    assert resp.status_code == 400


@pytest.mark.parametrize("email", ["\u212aate@muutto365.fi", "ada"])
async def test_a_non_ascii_or_malformed_email_is_refused(http, issuer, keycloak, email):
    keycloak.users[0]["email"] = "kate@muutto365.fi"
    client = await http(make_provider(issuer, keycloak))
    assert (await grant(client, issuer.assertion(email=email))).status_code == 400


async def test_the_email_matches_case_insensitively_against_keycloaks_stored_form(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak))
    assert (await grant(client, issuer.assertion(email="Ada@Muutto365.fi"))).status_code == 200


async def test_a_user_with_pending_required_actions_is_refused(http, issuer, keycloak):
    keycloak.users[0]["requiredActions"] = ["CONFIGURE_TOTP"]
    client = await http(make_provider(issuer, keycloak))
    assert (await grant(client, issuer.assertion())).status_code == 400


async def test_a_brute_force_locked_user_is_refused(http, issuer, keycloak):
    keycloak.locked.add("kc-ada")
    client = await http(make_provider(issuer, keycloak))
    assert (await grant(client, issuer.assertion())).status_code == 400


async def test_an_assertion_for_another_resource_is_refused(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak))
    resp = await grant(client, issuer.assertion(resource="https://other.example/mcp"))
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant"
    target = await grant(client, issuer.assertion(), resource="https://other.example/mcp")
    assert target.status_code == 400 and target.json()["error"] == "invalid_target"


async def test_unsupported_assertion_scopes_are_dropped_not_fatal(http, issuer, keycloak):
    client = await http(make_provider(issuer, keycloak))
    resp = await grant(client, issuer.assertion(scope="mcp offline_access other:thing"))
    assert resp.status_code == 200 and resp.json()["scope"] == "mcp"


async def test_group_paths_emit_full_paths_only(http, issuer, keycloak):
    keycloak.groups["kc-ada"] = [{"name": "admins", "path": "/contractors/admins"}]
    provider = make_provider(issuer, keycloak, group_paths=True, idp_kwargs={"allowed_groups": ["admins"]})
    client = await http(provider)
    # The bare name is not granted where the realm emits full paths.
    assert (await grant(client, issuer.assertion())).status_code == 400


async def test_a_stale_stored_client_record_is_refreshed_from_its_document(http, issuer, keycloak, monkeypatch):
    """A claude.ai record persisted before its document declared jwt-bearer
    is re-fetched once, not refused until the record expires."""
    provider = make_provider(issuer, keycloak)
    old = {**CLAUDE_CIMD, "grant_types": ["authorization_code", "refresh_token"]}
    provider.storage.register_client(CLAUDE, None, old["redirect_uris"], "none", old)
    fetches = []

    def fetch(client_id, allow_private_hosts=False):
        fetches.append(client_id)
        return dict(CLAUDE_CIMD)
    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fetch)
    client = await http(provider)
    assert (await grant(client, issuer.assertion())).status_code == 200
    assert fetches == [CLAUDE]
    assert (await grant(client, issuer.assertion())).status_code == 200
    assert fetches == [CLAUDE]  # fresh record now: no second fetch
