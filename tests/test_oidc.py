"""Upstream OIDC sign-in (#130): /authorize -> IdP -> /authorize/callback -> code.

Every test runs against FakeIdP, an in-process OpenID provider that replaces
IdentityProvider.fetch_json — the single seam through which origo talks to an
IdP — so nothing here touches the network. FakeIdP plays both halves of the
upstream: the person signing in (FakeIdP.sign_in, given the authorization URL
origo redirected to) and the IdP's discovery/JWKS/token endpoints. Its token
endpoint enforces the upstream PKCE verifier, so a flow that passes proves
origo sent the right one.
"""

import base64
import hashlib
import json
import logging
import secrets
import sqlite3
import time
from urllib.parse import parse_qs, urlparse

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from httpx import ASGITransport, AsyncClient

from origo import IdentityError, IdentityProvider, OAuthProvider
from tests.conftest import make_pkce_pair

ISSUER = "https://idp.example/realms/staff"
BASE = "https://testserver"
CLIENT_REDIRECT = "https://client.example/cb"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64json(obj) -> str:
    return _b64(json.dumps(obj).encode())


def _int_b64(value: int) -> str:
    return _b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class FakeIdP:
    def __init__(self, issuer=ISSUER, client_id="origo", client_secret="idp-secret"):
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "k1"
        self.extra_keys: list[dict] = []
        self.grants: dict[str, dict] = {}
        self.requests: list[str] = []
        self.discovery_issuer = issuer
        # Per-test tampering of the next id_token.
        self.claim_overrides: dict = {}
        self.header_overrides: dict = {}
        self.sign_with = None  # alternative RSA key
        self.raw_id_token = None  # exact token string to return

    def jwk(self) -> dict:
        pub = self.key.public_key().public_numbers()
        return {"kty": "RSA", "kid": self.kid, "use": "sig", "alg": "RS256", "n": _int_b64(pub.n), "e": _int_b64(pub.e)}

    def sign_in(self, authorization_url: str, **claims) -> dict:
        """The person signs in at the IdP; returns the callback query params."""
        parsed = urlparse(authorization_url)
        assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == f"{self.issuer}/protocol/openid-connect/auth"
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        assert q["response_type"] == "code"
        assert q["client_id"] == self.client_id
        assert q["code_challenge_method"] == "S256"
        assert "openid" in q["scope"].split()
        code = secrets.token_urlsafe(16)
        self.grants[code] = {
            "redirect_uri": q["redirect_uri"],
            "nonce": q["nonce"],
            "code_challenge": q["code_challenge"],
            "claims": {
                "sub": "user-1",
                "email": "ada@muutto365.fi",
                "email_verified": True,
                "name": "Ada Lovelace",
                "groups": ["/staff"],
                **claims,
            },
        }
        return {"code": code, "state": q["state"]}

    def make_id_token(self, grant: dict) -> str:
        if self.raw_id_token is not None:
            return self.raw_id_token
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": self.client_id,
            "azp": self.client_id,
            "iat": now,
            "exp": now + 300,
            "nonce": grant["nonce"],
            **grant["claims"],
            **self.claim_overrides,
        }
        claims = {k: v for k, v in claims.items() if v is not None}
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid, **self.header_overrides}
        signing_input = f"{_b64json(header)}.{_b64json(claims)}".encode()
        key = self.sign_with or self.key
        signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input.decode()}.{_b64(signature)}"

    def fetch_json(self, url, form=None, headers=None):
        self.requests.append(url)
        if url == f"{self.issuer}/.well-known/openid-configuration":
            return {
                "issuer": self.discovery_issuer,
                "authorization_endpoint": f"{self.issuer}/protocol/openid-connect/auth",
                "token_endpoint": f"{self.issuer}/protocol/openid-connect/token",
                "jwks_uri": f"{self.issuer}/protocol/openid-connect/certs",
            }
        if url == f"{self.issuer}/protocol/openid-connect/certs":
            # An encryption key with the same kty first, as Keycloak publishes.
            enc = {**self.jwk(), "kid": "enc", "use": "enc"}
            return {"keys": [enc, self.jwk(), *self.extra_keys]}
        if url == f"{self.issuer}/protocol/openid-connect/token":
            auth = (headers or {}).get("Authorization", "")
            expected = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
            if auth != f"Basic {expected}":
                raise IdentityError("fake IdP: bad client auth", error="server_error")
            grant = self.grants.pop(form["code"], None)
            if grant is None or form["redirect_uri"] != grant["redirect_uri"]:
                raise IdentityError("fake IdP: invalid_grant", error="server_error")
            digest = hashlib.sha256(form["code_verifier"].encode()).digest()
            if _b64(digest) != grant["code_challenge"]:
                raise IdentityError("fake IdP: PKCE mismatch", error="server_error")
            return {"access_token": "upstream-at", "token_type": "Bearer", "id_token": self.make_id_token(grant)}
        raise AssertionError(f"unexpected IdP request {url}")


def make_idp(fake: FakeIdP, **kwargs) -> IdentityProvider:
    idp = IdentityProvider(issuer=fake.issuer, client_id=fake.client_id, client_secret=fake.client_secret, **kwargs)
    idp.fetch_json = fake.fetch_json
    return idp


def make_provider(fake: FakeIdP, idp_kwargs=None, **kwargs) -> OAuthProvider:
    kwargs.setdefault("storage_path", None)
    return OAuthProvider(
        base_url=BASE,
        clients={"test-client": "test-secret"},
        client_redirect_uris={"test-client": [CLIENT_REDIRECT]},
        identity_provider=make_idp(fake, **(idp_kwargs or {})),
        **kwargs,
    )


@pytest.fixture(autouse=True)
def _no_consent_opt_in(monkeypatch):
    # Upstream sign-in must not lean on the suite-wide consent opt-in.
    monkeypatch.delenv("ORIGO_ALLOW_UNAUTHENTICATED_CONSENT", raising=False)


@pytest.fixture
def fake():
    return FakeIdP()


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


async def start(client, scope="openid email profile groups", state="client-state"):
    verifier, challenge = make_pkce_pair()
    resp = await client.get("/authorize", params={
        "response_type": "code",
        "client_id": "test-client",
        "redirect_uri": CLIENT_REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "scope": scope,
    })
    return resp, verifier


async def sign_in(client, fake, **claims):
    """Drive /authorize -> IdP -> callback; return (callback response, verifier)."""
    resp, verifier = await start(client)
    assert resp.status_code == 302, resp.text
    callback_params = fake.sign_in(resp.headers["location"], **claims)
    cb = await client.get("/authorize/callback", params=callback_params)
    return cb, verifier


def client_redirect_params(resp) -> dict:
    assert resp.status_code == 302, resp.text
    loc = resp.headers["location"]
    assert loc.startswith(CLIENT_REDIRECT), loc
    return {k: v[0] for k, v in parse_qs(urlparse(loc).query).items()}


async def exchange(client, code, verifier):
    resp = await client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": CLIENT_REDIRECT,
    })
    assert resp.status_code == 200, resp.text
    return resp.json()


async def full_sign_in(client, fake, **claims):
    cb, verifier = await sign_in(client, fake, **claims)
    params = client_redirect_params(cb)
    assert params["state"] == "client-state"
    return await exchange(client, params["code"], verifier)


def assert_refused(cb, error="access_denied"):
    params = client_redirect_params(cb)
    assert "code" not in params
    assert params["error"] == error
    assert params["state"] == "client-state"


# --- Happy path ---

async def test_sign_in_issues_tokens_carrying_the_person(fake, http):
    provider = make_provider(fake)
    client = await http(provider)

    resp, _ = await start(client)
    assert resp.status_code == 302
    # No consent page, straight to the IdP, with a browser-binding cookie.
    assert resp.headers["location"].startswith(f"{ISSUER}/protocol/openid-connect/auth?")
    assert "__Host-origo_login" in resp.headers["set-cookie"]

    tokens = await full_sign_in(client, fake)
    meta = provider.verify_token(tokens["access_token"], resource=None)
    assert meta["sub"] == f"{ISSUER}|user-1"
    assert meta["email"] == "ada@muutto365.fi"
    assert meta["name"] == "Ada Lovelace"
    assert meta["groups"] == ["/staff"]
    assert meta["client_id"] == "test-client"
    assert meta["scope"] == "openid email profile groups"
    assert "claims" not in meta

    info = await client.get("/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert info.status_code == 200
    assert info.json() == {
        "sub": f"{ISSUER}|user-1",
        "email": "ada@muutto365.fi",
        "email_verified": True,
        "name": "Ada Lovelace",
        "groups": ["/staff"],
    }

    id_claims = json.loads(base64.urlsafe_b64decode(tokens["id_token"].split(".")[1] + "=="))
    assert id_claims["sub"] == f"{ISSUER}|user-1"
    assert id_claims["email"] == "ada@muutto365.fi"


async def test_two_people_get_different_subjects(fake, http):
    provider = make_provider(fake)
    client = await http(provider)
    a = await full_sign_in(client, fake, sub="user-a", email="a@muutto365.fi")
    b = await full_sign_in(client, fake, sub="user-b", email="b@muutto365.fi")
    assert provider.verify_token(a["access_token"])["sub"] == f"{ISSUER}|user-a"
    assert provider.verify_token(b["access_token"])["sub"] == f"{ISSUER}|user-b"


async def test_fastmcp_adapter_exposes_claims(fake, http):
    pytest.importorskip("fastmcp")
    from origo.fastmcp_auth import OrigoTokenVerifier

    provider = make_provider(fake)
    client = await http(provider)
    tokens = await full_sign_in(client, fake)
    # The flow carried no resource, which the verifier's resource check accepts.
    access = await OrigoTokenVerifier(provider).verify_token(tokens["access_token"])
    assert access.claims["sub"] == f"{ISSUER}|user-1"
    assert access.claims["email"] == "ada@muutto365.fi"


# --- id_token verification ---

async def test_bad_signature_is_refused(fake, http):
    fake.sign_with = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = await http(make_provider(fake))
    cb, _ = await sign_in(client, fake)
    assert_refused(cb)


async def test_wrong_audience_is_refused(fake, http):
    fake.claim_overrides = {"aud": "some-other-client", "azp": None}
    client = await http(make_provider(fake))
    cb, _ = await sign_in(client, fake)
    assert_refused(cb)


async def test_multiple_audiences_require_azp(fake, http):
    fake.claim_overrides = {"aud": ["origo", "other"], "azp": "other"}
    client = await http(make_provider(fake))
    cb, _ = await sign_in(client, fake)
    assert_refused(cb)


async def test_wrong_issuer_is_refused(fake, http):
    fake.claim_overrides = {"iss": "https://idp.example/realms/other"}
    client = await http(make_provider(fake))
    cb, _ = await sign_in(client, fake)
    assert_refused(cb)


async def test_expired_id_token_is_refused(fake, http):
    fake.claim_overrides = {"exp": int(time.time()) - 3600}
    client = await http(make_provider(fake))
    cb, _ = await sign_in(client, fake)
    assert_refused(cb)


async def test_nonce_mismatch_is_refused(fake, http):
    fake.claim_overrides = {"nonce": "not-the-nonce-origo-sent"}
    client = await http(make_provider(fake))
    cb, _ = await sign_in(client, fake)
    assert_refused(cb)


async def test_missing_nonce_is_refused(fake, http):
    fake.claim_overrides = {"nonce": None}
    client = await http(make_provider(fake))
    cb, _ = await sign_in(client, fake)
    assert_refused(cb)


@pytest.mark.parametrize("alg", ["none", "HS256"])
async def test_symmetric_and_none_algorithms_are_refused(fake, http, alg):
    fake.header_overrides = {"alg": alg}
    client = await http(make_provider(fake))
    cb, _ = await sign_in(client, fake)
    assert_refused(cb)


async def test_hs256_signed_with_public_key_is_refused(fake, http):
    """The classic confusion attack: HMAC keyed with the IdP's public key."""
    import hmac as _hmac

    client = await http(make_provider(fake))
    resp, _ = await start(client)
    params = fake.sign_in(resp.headers["location"])
    grant = fake.grants[params["code"]]
    claims = {"iss": ISSUER, "aud": "origo", "exp": int(time.time()) + 300, "nonce": grant["nonce"], "sub": "attacker"}
    signing_input = f"{_b64json({'alg': 'HS256', 'kid': 'k1'})}.{_b64json(claims)}"
    sig = _hmac.new(json.dumps(fake.jwk()).encode(), signing_input.encode(), hashlib.sha256).digest()
    fake.raw_id_token = f"{signing_input}.{_b64(sig)}"
    cb = await client.get("/authorize/callback", params=params)
    assert_refused(cb)


async def test_es256_id_token_verifies(fake, http):
    ec_key = ec.generate_private_key(ec.SECP256R1())
    nums = ec_key.public_key().public_numbers()
    fake.extra_keys = [{"kty": "EC", "kid": "ec1", "use": "sig", "crv": "P-256",
                        "x": _b64(nums.x.to_bytes(32, "big")), "y": _b64(nums.y.to_bytes(32, "big"))}]
    client = await http(make_provider(fake))
    resp, verifier = await start(client)
    params = fake.sign_in(resp.headers["location"])
    grant = fake.grants[params["code"]]
    claims = {"iss": ISSUER, "aud": "origo", "exp": int(time.time()) + 300, "nonce": grant["nonce"], "sub": "ec-user"}
    signing_input = f"{_b64json({'alg': 'ES256', 'kid': 'ec1'})}.{_b64json(claims)}"
    r, s = decode_dss_signature(ec_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    fake.raw_id_token = f"{signing_input}.{_b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
    cb = await client.get("/authorize/callback", params=params)
    code = client_redirect_params(cb)["code"]
    tokens = await exchange(client, code, verifier)
    assert tokens["access_token"]


async def test_rotated_signing_key_is_refetched(fake, http):
    provider = make_provider(fake)
    client = await http(provider)
    await full_sign_in(client, fake)
    # The IdP rotates its key; the cached JWKS doesn't know the new kid.
    fake.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake.kid = "k2"
    provider.identity_provider._jwks_fetched_at = 0  # past the refetch rate limit
    await full_sign_in(client, fake)


async def test_discovery_issuer_mismatch_fails_safely(fake, http):
    fake.discovery_issuer = "https://evil.example/realms/staff"
    client = await http(make_provider(fake))
    resp, _ = await start(client)
    assert_refused(resp, error="temporarily_unavailable")


# --- Gate and email ---

async def test_email_domain_gate_refuses_other_domains(fake, http):
    client = await http(make_provider(fake, idp_kwargs={"allowed_email_domains": ["muutto365.fi"]}))
    cb, _ = await sign_in(client, fake, email="mallory@evilmuutto365.fi")
    assert_refused(cb)
    cb, _ = await sign_in(client, fake, email="mallory@sub.muutto365.fi")
    assert_refused(cb)
    assert "code" in client_redirect_params((await sign_in(client, fake))[0])


async def test_group_gate(fake, http):
    client = await http(make_provider(fake, idp_kwargs={"allowed_groups": ["/staff", "/contractors"]}))
    cb, _ = await sign_in(client, fake, groups=["/customers"])
    assert_refused(cb)
    cb, _ = await sign_in(client, fake, groups=None)
    assert_refused(cb)
    cb, _ = await sign_in(client, fake, groups=["/customers", "/contractors"])
    assert "code" in client_redirect_params(cb)


async def test_groups_claim_dotted_path(fake, http):
    provider = make_provider(fake, idp_kwargs={"groups_claim": "realm_access.roles", "allowed_groups": ["mcp-user"]})
    client = await http(provider)
    tokens = await full_sign_in(client, fake, groups=None, realm_access={"roles": ["mcp-user"]})
    assert provider.verify_token(tokens["access_token"])["groups"] == ["mcp-user"]


async def test_unverified_email_fails_domain_gate(fake, http):
    client = await http(make_provider(fake, idp_kwargs={"allowed_email_domains": ["muutto365.fi"]}))
    cb, _ = await sign_in(client, fake, email_verified=False)
    assert_refused(cb)
    # A string "true" is not the boolean the spec requires.
    cb, _ = await sign_in(client, fake, email_verified="true")
    assert_refused(cb)


async def test_unverified_email_is_never_a_claim(fake, http):
    provider = make_provider(fake)  # no gate: the person gets in, the email doesn't
    client = await http(provider)
    tokens = await full_sign_in(client, fake, email_verified=False)
    meta = provider.verify_token(tokens["access_token"])
    assert meta["sub"] == f"{ISSUER}|user-1"
    assert "email" not in meta
    info = await client.get("/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert "email" not in info.json()


# --- Callback hardening ---

async def test_callback_requires_the_starting_browser(fake, http):
    provider = make_provider(fake)
    client = await http(provider)
    resp, _ = await start(client)
    params = fake.sign_in(resp.headers["location"])
    other_browser = await http(provider)
    cb = await other_browser.get("/authorize/callback", params=params)
    assert cb.status_code == 400
    assert "location" not in cb.headers
    # ...and the sign-in is spent, not left for a retry.
    cb = await client.get("/authorize/callback", params=params)
    assert cb.status_code == 400


async def test_callback_state_is_single_use(fake, http):
    client = await http(make_provider(fake))
    resp, _ = await start(client)
    params = fake.sign_in(resp.headers["location"])
    assert (await client.get("/authorize/callback", params=params)).status_code == 302
    assert (await client.get("/authorize/callback", params=params)).status_code == 400


async def test_unknown_state_is_rejected(fake, http):
    client = await http(make_provider(fake))
    cb = await client.get("/authorize/callback", params={"state": "made-up", "code": "x"})
    assert cb.status_code == 400


async def test_idp_error_is_relayed_as_access_denied(fake, http):
    client = await http(make_provider(fake))
    resp, _ = await start(client)
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
    cb = await client.get("/authorize/callback", params={"state": state, "error": "access_denied", "error_description": "user cancelled"})
    assert_refused(cb)


async def test_consent_post_is_refused_with_an_idp(fake, http):
    """The self-issued CSRF pair must not be a way around sign-in."""
    client = await http(make_provider(fake, auto_approve=True))
    _, challenge = make_pkce_pair()
    client.cookies.set("__Host-origo_csrf", "t", domain="testserver")
    resp = await client.post("/authorize", data={
        "response_type": "code", "client_id": "test-client", "redirect_uri": CLIENT_REDIRECT,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s",
        "csrf_token": "t", "approved": "true",
    })
    assert resp.status_code == 400
    assert "code=" not in resp.headers.get("location", "")


async def test_callback_is_404_without_an_idp(http):
    provider = OAuthProvider(base_url=BASE, clients={"c": "s"}, client_redirect_uris={"c": [CLIENT_REDIRECT]}, storage_path=None)
    client = await http(provider)
    assert (await client.get("/authorize/callback", params={"state": "x"})).status_code == 404


async def test_callback_path_is_public_through_the_middleware(fake, http):
    from starlette.applications import Starlette
    from origo import OAuthMiddleware

    provider = make_provider(fake)
    app = Starlette(routes=list(provider.asgi_app().routes))
    for key, value in vars(provider.asgi_app().state)["_state"].items():
        setattr(app.state, key, value)
    app.add_middleware(OAuthMiddleware, provider=provider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE) as client:
        resp, _ = await start(client)
        params = fake.sign_in(resp.headers["location"])
        cb = await client.get("/authorize/callback", params=params)
        assert "code" in client_redirect_params(cb)


# --- Refresh keeps the person ---

@pytest.mark.parametrize("persistent", [False, True])
async def test_refresh_rotation_keeps_claims(fake, http, tmp_path, persistent):
    provider = make_provider(fake, storage_path=str(tmp_path / "o.db") if persistent else None)
    client = await http(provider)
    tokens = await full_sign_in(client, fake)
    for _ in range(3):
        resp = await client.post("/token", data={
            "grant_type": "refresh_token", "client_id": "test-client", "client_secret": "test-secret",
            "refresh_token": tokens["refresh_token"],
        })
        assert resp.status_code == 200, resp.text
        tokens = resp.json()
        meta = provider.verify_token(tokens["access_token"])
        assert meta["sub"] == f"{ISSUER}|user-1"
        assert meta["email"] == "ada@muutto365.fi"
        assert meta["groups"] == ["/staff"]
        id_claims = json.loads(base64.urlsafe_b64decode(tokens["id_token"].split(".")[1] + "=="))
        assert id_claims["sub"] == f"{ISSUER}|user-1"
    # Rotation never went back to the IdP.
    assert sum(u.endswith("/token") for u in fake.requests) == 1


async def test_pending_login_survives_across_processes_sharing_storage(fake, http, tmp_path):
    """The IdP's callback may land on another worker sharing the SQLite file."""
    path = str(tmp_path / "o.db")
    first = await http(make_provider(fake, storage_path=path))
    resp, verifier = await start(first)
    params = fake.sign_in(resp.headers["location"])
    second = await http(make_provider(fake, storage_path=path))
    second.cookies = first.cookies
    cb = await second.get("/authorize/callback", params=params)
    code = client_redirect_params(cb)["code"]
    assert (await exchange(second, code, verifier))["access_token"]


async def test_tokens_from_before_the_idp_stop_working(fake, http, tmp_path, monkeypatch):
    """Upgrade path: approve-only tokens persisted before an IdP was configured
    name no person, and must not keep working beside per-user ones."""
    from tests.conftest import do_full_flow

    path = str(tmp_path / "o.db")
    legacy = OAuthProvider(base_url=BASE, clients={"test-client": "test-secret"},
                           client_redirect_uris={"test-client": ["https://example.com/cb"]},
                           auto_approve=True, allow_unauthenticated_consent=True, storage_path=path)
    async with AsyncClient(transport=ASGITransport(app=legacy.asgi_app()), base_url=BASE) as c:
        access = await do_full_flow(c, legacy, "test-client", "test-secret")
    assert legacy.verify_token(access) is not None
    assert "sub" not in legacy.verify_token(access)  # the static subject is nobody

    upgraded = make_provider(fake, storage_path=path)
    assert upgraded.verify_token(access) is None
    client = await http(upgraded)
    info = await client.get("/userinfo", headers={"Authorization": f"Bearer {access}"})
    assert info.status_code == 401


async def test_sqlite_schema_from_older_origo_is_migrated(fake, http, tmp_path):
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE clients (client_id TEXT PRIMARY KEY, secret_hash TEXT, redirect_uris TEXT NOT NULL,
            token_endpoint_auth_method TEXT NOT NULL, client_metadata TEXT NOT NULL, registered_at REAL NOT NULL);
        CREATE TABLE codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
            code_challenge TEXT NOT NULL, code_challenge_method TEXT NOT NULL, resource TEXT, scope TEXT NOT NULL,
            expires_at REAL NOT NULL);
        CREATE TABLE tokens (token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, resource TEXT, scope TEXT NOT NULL,
            expires_at REAL NOT NULL, family TEXT);
        CREATE TABLE refresh_tokens (token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, resource TEXT,
            scope TEXT NOT NULL, expires_at REAL NOT NULL, family TEXT NOT NULL);
        INSERT INTO tokens VALUES ('h', 'c', NULL, '', 1e12, 'f');
    """)
    conn.commit()
    conn.close()

    provider = make_provider(fake, storage_path=path)
    client = await http(provider)
    tokens = await full_sign_in(client, fake)
    assert provider.verify_token(tokens["access_token"])["sub"] == f"{ISSUER}|user-1"
    resp = await client.post("/token", data={
        "grant_type": "refresh_token", "client_id": "test-client", "client_secret": "test-secret",
        "refresh_token": tokens["refresh_token"],
    })
    assert resp.status_code == 200
    # Opening it again is a no-op, not a "duplicate column" crash.
    make_provider(fake, storage_path=path)


# --- No IdP: fail closed unless opted in ---

def _plain_provider(**kwargs):
    return OAuthProvider(
        base_url=BASE, clients={"test-client": "test-secret"},
        client_redirect_uris={"test-client": [CLIENT_REDIRECT]}, storage_path=None, **kwargs,
    )


async def test_fails_closed_without_idp_or_opt_in(http, caplog):
    with caplog.at_level(logging.WARNING, logger="origo"):
        provider = _plain_provider(auto_approve=True)
    assert "fail closed" in caplog.text
    client = await http(provider)

    resp, _ = await start(client)
    assert resp.status_code == 403
    assert "location" not in resp.headers

    # A scripted consent submission is refused the same way.
    _, challenge = make_pkce_pair()
    client.cookies.set("__Host-origo_csrf", "t", domain="testserver")
    resp = await client.post("/authorize", data={
        "response_type": "code", "client_id": "test-client", "redirect_uri": CLIENT_REDIRECT,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s",
        "csrf_token": "t", "approved": "true",
    })
    assert resp.status_code == 403


async def test_env_var_opt_in_restores_consent(http, monkeypatch, caplog):
    monkeypatch.setenv("ORIGO_ALLOW_UNAUTHENTICATED_CONSENT", "true")
    with caplog.at_level(logging.WARNING, logger="origo"):
        provider = _plain_provider(auto_approve=True)
    assert "authenticates nobody" in caplog.text
    client = await http(provider)
    resp, _ = await start(client)
    assert "code" in client_redirect_params(resp)
    # Without auto_approve the opt-in shows the consent page.
    client = await http(_plain_provider())
    resp, _ = await start(client)
    assert resp.status_code == 200
    assert "Approve" in resp.text


async def test_constructor_opt_in_and_override(http, monkeypatch):
    client = await http(_plain_provider(auto_approve=True, allow_unauthenticated_consent=True))
    resp, _ = await start(client)
    assert "code" in client_redirect_params(resp)

    # An explicit False beats the env var.
    monkeypatch.setenv("ORIGO_ALLOW_UNAUTHENTICATED_CONSENT", "true")
    client = await http(_plain_provider(auto_approve=True, allow_unauthenticated_consent=False))
    resp, _ = await start(client)
    assert resp.status_code == 403


async def test_idp_ignores_auto_approve_and_opt_in(fake, http, caplog):
    with caplog.at_level(logging.WARNING, logger="origo"):
        provider = make_provider(fake, auto_approve=True, allow_unauthenticated_consent=True)
    assert "ignored" in caplog.text
    client = await http(provider)
    resp, _ = await start(client)
    assert resp.headers["location"].startswith(ISSUER)


# --- CIMD client allowlist ---

CIMD_ID = "https://claude.ai/oauth/mcp-oauth-client-metadata"


@pytest.fixture
def cimd_documents(monkeypatch):
    def fetch(client_id, allow_private_hosts=False):
        return {"client_id": client_id, "redirect_uris": [CLIENT_REDIRECT], "token_endpoint_auth_method": "none"}
    monkeypatch.setattr("origo.endpoints._fetch_client_metadata_document", fetch)


async def _cimd_authorize(client, client_id):
    _, challenge = make_pkce_pair()
    return await client.get("/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": CLIENT_REDIRECT,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s",
    })


@pytest.mark.parametrize("allowed, client_id, ok", [
    (["claude.ai"], CIMD_ID, True),
    ([CIMD_ID], CIMD_ID, True),
    (["*.example.com"], "https://app.example.com/meta", True),
    (["claude.ai"], "https://evil.example/meta", False),
    (["claude.ai"], "https://evilclaude.ai/meta", False),
    (["claude.ai"], "https://sub.claude.ai/meta", False),
    (["*.example.com"], "https://example.com/meta", False),
    ([CIMD_ID], CIMD_ID + "-other", False),
])
async def test_cimd_allowlist(fake, http, cimd_documents, allowed, client_id, ok):
    provider = OAuthProvider(base_url=BASE, public_registration=True, storage_path=None,
                             identity_provider=make_idp(fake), cimd_allowed_clients=allowed)
    client = await http(provider)
    resp = await _cimd_authorize(client, client_id)
    if ok:
        assert resp.status_code == 302 and resp.headers["location"].startswith(ISSUER)
    else:
        assert resp.status_code == 401
        assert not provider.storage.client_exists(client_id)


async def test_cimd_allowlist_cuts_off_already_registered_clients(fake, http, cimd_documents, tmp_path):
    path = str(tmp_path / "o.db")
    before = OAuthProvider(base_url=BASE, public_registration=True, storage_path=path, client_ttl=3600,
                           identity_provider=make_idp(fake))
    assert (await _cimd_authorize(await http(before), "https://evil.example/meta")).status_code == 302
    after = OAuthProvider(base_url=BASE, public_registration=True, storage_path=path, client_ttl=3600,
                          identity_provider=make_idp(fake), cimd_allowed_clients=["claude.ai"])
    assert after.storage.client_exists("https://evil.example/meta")
    assert (await _cimd_authorize(await http(after), "https://evil.example/meta")).status_code == 401


async def test_cimd_allowlist_turns_dcr_off(fake, http):
    """DCR would mint an unlisted client with any redirect_uri, walking
    around the allowlist — so the allowlist closes it."""
    provider = OAuthProvider(base_url=BASE, public_registration=True, storage_path=None,
                             identity_provider=make_idp(fake), cimd_allowed_clients=["claude.ai"])
    client = await http(provider)
    resp = await client.post("/register", json={"redirect_uris": ["https://attacker.example/cb"]})
    assert resp.status_code == 400
    assert resp.json()["error"] == "access_denied"
    meta = (await client.get("/.well-known/oauth-authorization-server")).json()
    assert "registration_endpoint" not in meta

    # Without the allowlist DCR stays as it was.
    open_provider = OAuthProvider(base_url=BASE, public_registration=True, storage_path=None,
                                  identity_provider=make_idp(fake))
    client = await http(open_provider)
    resp = await client.post("/register", json={"redirect_uris": ["https://app.example/cb"]})
    assert resp.status_code == 201


# --- Config validation ---

def test_identity_provider_config_validation():
    with pytest.raises(ValueError):
        IdentityProvider(issuer="http://idp.example", client_id="x")
    with pytest.raises(ValueError):
        IdentityProvider(issuer=ISSUER, client_id="x", scopes=["email"])
    with pytest.raises(TypeError):
        IdentityProvider(issuer=ISSUER, client_id="x", allowed_groups="staff")
    with pytest.raises(TypeError):
        OAuthProvider(base_url=BASE, public_registration=True, storage_path=None, cimd_allowed_clients="claude.ai")
    # Loopback http is fine for local development.
    IdentityProvider(issuer="http://localhost:8080/realms/dev", client_id="x")
