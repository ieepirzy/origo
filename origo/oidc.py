"""Upstream OpenID Connect sign-in for :class:`origo.OAuthProvider`.

With an :class:`IdentityProvider` configured, ``/authorize`` no longer shows
the approve/deny consent page. It sends the person to the upstream IdP
(Keycloak, Google Workspace, Entra, ...) with the OIDC authorization-code flow
— PKCE, ``state`` and ``nonce`` — and only issues an origo code once the IdP's
``id_token`` has been verified and the person has passed the allow gate. The
IdP owns accounts, passwords, MFA and groups; origo never sees a password.

What origo takes from the IdP, and nothing more:

- ``sub``, namespaced by issuer as ``<issuer>|<idp sub>``, so two IdPs (or two
  realms on one Keycloak) can never collide on a subject.
- ``email``, only when the IdP asserts ``email_verified: true``. An unverified
  email is dropped, and fails the domain gate if one is configured.
- ``name`` and, when the configured claim is present, ``groups``.

Those claims are stored with the grant (code -> access token -> every rotated
refresh token), so they survive refresh-token rotation without another trip to
the IdP.

With ``recheck_on_refresh`` on, origo also keeps the IdP's own refresh token
for the grant, sealed with AES-GCM under an operator key (see
:class:`TokenSealer`), and every origo refresh first refreshes at the IdP. The
person's access then ends server-side, within one origo access-token lifetime,
as soon as the IdP refuses: account disabled, session logged out or revoked,
SSO session idle or max reached, or no longer in an allowed group. Nothing
depends on what the client holds.

The id_token is verified with ``cryptography`` (already a dependency for
origo's own signing) rather than a JWT library: signature against the IdP's
JWKS, ``iss``, ``aud``/``azp``, ``exp`` and ``nonce``. Only asymmetric
algorithms are accepted — ``none`` and the HMAC family are refused outright,
since an HS256 token "signed" with a public key is the classic JWT confusion
attack.

HTTP to the IdP goes through :meth:`IdentityProvider.fetch_json`, a plain
synchronous method run in a worker thread. It is deliberately the single seam
the tests replace with a fake IdP; nothing else here touches the network.
"""

import base64
import hashlib
import hmac
import http.client
import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Iterable, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import asyncio

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


logger = logging.getLogger("origo")

# alg -> (key type, hash, EC curve name or None). Asymmetric only: see module docstring.
_ALGORITHMS = {
    "RS256": ("RSA", hashes.SHA256, None),
    "RS384": ("RSA", hashes.SHA384, None),
    "RS512": ("RSA", hashes.SHA512, None),
    "PS256": ("RSA-PSS", hashes.SHA256, None),
    "PS384": ("RSA-PSS", hashes.SHA384, None),
    "PS512": ("RSA-PSS", hashes.SHA512, None),
    "ES256": ("EC", hashes.SHA256, "P-256"),
    "ES384": ("EC", hashes.SHA384, "P-384"),
    "ES512": ("EC", hashes.SHA512, "P-521"),
}

_EC_CURVES = {
    "P-256": (ec.SECP256R1, 32),
    "P-384": (ec.SECP384R1, 48),
    "P-521": (ec.SECP521R1, 66),
}

# Bound every IdP response: a misbehaving or hostile endpoint must not be able
# to make origo buffer an unbounded body.
_MAX_RESPONSE_BYTES = 1024 * 1024

# A kid the cached JWKS doesn't know triggers one refetch (the IdP rotated its
# keys), but not more often than this — otherwise a stream of forged kids
# becomes a stream of requests to the IdP.
_JWKS_REFETCH_INTERVAL = 60

# Cache lifetimes. Keys rotate, and an IdP's endpoints can move; neither is
# re-read per sign-in, but neither is trusted for the life of the process.
_JWKS_TTL = 3600
_DISCOVERY_TTL = 24 * 3600

# After a failed refresh with a cached copy in hand, wait this long before
# trying again. Otherwise, during an IdP outage, every sign-in would spend up
# to the fetch timeout retrying before falling back to the cache.
_REFRESH_BACKOFF = 60

_USER_AGENT = "origo (+https://github.com/ieepirzy/origo)"


class IdentityError(Exception):
    """Upstream sign-in failed; no origo code may be issued.

    ``error`` is the OAuth error code relayed to the client's redirect_uri:
    ``access_denied`` when the person or their token was refused, and
    ``server_error`` when the IdP could not be reached or misbehaved.
    The message is for origo's log only, never sent to the client.

    ``status`` and ``oauth_error`` are set when the IdP answered an HTTP error:
    its status code and, if its body was an OAuth error object, the ``error``
    code in it (``invalid_grant`` and so on).
    """

    def __init__(self, message: str, error: str = "access_denied", status: Optional[int] = None,
                 oauth_error: Optional[str] = None):
        super().__init__(message)
        self.error = error
        self.status = status
        self.oauth_error = oauth_error


class IdentityRefused(IdentityError):
    """A verified identity that failed the allow gate (domain or group), or,
    on a refresh re-check, a grant the IdP no longer honours."""


# --- Sealing the IdP's refresh token at rest ---

_SEAL_VERSION = "v1"
_SEAL_CONTEXT = b"origo-idp-refresh-token\0"


def _load_key(raw: bytes, what: str) -> bytes:
    """A 32-byte AES-256 key: the raw bytes, or their base64 / base64url /
    hex encoding (surrounding whitespace ignored)."""
    if len(raw) == 32:
        return raw
    text = raw.strip()
    for decode in (
        lambda t: bytes.fromhex(t.decode("ascii")),
        lambda t: base64.b64decode(t + b"=" * (-len(t) % 4), validate=True),
        lambda t: base64.urlsafe_b64decode(t + b"=" * (-len(t) % 4)),
    ):
        try:
            key = decode(text)
        except (ValueError, UnicodeDecodeError):
            continue
        if len(key) == 32:
            return key
    raise ValueError(f"{what} is not a 32-byte key (raw, hex, base64 or base64url)")


class TokenSealer:
    """AES-256-GCM sealing of the IdP refresh tokens origo keeps.

    The first key seals; every key opens, so a key can be rotated without
    signing anyone out: add the new key in front, keep the old one behind it
    until every grant has refreshed once (each refresh re-seals under the
    first key), then drop it. A sealed value names its key by an 8-hex-digit
    fingerprint (a prefix of the key's SHA-256), never the key itself.

    ``associated`` binds a sealed value to where it is stored (the grant's
    token family, or the auth code it waits under), so a value copied to
    another grant's row does not open.
    """

    def __init__(self, keys: Iterable[bytes]):
        self._keys: list[tuple[str, AESGCM]] = []
        for key in keys:
            if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
                raise ValueError("token keys must be 32 bytes each (AES-256)")
            kid = hashlib.sha256(bytes(key)).hexdigest()[:8]
            if any(k == kid for k, _ in self._keys):
                raise ValueError("the same token key is configured twice")
            self._keys.append((kid, AESGCM(bytes(key))))
        if not self._keys:
            raise ValueError("TokenSealer needs at least one key")

    @classmethod
    def from_files(cls, paths: Iterable[str]) -> "TokenSealer":
        keys = []
        for path in paths:
            with open(path, "rb") as f:
                keys.append(_load_key(f.read(), f"token key file {path!r}"))
        return cls(keys)

    def seal(self, value: str, associated: str) -> str:
        kid, aead = self._keys[0]
        nonce = os.urandom(12)
        ciphertext = aead.encrypt(nonce, value.encode("utf-8"), _SEAL_CONTEXT + associated.encode("utf-8"))
        return f"{_SEAL_VERSION}.{kid}.{base64.urlsafe_b64encode(nonce + ciphertext).decode().rstrip('=')}"

    def open(self, sealed: str, associated: str) -> Optional[str]:
        """The value, or None when no configured key opens it (wrong key,
        tampered, or bound to another place)."""
        try:
            version, kid, body = sealed.split(".", 2)
            raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        except (AttributeError, ValueError):
            return None
        if version != _SEAL_VERSION or len(raw) < 12 + 16:
            return None
        for key_id, aead in self._keys:
            if key_id != kid:
                continue
            try:
                return aead.decrypt(raw[:12], raw[12:], _SEAL_CONTEXT + associated.encode("utf-8")).decode("utf-8")
            except (InvalidTag, UnicodeDecodeError):
                return None
        return None


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("not a string")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64url_int(value: str) -> int:
    return int.from_bytes(_b64url_decode(value), "big")


def _is_loopback_host(hostname: Optional[str]) -> bool:
    return (hostname or "") in ("localhost", "127.0.0.1", "::1")


def _require_secure_url(url: str, what: str) -> None:
    """https always; plain http only to a loopback IdP (local development)."""
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise ValueError(f"{what} is not a valid URL: {url!r}") from exc
    if parsed.scheme == "https" and parsed.hostname:
        return
    if parsed.scheme == "http" and _is_loopback_host(parsed.hostname):
        return
    raise ValueError(f"{what} must be an https URL (http only for localhost); got {url!r}")


def domain_matches(host: str, pattern: str) -> bool:
    """Exact host match, or a ``*.example.com`` pattern matching any subdomain.

    The wildcard needs a dot boundary — ``*.muutto365.fi`` matches
    ``a.muutto365.fi`` but neither ``muutto365.fi`` nor ``evilmuutto365.fi`` —
    and a bare pattern never matches a subdomain. Used by the CIMD client
    allowlist.
    """
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def _verify_jws_signature(header_b64: str, payload_b64: str, signature: bytes, alg: str, jwk: dict, what: str) -> None:
    """Verify a JWS signature with an asymmetric ``alg`` (a key of _ALGORITHMS)
    against ``jwk``. Raises IdentityError naming ``what`` on any failure."""
    family, hash_cls, curve = _ALGORITHMS[alg]
    kty = "EC" if family == "EC" else "RSA"
    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        if kty == "RSA":
            public_key = rsa.RSAPublicNumbers(_b64url_int(jwk["e"]), _b64url_int(jwk["n"])).public_key()
            pad = (
                padding.PKCS1v15() if family == "RSA"
                else padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=hash_cls.digest_size)
            )
            public_key.verify(signature, signing_input, pad, hash_cls())
        else:
            if jwk.get("crv") != curve:
                raise IdentityError(f"{what} alg {alg} does not match key curve {jwk.get('crv')!r}")
            curve_cls, size = _EC_CURVES[curve]
            public_key = ec.EllipticCurvePublicNumbers(
                _b64url_int(jwk["x"]), _b64url_int(jwk["y"]), curve_cls()
            ).public_key()
            # JWS carries ECDSA signatures as raw r||s, not DER.
            if len(signature) != 2 * size:
                raise IdentityError(f"{what} ECDSA signature has the wrong length")
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
            public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hash_cls()))
    except InvalidSignature as exc:
        raise IdentityError(f"{what} signature is invalid") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise IdentityError(f"IdP signing key is unusable: {exc}") from exc


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """The token endpoint must answer itself: a redirect could carry the
    authorization code and client secret somewhere else."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_json(url: str, form: Optional[dict] = None, headers: Optional[dict] = None, allow_list: bool = False):
    """GET (or, with ``form``, POST form-encoded) ``url`` and return its JSON
    object (or, with ``allow_list``, array). Raises IdentityError on any
    transport, status or decoding failure. Redirects are refused. Synchronous;
    callers use a worker thread."""
    _require_secure_url(url, "IdP endpoint")
    # An explicit User-Agent: Cloudflare's default bot rules answer 403 to
    # urllib's "Python-urllib/x.y" (observed in front of the first
    # Keycloak this was deployed against), which would fail every sign-in.
    request_headers = {"Accept": "application/json", "User-Agent": _USER_AGENT, **(headers or {})}
    data = None
    if form is not None:
        data = urlencode(form).encode()
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=data, headers=request_headers, method="POST" if data is not None else "GET")
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=10) as response:
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        # The IdP's error body (e.g. {"error": "invalid_grant"}) is the
        # useful part of a failed exchange; keep it for the log.
        try:
            detail = exc.read(4096).decode("utf-8", "replace")
        except Exception:
            detail = ""
        oauth_error = None
        try:
            parsed_detail = json.loads(detail)
            if isinstance(parsed_detail, dict) and isinstance(parsed_detail.get("error"), str):
                oauth_error = parsed_detail["error"]
        except ValueError:
            pass
        raise IdentityError(
            f"IdP returned HTTP {exc.code} from {url}: {detail}",
            error="server_error", status=exc.code, oauth_error=oauth_error,
        ) from exc
    except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError) as exc:
        # HTTPException: a truncated or malformed response (IncompleteRead,
        # BadStatusLine) must become a server_error redirect, not a 500.
        raise IdentityError(f"IdP request to {url} failed: {exc}", error="server_error") from exc
    if len(body) > _MAX_RESPONSE_BYTES:
        raise IdentityError(f"IdP response from {url} exceeds {_MAX_RESPONSE_BYTES} bytes", error="server_error")
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise IdentityError(f"IdP response from {url} is not JSON", error="server_error") from exc
    if not isinstance(parsed, dict) and not (allow_list and isinstance(parsed, list)):
        raise IdentityError(f"IdP response from {url} is not a JSON object", error="server_error")
    return parsed


class IdentityProvider:
    """
    An upstream OpenID Connect provider that people sign in with.

    Endpoints are found through OIDC discovery at
    ``<issuer>/.well-known/openid-configuration``, fetched on the first sign-in
    (never at construction, so building an OAuthProvider never touches the
    network) and cached for the life of the process.

    Args:
        issuer:          The IdP's issuer URL, exactly as it appears in its
                         id_tokens' ``iss`` — for Keycloak
                         ``https://<host>/realms/<realm>``.
        client_id:       origo's client ID at the IdP.
        client_secret:   origo's client secret at the IdP. Omit for a public
                         IdP client (PKCE only).
        scopes:          Scopes requested from the IdP. Must include ``openid``.
                         Default ``["openid", "email", "profile"]``.
        allowed_email_domains: If set, only people whose *verified* email is at
                         one of these domains (exact match, no subdomains) may
                         sign in.
        allowed_groups:  If set, only people in at least one of these groups
                         (exact string match against ``groups_claim``) may sign
                         in. Keycloak's group-membership mapper emits
                         ``/name`` when "Full group path" is on and ``name``
                         when it is off.
        groups_claim:    id_token claim holding the person's groups. A dotted
                         path reaches into nested claims, e.g.
                         ``realm_access.roles``. Default ``"groups"``.
        token_endpoint_auth_method: How origo authenticates to the IdP's token
                         endpoint: ``"client_secret_basic"`` (default) or
                         ``"client_secret_post"``. Ignored without a secret.
        login_ttl:       Seconds a person has to finish signing in at the IdP.
                         Default 600.
        max_grant_age:   Seconds a signed-in grant may be refreshed for, counted
                         from the sign-in. Past it /token refuses the refresh and
                         the client has to send the person back through the IdP.
                         Default 12 hours. With ``recheck_on_refresh`` it stays
                         an absolute upper bound on top of the IdP's own limits.
        clock_skew:      Leeway in seconds for ``exp``/``iat``. Default 60.
        recheck_on_refresh: Keep the IdP's refresh token for each grant and
                         refresh at the IdP on every origo refresh. The IdP's
                         refusal (``invalid_grant``: account disabled, logged
                         out, session revoked, SSO session idle or max
                         reached) or a failed allow gate on the fresh claims
                         ends the grant and revokes its live tokens; group and
                         email changes reach the stored claims. An unreachable
                         IdP refuses the refresh as retryable without ending
                         the grant. A grant's lifetime then follows the IdP's
                         session settings (Keycloak: SSO Session Idle/Max and
                         Client Session Idle/Max); a refresh every token_ttl
                         keeps an idle timeout longer than it alive. Requires
                         ``token_keys`` or ``token_key_files``. Default False.
        token_keys:      32-byte AES-256 keys sealing the kept IdP refresh
                         tokens; the first seals, all open (rotation: see
                         :class:`TokenSealer`).
        token_key_files: Paths to the same keys, one per file (raw 32 bytes,
                         hex, base64 or base64url), read once at construction.

    Every configured gate must pass. With neither gate set, anyone the IdP
    authenticates gets in — right for a realm that holds only your own people.
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: Optional[str] = None,
        scopes: Optional[Iterable[str]] = None,
        allowed_email_domains: Optional[Iterable[str]] = None,
        allowed_groups: Optional[Iterable[str]] = None,
        groups_claim: str = "groups",
        token_endpoint_auth_method: str = "client_secret_basic",
        login_ttl: int = 600,
        clock_skew: int = 60,
        max_grant_age: int = 12 * 3600,
        recheck_on_refresh: bool = False,
        token_keys: Optional[Iterable[bytes]] = None,
        token_key_files: Optional[Iterable[str]] = None,
    ):
        if not issuer or not client_id:
            raise ValueError("IdentityProvider requires issuer and client_id")
        _require_secure_url(issuer, "IdentityProvider issuer")
        for name, value in (("scopes", scopes), ("allowed_email_domains", allowed_email_domains), ("allowed_groups", allowed_groups)):
            if isinstance(value, str):
                raise TypeError(f"IdentityProvider {name} must be a list of strings, not a single string")
        if token_endpoint_auth_method not in ("client_secret_basic", "client_secret_post"):
            raise ValueError("token_endpoint_auth_method must be 'client_secret_basic' or 'client_secret_post'")

        # Kept verbatim: iss is compared exactly, and Keycloak's issuer has no
        # trailing slash while some IdPs' (Auth0) does.
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = list(scopes) if scopes is not None else ["openid", "email", "profile"]
        if "openid" not in self.scopes:
            raise ValueError("IdentityProvider scopes must include 'openid'")
        self.allowed_email_domains = frozenset(d.lower().lstrip("@") for d in (allowed_email_domains or []))
        self.allowed_groups = frozenset(allowed_groups or [])
        self.groups_claim = groups_claim
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.login_ttl = login_ttl
        self.clock_skew = clock_skew
        self.max_grant_age = max_grant_age

        if isinstance(token_key_files, str):
            raise TypeError("IdentityProvider token_key_files must be a list of paths, not a single string")
        if token_keys is not None and token_key_files is not None:
            raise ValueError("give token_keys or token_key_files, not both")
        self.sealer: Optional[TokenSealer] = None
        if token_key_files is not None:
            self.sealer = TokenSealer.from_files(token_key_files)
        elif token_keys is not None:
            self.sealer = TokenSealer(token_keys)
        if recheck_on_refresh and self.sealer is None:
            raise ValueError(
                "IdentityProvider recheck_on_refresh needs token_keys or token_key_files: "
                "the IdP refresh tokens it keeps are sealed at rest"
            )
        self.recheck_on_refresh = bool(recheck_on_refresh)

        self._metadata: Optional[dict] = None
        self._metadata_fetched_at = 0.0
        self._metadata_retry_after = 0.0
        self._jwks: Optional[dict] = None
        self._jwks_fetched_at = 0.0
        self._jwks_retry_after = 0.0

    # --- HTTP (the one seam tests replace) ---

    def fetch_json(self, url: str, form: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        """GET (or, with ``form``, POST form-encoded) ``url`` and return its JSON object.

        Raises IdentityError on any transport, status or decoding failure.
        Redirects are refused. Runs synchronously; callers use a worker thread.
        """
        return _http_json(url, form, headers)

    async def _fetch(self, url: str, form: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        return await asyncio.to_thread(self.fetch_json, url, form, headers)

    # --- Discovery ---

    async def metadata(self) -> dict:
        """The IdP's discovery document, cached for a day.

        A failed refresh keeps serving the cached document (logged) rather
        than failing sign-ins over a transient outage of the discovery URL.
        """
        now = time.time()
        if self._metadata is not None and (
            now - self._metadata_fetched_at < _DISCOVERY_TTL or now < self._metadata_retry_after
        ):
            return self._metadata
        try:
            document = await self._fetch_metadata()
        except IdentityError as exc:
            if self._metadata is None:
                raise
            self._metadata_retry_after = now + _REFRESH_BACKOFF
            logger.warning("IdP discovery refresh failed, keeping the cached document: %s", exc)
            return self._metadata
        self._metadata = document
        self._metadata_fetched_at = time.time()
        return document

    async def _fetch_metadata(self) -> dict:
        # Appended, never urljoin()ed: urljoin would drop the issuer's path
        # (Keycloak's /realms/<realm>) and fetch the host's root document.
        url = self.issuer.rstrip("/") + "/.well-known/openid-configuration"
        document = await self._fetch(url)
        # OIDC Discovery §4.3: the document's issuer MUST equal the configured
        # one. A mismatch means the URL is not the IdP we think it is.
        if document.get("issuer") != self.issuer:
            raise IdentityError(
                f"IdP discovery issuer {document.get('issuer')!r} does not match configured issuer {self.issuer!r}",
                error="server_error",
            )
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = document.get(key)
            if not isinstance(value, str):
                raise IdentityError(f"IdP discovery document lacks {key}", error="server_error")
            try:
                _require_secure_url(value, f"IdP {key}")
            except ValueError as exc:
                raise IdentityError(str(exc), error="server_error") from exc
        return document

    async def authorization_url(self, redirect_uri: str, state: str, nonce: str, code_challenge: str) -> str:
        """Where to send the person to sign in, for this one login attempt."""
        endpoint = (await self.metadata())["authorization_endpoint"]
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        parts = urlparse(endpoint)
        query = urlencode(parse_qsl(parts.query) + list(params.items()))
        return urlunparse(parts._replace(query=query))

    # --- Code exchange ---

    async def _token_request(self, form: dict) -> dict:
        """POST to the IdP's token endpoint with origo's client authentication."""
        metadata = await self.metadata()
        form = {**form, "client_id": self.client_id}
        headers = {}
        if self.client_secret:
            if self.token_endpoint_auth_method == "client_secret_post":
                form["client_secret"] = self.client_secret
            else:
                # RFC 6749 §2.3.1: both halves are form-urlencoded before
                # being joined, so a secret containing ':' or '%' survives.
                pair = f"{_form_encode(self.client_id)}:{_form_encode(self.client_secret)}"
                headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
        return await self._fetch(metadata["token_endpoint"], form=form, headers=headers)

    async def complete_login(self, code: str, redirect_uri: str, code_verifier: str, nonce: str) -> dict:
        """Exchange the IdP's code, verify its id_token, apply the gate, and
        return origo's claims for the person: sub, plus email/name/groups when
        the IdP provided them. Raises IdentityError (or IdentityRefused)."""
        identity, _ = await self.complete_login_with_refresh_token(code, redirect_uri, code_verifier, nonce)
        return identity

    async def complete_login_with_refresh_token(
        self, code: str, redirect_uri: str, code_verifier: str, nonce: str
    ) -> tuple[dict, Optional[str]]:
        """complete_login, also returning the IdP's refresh token (None when
        the IdP issued none). The token is a credential: seal it, never log it."""
        response = await self._token_request({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        })
        id_token = response.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise IdentityError("IdP token response carries no id_token", error="server_error")
        claims = await self.verify_id_token(id_token, nonce)
        identity = self.map_claims(claims)
        self.check_gate(identity, claims)
        refresh_token = response.get("refresh_token")
        return identity, refresh_token if isinstance(refresh_token, str) and refresh_token else None

    async def refresh_identity(self, refresh_token: str, sub: str) -> tuple[dict, str]:
        """Refresh at the IdP with its refresh token for the grant of ``sub``
        (origo's namespaced subject). Returns the person's fresh claims, gate
        applied, and the refresh token to keep next (the rotated one, or the
        same one when the IdP does not rotate).

        Raises IdentityRefused when the grant is over: the IdP answered
        ``invalid_grant``, named a different subject, or the fresh claims fail
        the allow gate. Raises a plain IdentityError when the IdP could not
        give an answer (unreachable, 5xx, any other error, an id_token that
        doesn't verify): retryable, the grant is not over.
        """
        try:
            response = await self._token_request({"grant_type": "refresh_token", "refresh_token": refresh_token})
        except IdentityRefused:
            raise
        except IdentityError as exc:
            if exc.oauth_error == "invalid_grant":
                raise IdentityRefused(f"the IdP refused the grant's refresh (HTTP {exc.status}, invalid_grant)") from exc
            # Without the IdP's body (it may echo request details) in the message.
            raise IdentityError(
                f"IdP refresh failed (HTTP {exc.status}, {exc.oauth_error or 'no OAuth error code'})"
                if exc.status is not None else "IdP refresh failed: the IdP could not be reached",
                error="server_error", status=exc.status, oauth_error=exc.oauth_error,
            ) from exc

        id_token = response.get("id_token")
        if isinstance(id_token, str) and id_token:
            # OIDC Core §12.2: a refreshed id_token's iss, sub and aud match
            # the original's. Its nonce, if any, is the original sign-in's,
            # which origo doesn't keep: the signature, iss, aud/azp and exp
            # are what bind this token to this IdP and this client.
            claims = await self.verify_id_token(id_token, nonce=None)
        else:
            claims = await self._userinfo(response.get("access_token"))
        if f"{self.issuer}|{claims.get('sub')}" != sub:
            raise IdentityRefused("the IdP's refreshed identity names a different subject")
        identity = self.map_claims(claims)
        self.check_gate(identity, claims)
        new_refresh_token = response.get("refresh_token")
        return identity, new_refresh_token if isinstance(new_refresh_token, str) and new_refresh_token else refresh_token

    async def _userinfo(self, access_token) -> dict:
        """The person's claims from the IdP's userinfo endpoint, for an IdP
        that returns no id_token on refresh. Fetched over TLS straight from
        the discovered endpoint with the access token the IdP just issued."""
        endpoint = (await self.metadata()).get("userinfo_endpoint")
        if not isinstance(access_token, str) or not access_token or not isinstance(endpoint, str):
            raise IdentityError(
                "IdP refresh returned no id_token, and no userinfo endpoint and access token to fall back on",
                error="server_error",
            )
        try:
            _require_secure_url(endpoint, "IdP userinfo_endpoint")
        except ValueError as exc:
            raise IdentityError(str(exc), error="server_error") from exc
        claims = await self._fetch(endpoint, headers={"Authorization": f"Bearer {access_token}"})
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise IdentityError("IdP userinfo has no sub", error="server_error")
        return claims

    # --- id_token verification ---

    async def _signing_key(self, kid: Optional[str], kty: str):
        """The JWKS key for kid. The JWKS is refetched when it is older than
        _JWKS_TTL, or when it lacks kid (the IdP rotated) — the latter at most
        once per _JWKS_REFETCH_INTERVAL."""
        now = time.time()
        age = now - self._jwks_fetched_at
        if self._jwks is None or (now >= self._jwks_retry_after and (
            age >= _JWKS_TTL
            or (self._find_jwk(self._jwks, kid, kty) is None and age >= _JWKS_REFETCH_INTERVAL)
        )):
            try:
                self._jwks = await self._fetch((await self.metadata())["jwks_uri"])
                self._jwks_fetched_at = now
            except IdentityError:
                if self._jwks is None:
                    raise
                self._jwks_retry_after = now + _REFRESH_BACKOFF
                logger.warning("IdP JWKS refresh failed, keeping the cached keys.")
        jwk = self._find_jwk(self._jwks, kid, kty)
        if jwk is None:
            raise IdentityError(f"no IdP signing key matches kid {kid!r}")
        return jwk

    @staticmethod
    def _find_jwk(jwks: dict, kid: Optional[str], kty: str) -> Optional[dict]:
        keys = jwks.get("keys")
        if not isinstance(keys, list):
            return None
        # Keycloak publishes an RSA-OAEP encryption key next to its signing
        # key; anything marked for another use is not a signing candidate.
        candidates = [
            k for k in keys
            if isinstance(k, dict) and k.get("kty") == kty and k.get("use", "sig") == "sig"
        ]
        if kid is not None:
            for key in candidates:
                if key.get("kid") == kid:
                    return key
            return None
        # No kid in the header: unambiguous only if the IdP has one such key.
        return candidates[0] if len(candidates) == 1 else None

    async def verify_id_token(self, id_token: str, nonce: Optional[str]) -> dict:
        """Verify signature, iss, aud/azp, exp and nonce; return the claims.

        ``nonce`` is None only for an id_token from a refresh, which answers
        no sign-in of ours (OIDC Core §12.2); every sign-in passes its own."""
        try:
            header_b64, payload_b64, signature_b64 = id_token.split(".")
            header = json.loads(_b64url_decode(header_b64))
            claims = json.loads(_b64url_decode(payload_b64))
            signature = _b64url_decode(signature_b64)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise IdentityError("id_token is not a well-formed JWS") from exc
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise IdentityError("id_token header or payload is not a JSON object")

        alg = header.get("alg")
        if alg not in _ALGORITHMS:
            raise IdentityError(f"id_token alg {alg!r} is not accepted")
        family, hash_cls, curve = _ALGORITHMS[alg]
        kty = "EC" if family == "EC" else "RSA"
        kid = header.get("kid")
        jwk = await self._signing_key(kid if isinstance(kid, str) else None, kty)

        _verify_jws_signature(header_b64, payload_b64, signature, alg, jwk, "id_token")

        if claims.get("iss") != self.issuer:
            raise IdentityError(f"id_token iss {claims.get('iss')!r} is not {self.issuer!r}")

        aud = claims.get("aud")
        audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        if self.client_id not in audiences:
            raise IdentityError(f"id_token aud {aud!r} does not include {self.client_id!r}")
        # OIDC Core §3.1.3.7: with several audiences the token must name us as
        # its authorized party; a present azp must always be us.
        azp = claims.get("azp")
        if (len(audiences) > 1 or azp is not None) and azp != self.client_id:
            raise IdentityError(f"id_token azp {azp!r} is not {self.client_id!r}")

        now = time.time()
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or isinstance(exp, bool) or exp + self.clock_skew < now:
            raise IdentityError("id_token is expired or has no exp")
        nbf = claims.get("nbf")
        if nbf is not None and (not isinstance(nbf, (int, float)) or nbf - self.clock_skew > now):
            raise IdentityError("id_token is not valid yet (nbf)")
        iat = claims.get("iat")
        if iat is not None and (not isinstance(iat, (int, float)) or iat - self.clock_skew > now):
            raise IdentityError("id_token iat is in the future")

        if nonce is not None:
            token_nonce = claims.get("nonce")
            if not isinstance(token_nonce, str) or not hmac.compare_digest(token_nonce.encode(), nonce.encode()):
                raise IdentityError("id_token nonce does not match this sign-in")

        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise IdentityError("id_token has no sub")
        return claims

    # --- Mapping and gate ---

    def _groups(self, claims: dict) -> Optional[list[str]]:
        value = claims
        for part in self.groups_claim.split("."):
            if not isinstance(value, dict) or part not in value:
                return None
            value = value[part]
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [g for g in value if isinstance(g, str)]
        return None

    def map_claims(self, claims: dict) -> dict:
        """origo's claims for a verified id_token."""
        identity: dict = {"sub": f"{self.issuer}|{claims['sub']}"}
        email = claims.get("email")
        # Only a verified email is an identity claim. Strictly the boolean:
        # a string "false" is truthy, and guessing at other encodings is how
        # an unverified address ends up passing a domain gate.
        if isinstance(email, str) and email and claims.get("email_verified") is True:
            identity["email"] = email
        name = claims.get("name")
        if isinstance(name, str) and name:
            identity["name"] = name
        groups = self._groups(claims)
        if groups is not None:
            identity["groups"] = groups
        return identity

    def check_gate(self, identity: dict, claims: dict) -> None:
        if self.allowed_email_domains:
            email = identity.get("email")
            if email is None:
                raise IdentityRefused(
                    f"sign-in of {identity['sub']!r} refused: no verified email "
                    f"(email={claims.get('email')!r}, email_verified={claims.get('email_verified')!r})"
                )
            domain = email.rsplit("@", 1)[-1].lower()
            # Exact domain only: "muutto365.fi" admits neither
            # "x.muutto365.fi" nor "evilmuutto365.fi".
            if domain not in self.allowed_email_domains:
                raise IdentityRefused(f"sign-in of {identity['sub']!r} refused: email domain {domain!r} is not allowed")
        if self.allowed_groups:
            if not self.allowed_groups.intersection(identity.get("groups") or []):
                raise IdentityRefused(
                    f"sign-in of {identity['sub']!r} refused: not in any allowed group "
                    f"(claim {self.groups_claim!r} = {identity.get('groups')!r})"
                )


def _form_encode(value: str) -> str:
    return urlencode({"": value})[1:]


def s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
