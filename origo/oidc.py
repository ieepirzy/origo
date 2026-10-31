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
import json
import logging
import time
import urllib.error
import urllib.request
from typing import Iterable, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import asyncio

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


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


class IdentityError(Exception):
    """Upstream sign-in failed; no origo code may be issued.

    ``error`` is the OAuth error code relayed to the client's redirect_uri:
    ``access_denied`` when the person or their token was refused, and
    ``server_error`` when the IdP could not be reached or misbehaved.
    The message is for origo's log only, never sent to the client.
    """

    def __init__(self, message: str, error: str = "access_denied"):
        super().__init__(message)
        self.error = error


class IdentityRefused(IdentityError):
    """A verified identity that failed the allow gate (domain or group)."""


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


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """The token endpoint must answer itself: a redirect could carry the
    authorization code and client secret somewhere else."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
        clock_skew:      Leeway in seconds for ``exp``/``iat``. Default 60.

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

        self._metadata: Optional[dict] = None
        self._jwks: Optional[dict] = None
        self._jwks_fetched_at = 0.0

    # --- HTTP (the one seam tests replace) ---

    def fetch_json(self, url: str, form: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        """GET (or, with ``form``, POST form-encoded) ``url`` and return its JSON object.

        Raises IdentityError on any transport, status or decoding failure.
        Redirects are refused. Runs synchronously; callers use a worker thread.
        """
        _require_secure_url(url, "IdP endpoint")
        request_headers = {"Accept": "application/json", **(headers or {})}
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
            raise IdentityError(f"IdP returned HTTP {exc.code} from {url}: {detail}", error="server_error") from exc
        except (OSError, urllib.error.URLError, ValueError) as exc:
            raise IdentityError(f"IdP request to {url} failed: {exc}", error="server_error") from exc
        if len(body) > _MAX_RESPONSE_BYTES:
            raise IdentityError(f"IdP response from {url} exceeds {_MAX_RESPONSE_BYTES} bytes", error="server_error")
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise IdentityError(f"IdP response from {url} is not JSON", error="server_error") from exc
        if not isinstance(parsed, dict):
            raise IdentityError(f"IdP response from {url} is not a JSON object", error="server_error")
        return parsed

    async def _fetch(self, url: str, form: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        return await asyncio.to_thread(self.fetch_json, url, form, headers)

    # --- Discovery ---

    async def metadata(self) -> dict:
        """The IdP's discovery document, fetched once and cached."""
        if self._metadata is not None:
            return self._metadata
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
        self._metadata = document
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

    async def complete_login(self, code: str, redirect_uri: str, code_verifier: str, nonce: str) -> dict:
        """Exchange the IdP's code, verify its id_token, apply the gate, and
        return origo's claims for the person: sub, plus email/name/groups when
        the IdP provided them. Raises IdentityError (or IdentityRefused)."""
        metadata = await self.metadata()
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "client_id": self.client_id,
        }
        headers = {}
        if self.client_secret:
            if self.token_endpoint_auth_method == "client_secret_post":
                form["client_secret"] = self.client_secret
            else:
                # RFC 6749 §2.3.1: both halves are form-urlencoded before
                # being joined, so a secret containing ':' or '%' survives.
                pair = f"{_form_encode(self.client_id)}:{_form_encode(self.client_secret)}"
                headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
        response = await self._fetch(metadata["token_endpoint"], form=form, headers=headers)
        id_token = response.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise IdentityError("IdP token response carries no id_token", error="server_error")
        claims = await self.verify_id_token(id_token, nonce)
        identity = self.map_claims(claims)
        self.check_gate(identity, claims)
        return identity

    # --- id_token verification ---

    async def _signing_key(self, kid: Optional[str], kty: str):
        """The JWKS key for kid, refetching the JWKS once if the IdP rotated."""
        now = time.time()
        if self._jwks is None or (
            self._find_jwk(self._jwks, kid, kty) is None and now - self._jwks_fetched_at >= _JWKS_REFETCH_INTERVAL
        ):
            self._jwks = await self._fetch((await self.metadata())["jwks_uri"])
            self._jwks_fetched_at = now
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

    async def verify_id_token(self, id_token: str, nonce: str) -> dict:
        """Verify signature, iss, aud/azp, exp and nonce; return the claims."""
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
                    raise IdentityError(f"id_token alg {alg} does not match key curve {jwk.get('crv')!r}")
                curve_cls, size = _EC_CURVES[curve]
                public_key = ec.EllipticCurvePublicNumbers(
                    _b64url_int(jwk["x"]), _b64url_int(jwk["y"]), curve_cls()
                ).public_key()
                # JWS carries ECDSA signatures as raw r||s, not DER.
                if len(signature) != 2 * size:
                    raise IdentityError("id_token ECDSA signature has the wrong length")
                r = int.from_bytes(signature[:size], "big")
                s = int.from_bytes(signature[size:], "big")
                public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hash_cls()))
        except InvalidSignature as exc:
            raise IdentityError("id_token signature is invalid") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise IdentityError(f"IdP signing key is unusable: {exc}") from exc

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
        iat = claims.get("iat")
        if iat is not None and (not isinstance(iat, (int, float)) or iat - self.clock_skew > now):
            raise IdentityError("id_token iat is in the future")

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
