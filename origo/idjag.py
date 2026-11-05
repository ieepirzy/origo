"""Managed sign-in: the Identity Assertion JWT Authorization Grant (ID-JAG).

draft-ietf-oauth-identity-assertion-authz-grant, as claude.ai's "managed
authorization" uses it: a trusted issuer (claude.ai's Claude-issued identity,
or an enterprise IdP) signs a short-lived assertion naming a person, the
client (claude.ai's CIMD client) presents it at origo's token endpoint as an
RFC 7523 ``urn:ietf:params:oauth:grant-type:jwt-bearer`` grant, and origo
issues an access token without a browser round trip.

origo never takes the assertion's word for *who* the person is inside the
organization. It is proof that a member of the trusted issuer's tenant is
calling, under some email. The person origo issues tokens for is the one
upstream :class:`IdentityProvider` (Keycloak) user with that verified email,
enabled, and passing the same allow gate an interactive sign-in passes. The
token's subject is the same ``<idp issuer>|<idp sub>`` an interactive sign-in
gets, so a person's data is theirs however they connected. A member with no
matching Keycloak user gets nothing: the assertion never creates identities.

What the assertion must carry (all checked, any failure is ``invalid_grant``):

- header ``typ`` ``oauth-id-jag+jwt``, an asymmetric ``alg`` (``none`` and the
  HMAC family are refused; see oidc.py), a signature by a key in the pinned
  issuer's JWKS;
- ``iss`` exactly the configured issuer;
- ``aud`` origo's own issuer identifier (its base URL), alone;
- ``client_id`` the client authenticating at /token;
- ``exp`` in the future, ``iat`` not in the future and no older than
  ``max_assertion_age``;
- ``jti``, used once: replay is refused through origo's persistent storage;
- ``sub`` and ``email``;
- ``aud_tenant`` equal to the configured ``tenant``, when one is configured.

The Keycloak lookup uses origo's own client at the IdP (client credentials),
so no new secret: that client needs "Service accounts" enabled and the
realm-management role ``view-users``.
"""

import asyncio
import json
import logging
import time
from typing import Optional
from urllib.parse import quote, urlencode

from .oidc import (
    _ALGORITHMS,
    IdentityError,
    IdentityProvider,
    IdentityRefused,
    _b64url_decode,
    _http_json,
    _JWKS_REFETCH_INTERVAL,
    _JWKS_TTL,
    _DISCOVERY_TTL,
    _REFRESH_BACKOFF,
    _require_secure_url,
    _verify_jws_signature,
)

logger = logging.getLogger("origo")

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
ID_JAG_TYP = "oauth-id-jag+jwt"
_MAX_JTI_LENGTH = 256


class ManagedSignIn:
    """
    Accept ID-JAG assertions from one trusted issuer at /token.

    Requires an :class:`IdentityProvider` on the same OAuthProvider: it is
    where the person is looked up (Keycloak), and its allow gate applies.

    Args:
        issuer:            The assertion issuer, exactly as in its ``iss`` —
                           for claude.ai's Claude-issued identity, the
                           "Issuer URL" its managed-authorization page shows
                           (``https://identity.anthropic.com/issuers/iss_...``).
                           It is per organization: pinning it is what limits
                           sign-in to members of yours.
        tenant:            If set, the assertion's ``aud_tenant`` must equal
                           it (claude.ai's "Tenant ID").
        max_assertion_age: Seconds an assertion is accepted for after its
                           ``iat``, whatever its ``exp``. Default 300.
        clock_skew:        Leeway in seconds for ``exp``/``iat``. Default 60.
    """

    def __init__(self, issuer: str, tenant: Optional[str] = None, max_assertion_age: int = 300, clock_skew: int = 60):
        if not issuer:
            raise ValueError("ManagedSignIn requires issuer")
        _require_secure_url(issuer, "ManagedSignIn issuer")
        if tenant is not None and (not isinstance(tenant, str) or not tenant):
            raise ValueError("ManagedSignIn tenant must be a non-empty string when given")
        self.issuer = issuer
        self.tenant = tenant
        self.max_assertion_age = max_assertion_age
        self.clock_skew = clock_skew
        self._metadata: Optional[dict] = None
        self._metadata_fetched_at = 0.0
        self._metadata_retry_after = 0.0
        self._jwks: Optional[dict] = None
        self._jwks_fetched_at = 0.0
        self._jwks_retry_after = 0.0
        self._admin_token: Optional[str] = None
        self._admin_token_expires_at = 0.0

    # --- HTTP (the one seam tests replace) ---

    def fetch_json(self, url: str, form: Optional[dict] = None, headers: Optional[dict] = None, allow_list: bool = False):
        return _http_json(url, form, headers, allow_list=allow_list)

    async def _fetch(self, url: str, form: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
        result = await asyncio.to_thread(self.fetch_json, url, form, headers, False)
        if not isinstance(result, dict):
            raise IdentityError(f"response from {url} is not a JSON object", error="server_error")
        return result

    async def _fetch_list(self, url: str, headers: Optional[dict] = None) -> list:
        result = await asyncio.to_thread(self.fetch_json, url, None, headers, True)
        if not isinstance(result, list):
            raise IdentityError(f"response from {url} is not a JSON array", error="server_error")
        return result

    # --- The issuer's keys ---

    async def _issuer_metadata(self) -> dict:
        now = time.time()
        if self._metadata is not None and (
            now - self._metadata_fetched_at < _DISCOVERY_TTL or now < self._metadata_retry_after
        ):
            return self._metadata
        try:
            document = await self._fetch(self.issuer.rstrip("/") + "/.well-known/openid-configuration")
            if document.get("issuer") != self.issuer:
                raise IdentityError(
                    f"assertion issuer discovery names {document.get('issuer')!r}, not {self.issuer!r}",
                    error="server_error",
                )
            jwks_uri = document.get("jwks_uri")
            if not isinstance(jwks_uri, str):
                raise IdentityError("assertion issuer discovery lacks jwks_uri", error="server_error")
            try:
                _require_secure_url(jwks_uri, "assertion issuer jwks_uri")
            except ValueError as exc:
                raise IdentityError(str(exc), error="server_error") from exc
        except IdentityError as exc:
            if self._metadata is None:
                raise
            self._metadata_retry_after = now + _REFRESH_BACKOFF
            logger.warning("assertion issuer discovery refresh failed, keeping the cached document: %s", exc)
            return self._metadata
        self._metadata = document
        self._metadata_fetched_at = time.time()
        return document

    async def _signing_key(self, kid: Optional[str], kty: str) -> dict:
        now = time.time()
        age = now - self._jwks_fetched_at
        if self._jwks is None or (now >= self._jwks_retry_after and (
            age >= _JWKS_TTL
            or (IdentityProvider._find_jwk(self._jwks, kid, kty) is None and age >= _JWKS_REFETCH_INTERVAL)
        )):
            try:
                self._jwks = await self._fetch((await self._issuer_metadata())["jwks_uri"])
                self._jwks_fetched_at = now
            except IdentityError:
                if self._jwks is None:
                    raise
                self._jwks_retry_after = now + _REFRESH_BACKOFF
                logger.warning("assertion issuer JWKS refresh failed, keeping the cached keys.")
        jwk = IdentityProvider._find_jwk(self._jwks or {}, kid, kty)
        if jwk is None:
            raise IdentityError(f"no assertion issuer signing key matches kid {kid!r}")
        return jwk

    # --- The assertion ---

    async def verify_assertion(self, assertion: str, audience: str, client_id: str) -> dict:
        """Verify an ID-JAG for ``audience`` (origo's issuer) presented by
        ``client_id``; return its claims. Raises IdentityError: ``error`` is
        ``access_denied`` for a bad assertion, ``server_error`` when the
        issuer's keys could not be fetched."""
        if not isinstance(assertion, str) or assertion.count(".") != 2:
            raise IdentityError("assertion is not a compact JWS")
        header_b64, payload_b64, signature_b64 = assertion.split(".")
        try:
            header = json.loads(_b64url_decode(header_b64))
            claims = json.loads(_b64url_decode(payload_b64))
            signature = _b64url_decode(signature_b64)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise IdentityError("assertion is not a well-formed JWS") from exc
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise IdentityError("assertion header or payload is not a JSON object")

        # RFC 8725 §3.11: explicit typing keeps an id_token or access token
        # from the same issuer from being replayed here as an ID-JAG.
        typ = header.get("typ")
        if not isinstance(typ, str) or typ.lower() != ID_JAG_TYP:
            raise IdentityError(f"assertion typ {typ!r} is not {ID_JAG_TYP!r}")
        alg = header.get("alg")
        if alg not in _ALGORITHMS:
            raise IdentityError(f"assertion alg {alg!r} is not accepted")
        if "crit" in header:
            raise IdentityError("assertion carries crit header parameters origo does not understand")

        # The issuer is checked before any key is fetched for it: an assertion
        # naming another issuer must not make origo fetch anything.
        if claims.get("iss") != self.issuer:
            raise IdentityError(f"assertion iss {claims.get('iss')!r} is not the trusted issuer")

        family = _ALGORITHMS[alg][0]
        kid = header.get("kid")
        jwk = await self._signing_key(kid if isinstance(kid, str) else None, "EC" if family == "EC" else "RSA")
        _verify_jws_signature(header_b64, payload_b64, signature, alg, jwk, "assertion")

        aud = claims.get("aud")
        if not (aud == audience or (isinstance(aud, list) and aud == [audience])):
            raise IdentityError(f"assertion aud {aud!r} is not {audience!r}")
        if claims.get("client_id") != client_id:
            raise IdentityError(f"assertion client_id {claims.get('client_id')!r} is not the calling client")

        now = time.time()
        exp, iat = _number(claims.get("exp"), "exp"), _number(claims.get("iat"), "iat")
        if exp + self.clock_skew < now:
            raise IdentityError("assertion is expired")
        if iat - self.clock_skew > now:
            raise IdentityError("assertion iat is in the future")
        if now - iat > self.max_assertion_age + self.clock_skew:
            raise IdentityError("assertion is older than max_assertion_age")
        nbf = claims.get("nbf")
        if nbf is not None and (not isinstance(nbf, (int, float)) or nbf - self.clock_skew > now):
            raise IdentityError("assertion is not valid yet (nbf)")

        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti or len(jti) > _MAX_JTI_LENGTH:
            raise IdentityError("assertion has no usable jti")
        if self.tenant is not None and claims.get("aud_tenant") != self.tenant:
            raise IdentityError(f"assertion aud_tenant {claims.get('aud_tenant')!r} is not the configured tenant")
        for name in ("sub", "email"):
            if not isinstance(claims.get(name), str) or not claims[name]:
                raise IdentityError(f"assertion has no {name}")
        return claims

    def replay_key(self, claims: dict) -> tuple[str, float]:
        """Storage key and lifetime (seconds) that make claims' jti single-use."""
        ttl = max(float(claims["exp"]) - time.time(), 0.0) + self.clock_skew
        return f"idjag-jti:{self.issuer}|{claims['jti']}", ttl

    # --- The person, from Keycloak ---

    async def resolve(self, identity_provider: IdentityProvider, email: str) -> dict:
        """origo's claims for the one enabled Keycloak user with this verified
        email, gate applied. Raises IdentityRefused when there is no such user
        (or more than one), IdentityError(server_error) when Keycloak could not
        be asked."""
        admin = _keycloak_admin_base(identity_provider.issuer)
        token = await self._admin_access_token(identity_provider)
        auth = {"Authorization": f"Bearer {token}"}
        query = urlencode({"email": email, "exact": "true", "briefRepresentation": "false"})
        users = await self._fetch_list(f"{admin}/users?{query}", headers=auth)
        matches = [
            u for u in users
            if isinstance(u, dict)
            and u.get("enabled") is True
            and u.get("emailVerified") is True
            and isinstance(u.get("email"), str)
            and u["email"].lower() == email.lower()
            and isinstance(u.get("id"), str) and u["id"]
        ]
        if len(matches) != 1:
            raise IdentityRefused(f"no single enabled Keycloak user with verified email {email!r} ({len(matches)} found)")
        user = matches[0]
        groups = await self._fetch_list(f"{admin}/users/{quote(user['id'], safe='')}/groups", headers=auth)
        # Both the name and the full path: Keycloak's group mapper emits one
        # or the other ("Full group path"), and the gate's allowed_groups is
        # written for whichever the realm uses. A name alone is what the
        # mapper emits for a nested group without the full path too.
        names: list[str] = []
        for group in groups:
            if isinstance(group, dict):
                for key in ("path", "name"):
                    value = group.get(key)
                    if isinstance(value, str) and value and value not in names:
                        names.append(value)
        name = " ".join(p for p in (user.get("firstName"), user.get("lastName")) if isinstance(p, str) and p)
        upstream = {"sub": user["id"], "email": user["email"], "email_verified": True, "groups": names}
        if name:
            upstream["name"] = name
        identity = identity_provider.map_claims(upstream)
        identity_provider.check_gate(identity, upstream)
        return identity

    async def _admin_access_token(self, identity_provider: IdentityProvider) -> str:
        if self._admin_token is not None and time.time() < self._admin_token_expires_at:
            return self._admin_token
        response = await identity_provider._token_request({"grant_type": "client_credentials"})
        token = response.get("access_token")
        if not isinstance(token, str) or not token:
            raise IdentityError("Keycloak issued no service-account access token", error="server_error")
        expires_in = response.get("expires_in")
        lifetime = expires_in if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool) else 60
        self._admin_token = token
        self._admin_token_expires_at = time.time() + max(lifetime - 30, 0)
        return token


def _number(value, name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise IdentityError(f"assertion has no numeric {name}")
    return float(value)


def _keycloak_admin_base(issuer: str) -> str:
    """``https://host/realms/r`` -> ``https://host/admin/realms/r``."""
    marker = "/realms/"
    if issuer.count(marker) != 1:
        raise IdentityError(f"identity provider issuer {issuer!r} is not a Keycloak realm URL", error="server_error")
    host, realm = issuer.split(marker)
    return f"{host}/admin/realms/{realm.rstrip('/')}"
