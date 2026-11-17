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

The Keycloak lookup uses origo's own client at the IdP (client credentials)
by default, so no new secret: that client needs "Service accounts" enabled
and the realm-management role ``view-users``. Where that client's secret is
shared with something that should not read the realm, a separate directory
client (``directory_client_id`` and its secret) makes the lookups instead,
and the read roles go to its service account. Two opt-in lookups make the managed
upstream carry what a realm's other mappers put in an interactive id_token:
``client_roles_claim`` (the IdP client's effective client roles; needs
``view-clients`` too, since Keycloak 26 answers a role-mapping read for a
client it may not view with an empty list, not an error) and
``organizations_claim`` (the person's Organizations; needs
``view-organizations``). Both fail closed: a lookup that cannot be made or
read is ``server_error``, never "none".
"""

import asyncio
import base64
import json
import logging
import math
import os
import time
from typing import Optional
from urllib.parse import quote, urlencode, urlparse

from .oidc import (
    _ALGORITHMS,
    IdentityError,
    IdentityProvider,
    IdentityRefused,
    _b64url_decode,
    _form_encode,
    _http_json,
    _is_cluster_service_url,
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
        group_paths:       Emit the person's groups as full paths (``/a/b``)
                           rather than names (``b``): set it to match the
                           realm's group mapper "Full group path", so the
                           groups (and the allow gate) are exactly what an
                           interactive sign-in gets. Default False (names).
        directory_url:     Where origo reaches Keycloak's admin API for the
                           lookup, when that is not the issuer's host: a
                           Keycloak that exposes only /realms publicly (the
                           admin API inside the cluster only) is reached at
                           its Service, e.g.
                           ``http://keycloak.keycloak.svc.cluster.local:8080``.
                           https, or plain http to a ``*.svc.cluster.local``
                           name only. Default: the
                           ``ORIGO_MANAGED_SIGNIN_DIRECTORY_URL`` environment
                           variable, else the issuer's own host.
        client_roles_claim: Put the person's effective client roles in the
                           identity provider's own client (``client_id``:
                           direct, through groups and through composites) at
                           this claim, a dotted path, as a list of role names:
                           what a realm's client-role mapper emits, e.g.
                           ``resource_access.my-mcp.roles``. Point the
                           identity provider's ``groups_claim`` at it to gate
                           on those roles. Omitted when the person has none,
                           as the mapper omits it. A
                           ``resource_access.<client>.roles`` path must name
                           the identity provider's own client. Default None
                           (not looked up).
        organizations_claim: Put the person's Organizations at this claim
                           (a dotted path) as ``{alias: {"id": id}}``, the
                           shape of the realm's organization-membership
                           mapper with "Add organization id" on, for a gate
                           that reads it (``check_gate``'s ``claims``): name
                           exactly the claim that gate reads, or it sees none.
                           Needs Organizations enabled on the realm.
                           Stricter than the mapper: a disabled Organization
                           counts too. Omitted when there are none. An
                           Organization without a readable alias and id fails
                           the sign-in (``server_error``) rather than being
                           skipped. Default None (not looked up).
        directory_client_id: A separate Keycloak client whose
                           client-credentials token makes the admin-API
                           lookups, instead of the identity provider's own
                           client: give it (a service account only) the read
                           roles, and the identity provider's client needs
                           none. Its token comes from the identity provider's
                           token endpoint. The roles read for
                           ``client_roles_claim`` stay the identity provider's
                           client's. Default: the
                           ``ORIGO_MANAGED_SIGNIN_DIRECTORY_CLIENT_ID``
                           environment variable, else None (the identity
                           provider's client).
        directory_client_secret: Its secret.
        directory_client_secret_file: Or a file holding it, read on each
                           token fetch (so a rotated secret is picked up
                           without a restart; unreadable or empty fails the
                           sign-in with ``server_error``). Exactly one of the
                           two with ``directory_client_id``, neither without.
                           Default: the
                           ``ORIGO_MANAGED_SIGNIN_DIRECTORY_CLIENT_SECRET_FILE``
                           environment variable. The environment is read
                           only when none of the three is given here.
                           The directory client authenticates with
                           client_secret_basic, and its token request goes
                           through this object's ``fetch_json``, not the
                           identity provider's.

    Assertions are not sender-constrained: claude.ai's client is public
    (``token_endpoint_auth_method: none``) and the issuer does not bind them
    (no ``cnf``), so a leaked assertion could be redeemed once by anyone
    within its lifetime. The window is ``max_assertion_age`` and the ``jti``
    is single-use. An assertion that does carry ``cnf`` is refused, since
    origo cannot verify the binding it asks for.
    """

    def __init__(self, issuer: str, tenant: Optional[str] = None, max_assertion_age: int = 300, clock_skew: int = 60,
                 group_paths: bool = False, directory_url: Optional[str] = None,
                 client_roles_claim: Optional[str] = None, organizations_claim: Optional[str] = None,
                 directory_client_id: Optional[str] = None, directory_client_secret: Optional[str] = None,
                 directory_client_secret_file: Optional[str] = None):
        if not issuer:
            raise ValueError("ManagedSignIn requires issuer")
        _require_secure_url(issuer, "ManagedSignIn issuer")
        if tenant is not None and (not isinstance(tenant, str) or not tenant):
            raise ValueError("ManagedSignIn tenant must be a non-empty string when given")
        self.issuer = issuer
        self.tenant = tenant
        self.max_assertion_age = max_assertion_age
        self.clock_skew = clock_skew
        self.group_paths = bool(group_paths)
        if directory_url is None:
            directory_url = os.environ.get("ORIGO_MANAGED_SIGNIN_DIRECTORY_URL", "").strip() or None
        if directory_url is not None:
            directory_url = directory_url.rstrip("/")
            if not _is_cluster_service_url(directory_url):
                _require_secure_url(directory_url, "ManagedSignIn directory_url")
            if urlparse(directory_url).path not in ("", "/") or urlparse(directory_url).query:
                raise ValueError("ManagedSignIn directory_url is a scheme, host and port only")
        self.directory_url = directory_url
        if directory_client_id is None and directory_client_secret is None and directory_client_secret_file is None:
            # The environment fills in a directory client as a whole, never
            # half of one given here.
            directory_client_id = os.environ.get("ORIGO_MANAGED_SIGNIN_DIRECTORY_CLIENT_ID", "").strip() or None
            directory_client_secret_file = (
                os.environ.get("ORIGO_MANAGED_SIGNIN_DIRECTORY_CLIENT_SECRET_FILE", "").strip() or None
            )
        for value, name in ((directory_client_id, "directory_client_id"),
                            (directory_client_secret, "directory_client_secret"),
                            (directory_client_secret_file, "directory_client_secret_file")):
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"ManagedSignIn {name} must be a non-empty string when given")
        if directory_client_secret is not None and directory_client_secret_file is not None:
            raise ValueError("ManagedSignIn takes directory_client_secret or directory_client_secret_file, not both")
        has_secret = directory_client_secret is not None or directory_client_secret_file is not None
        if (directory_client_id is None) != (not has_secret):
            # Half a directory client would quietly fall back to the identity
            # provider's client, the one it exists to keep the reads off.
            raise ValueError("ManagedSignIn directory_client_id and its secret are given together or not at all")
        self.directory_client_id = directory_client_id
        self._directory_client_secret = directory_client_secret
        self.directory_client_secret_file = directory_client_secret_file
        self.client_roles_claim = client_roles_claim
        self.organizations_claim = organizations_claim
        self._client_roles_path = _upstream_claim_path(client_roles_claim, "client_roles_claim")
        self._organizations_path = _upstream_claim_path(organizations_claim, "organizations_claim")
        a, b = self._client_roles_path, self._organizations_path
        if a and b and (a[: len(b)] == b or b[: len(a)] == a):
            raise ValueError("ManagedSignIn client_roles_claim and organizations_claim overlap")
        self._client_uuids: dict[tuple[str, str], str] = {}
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
        in_directory = self.directory_url is not None and url.startswith(self.directory_url + "/")
        return _http_json(url, form, headers, allow_list=allow_list, allow_cluster_http=in_directory)

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
        if not isinstance(alg, str) or alg not in _ALGORITHMS:
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
        # Matched exactly against Keycloak's stored (lowercased) email: ASCII
        # only, so no Unicode case folding (the Kelvin sign) can make two
        # addresses equal.
        if not claims["email"].isascii() or "@" not in claims["email"]:
            raise IdentityError("assertion email is not a plain ASCII address")
        if "cnf" in claims:
            raise IdentityError("assertion is sender-constrained (cnf), which origo cannot verify")
        return claims

    def replay_key(self, claims: dict) -> tuple[str, float]:
        """Storage key and lifetime (seconds) that make claims' jti single-use."""
        # Capped: an assertion is accepted for at most max_assertion_age past
        # its iat, so the record need not outlive that whatever exp says.
        ttl = min(max(float(claims["exp"]) - time.time(), 0.0), float(self.max_assertion_age)) + 2 * self.clock_skew
        return f"idjag-jti:{self.issuer}|{claims['jti']}", ttl

    # --- The person, from Keycloak ---

    async def resolve(self, identity_provider: IdentityProvider, email: str) -> dict:
        """origo's claims for the one enabled Keycloak user with this verified
        email, gate applied. Raises IdentityRefused when there is no such user
        (or more than one), IdentityError(server_error) when Keycloak could not
        be asked."""
        admin = _keycloak_admin_base(identity_provider.issuer, self.directory_url)
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
            and u["email"] == email.lower()
            # A sign-in Keycloak would stop at a required action (verify
            # email, set up OTP, new password, terms) is not issued here.
            and not u.get("requiredActions")
            and isinstance(u.get("id"), str) and u["id"]
        ]
        if len(matches) != 1:
            raise IdentityRefused(f"no single enabled Keycloak user with verified email {email!r} ({len(matches)} found)")
        user = matches[0]
        # A temporary brute-force lockout leaves the user enabled.
        status = await self._fetch(f"{admin}/attack-detection/brute-force/users/{quote(user['id'], safe='')}", headers=auth)
        if status.get("disabled") is not False:
            raise IdentityRefused(f"Keycloak user {user['id']!r} is locked out (brute-force detection)")
        groups = await self._fetch_list(f"{admin}/users/{quote(user['id'], safe='')}/groups", headers=auth)
        # One form, the one the realm's group mapper emits (group_paths), so
        # the groups are exactly an interactive sign-in's.
        key = "path" if self.group_paths else "name"
        names: list[str] = []
        for group in groups:
            value = group.get(key) if isinstance(group, dict) else None
            if isinstance(value, str) and value and value not in names:
                names.append(value)
        name = " ".join(p for p in (user.get("firstName"), user.get("lastName")) if isinstance(p, str) and p)
        upstream = {"sub": user["id"], "email": user["email"], "email_verified": True, "groups": names}
        if name:
            upstream["name"] = name
        if self._client_roles_path:
            path = self._client_roles_path
            if (len(path) == 3 and path[0] == "resource_access" and path[2] == "roles"
                    and path[1] != identity_provider.client_id):
                # The roles are always the identity provider's own client's:
                # filed under another client's name, a gate on that client
                # would admit people for roles they hold elsewhere.
                raise IdentityError(
                    f"client_roles_claim {self.client_roles_claim!r} names another client than "
                    f"{identity_provider.client_id!r}, whose roles it would carry",
                    error="server_error",
                )
            roles = await self._client_roles(admin, auth, identity_provider.client_id, user["id"])
            if roles:
                _put_claim(upstream, self._client_roles_path, roles)
        if self._organizations_path:
            organizations = await self._organizations(admin, auth, user["id"])
            if organizations:
                _put_claim(upstream, self._organizations_path, organizations)
        identity = identity_provider.map_claims(upstream)
        identity_provider.check_gate(identity, upstream)
        return identity

    async def _client_roles(self, admin: str, auth: dict, client_id: str, user_id: str) -> list[str]:
        """The user's effective roles in ``client_id``, as Keycloak's
        client-role mapper would emit them."""
        client_uuid = self._client_uuids.get((admin, client_id))
        if client_uuid is None:
            # Exactly one exact match, or no roles can be read at all. Without
            # view-clients Keycloak answers 403 here (or [] under
            # query-clients) and the role read below would quietly be [].
            query = urlencode({"clientId": client_id})
            found = [
                c for c in await self._fetch_list(f"{admin}/clients?{query}", headers=auth)
                if isinstance(c, dict) and c.get("clientId") == client_id
                and isinstance(c.get("id"), str) and c["id"]
            ]
            if len(found) != 1:
                raise IdentityError(
                    f"Keycloak client {client_id!r} not readable for the role lookup ({len(found)} found;"
                    " the service account needs realm-management view-clients)",
                    error="server_error",
                )
            client_uuid = found[0]["id"]
            self._client_uuids[(admin, client_id)] = client_uuid
        try:
            mappings = await self._fetch_list(
                f"{admin}/users/{quote(user_id, safe='')}/role-mappings/clients/{quote(client_uuid, safe='')}/composite",
                headers=auth,
            )
        except IdentityError:
            # A client recreated under a new id (or a realm re-import) answers
            # 404 here: look it up again next time rather than fail forever.
            self._client_uuids.pop((admin, client_id), None)
            raise
        roles: list[str] = []
        for role in mappings:
            value = role.get("name") if isinstance(role, dict) else None
            if isinstance(value, str) and value and value not in roles:
                roles.append(value)
        return roles

    async def _organizations(self, admin: str, auth: dict, user_id: str) -> dict:
        """The user's Organizations as ``{alias: {"id": id}}``. Every entry
        must be readable: one that is not fails the sign-in, so a gate that
        refuses members of any Organization never sees fewer than there are."""
        entries = await self._fetch_list(
            f"{admin}/organizations/members/{quote(user_id, safe='')}/organizations?briefRepresentation=true",
            headers=auth,
        )
        organizations: dict = {}
        for entry in entries:
            alias = entry.get("alias") if isinstance(entry, dict) else None
            org_id = entry.get("id") if isinstance(entry, dict) else None
            if not (isinstance(alias, str) and alias and isinstance(org_id, str) and org_id):
                raise IdentityError(
                    f"Keycloak returned an unreadable Organization for user {user_id!r}", error="server_error"
                )
            organizations[alias] = {"id": org_id}
        return organizations

    async def _admin_access_token(self, identity_provider: IdentityProvider) -> str:
        if self._admin_token is not None and time.time() < self._admin_token_expires_at:
            return self._admin_token
        if self.directory_client_id is None:
            response = await identity_provider._token_request({"grant_type": "client_credentials"})
        else:
            response = await self._directory_token_request(identity_provider)
        token = response.get("access_token")
        if not isinstance(token, str) or not token:
            raise IdentityError("Keycloak issued no service-account access token", error="server_error")
        expires_in = response.get("expires_in")
        lifetime = expires_in if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool) else 60
        self._admin_token = token
        self._admin_token_expires_at = time.time() + max(lifetime - 30, 0)
        return token

    async def _directory_token_request(self, identity_provider: IdentityProvider) -> dict:
        """The directory client's client-credentials grant at the identity
        provider's token endpoint. Never carries the identity provider's own
        client credentials."""
        secret = self._directory_client_secret
        if secret is None:
            try:
                with open(self.directory_client_secret_file, encoding="utf-8") as f:
                    secret = f.read().strip()
            except OSError as exc:
                raise IdentityError(
                    f"directory client secret file unreadable: {exc.strerror or type(exc).__name__}",
                    error="server_error",
                ) from exc
            if not secret:
                raise IdentityError("directory client secret file is empty", error="server_error")
        endpoint = (await identity_provider.metadata())["token_endpoint"]
        # RFC 6749 §2.3.1: both halves form-urlencoded before being joined.
        pair = f"{_form_encode(self.directory_client_id)}:{_form_encode(secret)}"
        headers = {"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()}
        form = {"grant_type": "client_credentials", "client_id": self.directory_client_id}
        return await self._fetch(endpoint, form=form, headers=headers)


def _number(value, name: str) -> float:
    # NaN and Infinity parse as JSON numbers in Python and compare False with
    # everything: they would pass every time check.
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise IdentityError(f"assertion has no finite numeric {name}")
    return float(value)


# The claims resolve() builds itself: an opt-in lookup may not overwrite them.
_RESERVED_UPSTREAM_CLAIMS = frozenset({"sub", "email", "email_verified", "name", "groups"})


def _upstream_claim_path(value: Optional[str], name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, str) or not value:
        raise ValueError(f"ManagedSignIn {name} must be a non-empty string when given")
    parts = tuple(value.split("."))
    if any(not part for part in parts):
        raise ValueError(f"ManagedSignIn {name} {value!r} has an empty segment")
    if parts[0] in _RESERVED_UPSTREAM_CLAIMS:
        raise ValueError(f"ManagedSignIn {name} may not be under {parts[0]!r}, which origo sets itself")
    return parts


def _put_claim(claims: dict, path: tuple[str, ...], value) -> None:
    target = claims
    for part in path[:-1]:
        target = target.setdefault(part, {})
    target[path[-1]] = value


def _keycloak_admin_base(issuer: str, directory_url: Optional[str] = None) -> str:
    """``https://host/realms/r`` -> ``https://host/admin/realms/r``, or
    ``<directory_url>/admin/realms/r`` when one is configured."""
    marker = "/realms/"
    if issuer.count(marker) != 1:
        raise IdentityError(f"identity provider issuer {issuer!r} is not a Keycloak realm URL", error="server_error")
    host, realm = issuer.split(marker)
    return f"{directory_url or host}/admin/realms/{realm.rstrip('/')}"
