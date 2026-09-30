import hmac
import secrets
import time
import warnings
from typing import Optional
from collections import deque


def _now() -> float:
    return time.time()


class FamilyRevokedError(Exception):
    """Raised when issuing a token into a family that has been revoked.

    Revocation and issuance can race: one caller can be between "exchange the
    refresh token" and "mint the replacements" while another caller's replay
    of a stolen token revokes the family. The revoked-family marker makes the
    losing side of that race fail here instead of issuing live tokens into a
    dead family.
    """


# Sentinel accepted as a client's entire redirect-URI allowlist (the bare
# string or a single-element list) to opt that client out of exact redirect
# URI matching. Restricted to pre-seeded clients holding a real secret: the
# secret still gates /token, so a leaked auth code alone stays unusable, but
# this does remove the exact-match layer of defense (RFC 9700 §2.1) and makes
# /authorize an open redirector to any https URL for whoever knows the public
# client_id. Opt in per client, and only where that trade is understood —
# e.g. single-operator deployments facing connectors (ChatGPT, Grok, ...)
# whose callback URLs are undocumented or churn. Scheme validation still
# applies at /authorize: only https (or loopback http / explicitly declared
# custom schemes) is ever accepted.
ANY_REDIRECT_URI = "any"


def _secret_matches(stored: str, presented: str) -> bool:
    try:
        if not isinstance(stored, str) or not isinstance(presented, str):
            return False
        return hmac.compare_digest(stored.encode("utf-8"), presented.encode("utf-8"))
    except Exception:
        return False


def _resolve_seed_redirect_uris(client_id: str, secret: Optional[str], value) -> tuple[set, bool]:
    """Normalize one seeded client's redirect_uris value to (allowlist, allow_any).

    Shared by both storage backends so the sentinel's guard rails cannot
    drift between them. Raises instead of warning: every rejected shape here
    is a config error that would otherwise become a silent security downgrade
    (a bare non-sentinel string iterates into a set of characters; a
    secret-less wildcard client would let anyone who knows the public
    client_id mint tokens at /token).
    """
    if value is None:
        return set(), False
    if isinstance(value, str):
        if value != ANY_REDIRECT_URI:
            raise TypeError(
                f"client_redirect_uris[{client_id!r}] is the string {value!r}; expected a "
                f"list of redirect URIs, or the sentinel {ANY_REDIRECT_URI!r} to disable "
                "exact redirect URI matching for this client."
            )
        allow_any = True
        uris: set = set()
    else:
        uris = set(value)
        allow_any = ANY_REDIRECT_URI in uris
        if allow_any and len(uris) > 1:
            raise ValueError(
                f"client_redirect_uris[{client_id!r}] mixes the {ANY_REDIRECT_URI!r} "
                "sentinel with explicit redirect URIs. The sentinel must be the entire "
                "allowlist — mixing the two shapes makes it ambiguous whether the "
                "explicit URIs were meant as a restriction."
            )
        if allow_any:
            uris = set()
    if allow_any and not secret:
        raise ValueError(
            f"client_redirect_uris[{client_id!r}] uses the {ANY_REDIRECT_URI!r} sentinel "
            "but the client has no secret. Without exact redirect URI matching the "
            "client secret is the only thing keeping a leaked authorization code "
            "unusable at /token, so the sentinel requires a confidential client."
        )
    return uris, allow_any


class OAuthStorage:
    def __init__(
        self,
        token_ttl: int = 3600,
        refresh_token_ttl: int = 30 * 24 * 3600,
        client_ttl: Optional[int] = None,
        max_dynamic_clients: int = 1000,
    ):
        self.token_ttl = token_ttl
        self.refresh_token_ttl = refresh_token_ttl
        self.client_ttl = client_ttl
        self.max_dynamic_clients = max_dynamic_clients
        self._dynamic_clients_count = 0
        self._clients: dict[str, dict] = {}        # client_id -> {secret, redirect_uris, token_endpoint_auth_method}
        self._codes: dict[str, dict] = {}          # code -> metadata
        self._tokens: dict[str, dict] = {}         # token -> metadata
        self._refresh_tokens: dict[str, dict] = {}  # refresh_token -> metadata
        # Rotated-out refresh tokens, kept so a replay can be recognized as
        # reuse (theft signal) and the whole token family revoked, per the
        # OAuth 2.1 refresh-token rotation guidance.
        self._consumed_refresh_tokens: dict[str, dict] = {}  # refresh_token -> {family, retain_until}
        self._revoked_families: dict[str, float] = {}  # family -> retain_until
        self._clients_expiry: deque = deque()
        self._codes_expiry: deque = deque()
        self._tokens_expiry: deque = deque()
        self._refresh_tokens_expiry: deque = deque()
        self._consumed_refresh_expiry: deque = deque()
        self._revoked_families_expiry: deque = deque()

    # --- Clients ---

    def seed_clients(self, clients: dict[str, str], redirect_uris: Optional[dict[str, list]] = None) -> None:
        """Seed pre-registered clients. A client seeded with an empty redirect_uris
        list fails closed: is_redirect_uri_allowed() will reject every redirect_uri
        for it, so it cannot complete /authorize until explicit URIs are configured.
        A confidential client may instead be seeded with the ANY_REDIRECT_URI
        sentinel as its entire allowlist to opt out of exact matching (see the
        sentinel's own comment for the trade-off)."""
        redirect_uris = redirect_uris or {}
        if clients and not any(redirect_uris.values()):
            warnings.warn(
                "OAuthProvider: clients seeded with no redirect_uris — "
                "they will reject every redirect_uri at /authorize (fail closed). "
                "Specify allowed URIs in production.",
                UserWarning,
                stacklevel=3,
            )
        for client_id, secret in clients.items():
            allowed_redirect_uris, allow_any = _resolve_seed_redirect_uris(
                client_id, secret, redirect_uris.get(client_id)
            )

            existing = self._clients.get(client_id)
            if existing and existing.get("registered_at") is not None:
                self._dynamic_clients_count -= 1

            self._clients[client_id] = {
                "secret": secret,
                "redirect_uris": allowed_redirect_uris,
                "allow_any_redirect_uri": allow_any,
                "token_endpoint_auth_method": "client_secret_post",
                "client_metadata": {},
                "registered_at": None,  # pre-seeded clients are permanent, not subject to eviction/TTL
            }
            if not allowed_redirect_uris and not allow_any:
                warnings.warn(
                    f"OAuthProvider: client '{client_id}' seeded with no redirect_uris — "
                    "it will reject every redirect_uri at /authorize (fail closed). "
                    "Specify allowed URIs to make it usable.",
                    UserWarning,
                    stacklevel=2,
                )

    def register_client(
        self,
        client_id: str,
        client_secret: Optional[str],
        redirect_uris: list[str] = (),
        token_endpoint_auth_method: str = "client_secret_post",
        client_metadata: Optional[dict] = None,
    ) -> None:
        """Dynamically register a new client (public mode, DCR or CIMD)."""
        self._cleanup_expired()

        existing = self._clients.get(client_id)
        is_existing_dynamic = existing is not None and existing.get("registered_at") is not None

        if not is_existing_dynamic and self._dynamic_clients_count >= self.max_dynamic_clients:
            raise ValueError("Maximum number of dynamic clients reached")

        registered_at = _now()

        if not is_existing_dynamic:
            self._dynamic_clients_count += 1

        self._clients[client_id] = {
            "secret": client_secret,
            "redirect_uris": set(redirect_uris),
            "token_endpoint_auth_method": token_endpoint_auth_method,
            "client_metadata": client_metadata or {},
            "registered_at": registered_at,
        }
        if self.client_ttl is not None:
            self._clients_expiry.append((client_id, registered_at + self.client_ttl))

    def _get_client(self, client_id: str) -> Optional[dict]:
        """Return client entry if present and unexpired, evicting it (and returning None) if its TTL has elapsed."""
        entry = self._clients.get(client_id)
        if entry is None:
            return None
        if (
            self.client_ttl is not None
            and entry["registered_at"] is not None
            and _now() - entry["registered_at"] > self.client_ttl
        ):
            self._clients.pop(client_id, None)
            self._dynamic_clients_count -= 1
            return None
        return entry

    def get_client_secret(self, client_id: str) -> Optional[str]:
        entry = self._get_client(client_id)
        return entry["secret"] if entry else None

    def verify_client_secret(self, client_id: str, client_secret: str) -> bool:
        """Constant-time check of a presented client_secret. False for unknown
        clients and for public (secret-less) clients."""
        entry = self._get_client(client_id)
        if entry is None or entry["secret"] is None:
            return False
        return _secret_matches(entry["secret"], client_secret)

    def get_client_auth_method(self, client_id: str) -> Optional[str]:
        entry = self._get_client(client_id)
        return entry.get("token_endpoint_auth_method", "client_secret_post") if entry else None

    def get_client_metadata(self, client_id: str) -> Optional[dict]:
        entry = self._get_client(client_id)
        return entry.get("client_metadata", {}) if entry else None

    def client_exists(self, client_id: str) -> bool:
        return self._get_client(client_id) is not None

    def is_redirect_uri_allowed(self, client_id: str, redirect_uri: str) -> bool:
        """Return True if redirect_uri is exactly on the client's allowlist.

        Fails closed: a client whose redirect_uris list is empty (e.g. seeded
        without explicit URIs) has no allowlist to match against, so every
        redirect_uri is rejected for it. The one deliberate escape hatch is
        the ANY_REDIRECT_URI seeding sentinel, surfaced separately via
        allows_any_redirect_uri() so /authorize can keep scheme validation in
        front of it — this method itself never wildcards.
        """
        entry = self._get_client(client_id)
        if entry is None:
            return False
        allowed = entry["redirect_uris"]
        return bool(allowed and redirect_uri in allowed)

    def allows_any_redirect_uri(self, client_id: str) -> bool:
        """True if the client was seeded with the ANY_REDIRECT_URI sentinel.

        Restricted to pre-seeded confidential clients: seeding is the only
        code path that sets the flag, but the registered_at/secret conditions
        are re-checked here anyway so a future registration path that copies
        entries around cannot silently widen a dynamic or secret-less client.
        """
        entry = self._get_client(client_id)
        return bool(
            entry is not None
            and entry.get("allow_any_redirect_uri")
            and entry.get("registered_at") is None
            and entry.get("secret")
        )

    # --- Auth codes ---

    def _cleanup_expired(self) -> None:
        now = _now()

        # Clean up codes
        while self._codes_expiry and self._codes_expiry[0][1] <= now:
            k, exp = self._codes_expiry.popleft()
            if k in self._codes and self._codes[k]["expires_at"] == exp:
                del self._codes[k]

        # Clean up tokens
        while self._tokens_expiry and self._tokens_expiry[0][1] <= now:
            k, exp = self._tokens_expiry.popleft()
            if k in self._tokens and self._tokens[k]["expires_at"] == exp:
                del self._tokens[k]

        # Clean up refresh tokens
        while self._refresh_tokens_expiry and self._refresh_tokens_expiry[0][1] <= now:
            k, exp = self._refresh_tokens_expiry.popleft()
            if k in self._refresh_tokens and self._refresh_tokens[k]["expires_at"] == exp:
                del self._refresh_tokens[k]

        # Clean up consumed-refresh-token markers
        while self._consumed_refresh_expiry and self._consumed_refresh_expiry[0][1] <= now:
            k, exp = self._consumed_refresh_expiry.popleft()
            if k in self._consumed_refresh_tokens and self._consumed_refresh_tokens[k]["retain_until"] == exp:
                del self._consumed_refresh_tokens[k]

        # Clean up revoked-family markers
        while self._revoked_families_expiry and self._revoked_families_expiry[0][1] <= now:
            k, exp = self._revoked_families_expiry.popleft()
            if self._revoked_families.get(k) == exp:
                del self._revoked_families[k]

        # Clean up clients
        if self.client_ttl is not None:
            while self._clients_expiry and self._clients_expiry[0][1] <= now:
                k, exp = self._clients_expiry.popleft()
                if k in self._clients and self._clients[k]["registered_at"] is not None:
                    # Expected expiration based on the current registration time
                    current_exp = self._clients[k]["registered_at"] + self.client_ttl
                    if current_exp == exp:
                        del self._clients[k]
                        self._dynamic_clients_count -= 1

    def store_code(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        resource: Optional[str] = None,
        scope: str = "",
    ) -> str:
        self._cleanup_expired()
        code = secrets.token_urlsafe(32)
        expires_at = _now() + 60
        self._codes[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "resource": resource,
            "scope": scope,
            "expires_at": expires_at,  # codes expire in 60 seconds
        }
        self._codes_expiry.append((code, expires_at))
        return code

    def exchange_code(self, code: str) -> Optional[dict]:
        """Return and consume a code. Returns None if missing or expired."""
        entry = self._codes.pop(code, None)
        if entry is None:
            return None
        if _now() > entry["expires_at"]:
            return None
        return entry

    # --- Tokens ---

    def store_token(self, client_id: str, resource: Optional[str] = None, scope: str = "", family: Optional[str] = None) -> str:
        self._cleanup_expired()
        if family is not None and family in self._revoked_families:
            raise FamilyRevokedError(family)
        token = secrets.token_urlsafe(48)
        expires_at = _now() + self.token_ttl
        self._tokens[token] = {
            "client_id": client_id,
            "resource": resource,
            "scope": scope,
            "expires_at": expires_at,
            "family": family,
        }
        self._tokens_expiry.append((token, expires_at))
        return token

    def verify_token(self, token: str) -> Optional[dict]:
        """Return token metadata if valid, None otherwise."""
        entry = self._tokens.get(token)
        if entry is None:
            return None
        if _now() > entry["expires_at"]:
            self._tokens.pop(token, None)
            return None
        return entry

    # --- Refresh tokens ---

    def store_refresh_token(self, client_id: str, resource: Optional[str] = None, scope: str = "", family: Optional[str] = None) -> str:
        """Store a refresh token. `family` groups a token with every token
        rotated from the same original grant; one is generated when omitted."""
        self._cleanup_expired()
        if family is not None and family in self._revoked_families:
            raise FamilyRevokedError(family)
        token = secrets.token_urlsafe(48)
        expires_at = _now() + self.refresh_token_ttl
        self._refresh_tokens[token] = {
            "client_id": client_id,
            "resource": resource,
            "scope": scope,
            "expires_at": expires_at,
            "family": family or secrets.token_urlsafe(16),
        }
        self._refresh_tokens_expiry.append((token, expires_at))
        return token

    def exchange_refresh_token(self, refresh_token: str) -> Optional[dict]:
        """Return and consume a refresh token (rotation). None if missing or expired.

        Presenting an already-consumed (rotated-out) refresh token is treated
        as evidence of theft: the entire token family — every live refresh and
        access token descended from the same grant — is revoked before None is
        returned, so neither the thief nor the victim keeps a live session.
        """
        consumed = self._consumed_refresh_tokens.get(refresh_token)
        if consumed is not None:
            self.revoke_family(consumed["family"])
            return None
        entry = self._refresh_tokens.pop(refresh_token, None)
        if entry is None:
            return None
        if _now() > entry["expires_at"]:
            return None
        # Remember the consumed token for as long as any descendant rotated
        # from it could still be alive, so a later replay still maps to its family.
        retain_until = _now() + self.refresh_token_ttl
        self._consumed_refresh_tokens[refresh_token] = {
            "family": entry["family"],
            "retain_until": retain_until,
        }
        self._consumed_refresh_expiry.append((refresh_token, retain_until))
        return entry

    def revoke_family(self, family: Optional[str]) -> None:
        """Revoke every live refresh and access token belonging to a family,
        and mark the family so no new tokens can be issued into it (closes the
        race where an in-flight refresh mints replacements after revocation)."""
        if not family:
            return
        for k in [k for k, v in self._refresh_tokens.items() if v.get("family") == family]:
            del self._refresh_tokens[k]
        for k in [k for k, v in self._tokens.items() if v.get("family") == family]:
            del self._tokens[k]
        retain_until = _now() + self.refresh_token_ttl
        self._revoked_families[family] = retain_until
        self._revoked_families_expiry.append((family, retain_until))
