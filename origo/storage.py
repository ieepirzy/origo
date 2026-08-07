import secrets
import time
import warnings
from typing import Optional
from collections import deque


def _now() -> float:
    return time.time()


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
        self._clients_expiry: deque = deque()
        self._codes_expiry: deque = deque()
        self._tokens_expiry: deque = deque()
        self._refresh_tokens_expiry: deque = deque()

    # --- Clients ---

    def seed_clients(self, clients: dict[str, str], redirect_uris: Optional[dict[str, list[str]]] = None) -> None:
        """Seed pre-registered clients. A client seeded with an empty redirect_uris
        list fails closed: is_redirect_uri_allowed() will reject every redirect_uri
        for it, so it cannot complete /authorize until explicit URIs are configured."""
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
            allowed_redirect_uris = set(redirect_uris.get(client_id, []))

            existing = self._clients.get(client_id)
            if existing and existing.get("registered_at") is not None:
                self._dynamic_clients_count -= 1

            self._clients[client_id] = {
                "secret": secret,
                "redirect_uris": allowed_redirect_uris,
                "token_endpoint_auth_method": "client_secret_post",
                "client_metadata": {},
                "registered_at": None,  # pre-seeded clients are permanent, not subject to eviction/TTL
            }
            if not allowed_redirect_uris:
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

    def get_client_auth_method(self, client_id: str) -> Optional[str]:
        entry = self._get_client(client_id)
        return entry.get("token_endpoint_auth_method", "client_secret_post") if entry else None

    def get_client_metadata(self, client_id: str) -> Optional[dict]:
        entry = self._get_client(client_id)
        return entry.get("client_metadata", {}) if entry else None

    def client_exists(self, client_id: str) -> bool:
        return self._get_client(client_id) is not None

    def is_redirect_uri_allowed(self, client_id: str, redirect_uri: str) -> bool:
        """Return True if redirect_uri is allowed for the client.

        Fails closed: a client whose redirect_uris list is empty (e.g. seeded
        without explicit URIs) has no allowlist to match against, so every
        redirect_uri is rejected for it — this does not grant an "accept any
        redirect_uri" escape hatch.
        """
        entry = self._get_client(client_id)
        if entry is None:
            return False
        allowed = entry["redirect_uris"]
        return bool(allowed and redirect_uri in allowed)

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

    def store_token(self, client_id: str, resource: Optional[str] = None, scope: str = "") -> str:
        self._cleanup_expired()
        token = secrets.token_urlsafe(48)
        expires_at = _now() + self.token_ttl
        self._tokens[token] = {
            "client_id": client_id,
            "resource": resource,
            "scope": scope,
            "expires_at": expires_at,
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

    def store_refresh_token(self, client_id: str, resource: Optional[str] = None, scope: str = "") -> str:
        self._cleanup_expired()
        token = secrets.token_urlsafe(48)
        expires_at = _now() + self.refresh_token_ttl
        self._refresh_tokens[token] = {
            "client_id": client_id,
            "resource": resource,
            "scope": scope,
            "expires_at": expires_at,
        }
        self._refresh_tokens_expiry.append((token, expires_at))
        return token

    def exchange_refresh_token(self, refresh_token: str) -> Optional[dict]:
        """Return and consume a refresh token (rotation). None if missing or expired."""
        entry = self._refresh_tokens.pop(refresh_token, None)
        if entry is None:
            return None
        if _now() > entry["expires_at"]:
            return None
        return entry
