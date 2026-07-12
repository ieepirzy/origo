import secrets
import time
import warnings
from typing import Optional


def _now() -> float:
    return time.time()


class OAuthStorage:
    def __init__(self, token_ttl: int = 3600, refresh_token_ttl: int = 30 * 24 * 3600):
        self.token_ttl = token_ttl
        self.refresh_token_ttl = refresh_token_ttl
        self._clients: dict[str, dict] = {}        # client_id -> {secret, redirect_uris, token_endpoint_auth_method}
        self._codes: dict[str, dict] = {}          # code -> metadata
        self._tokens: dict[str, dict] = {}         # token -> metadata
        self._refresh_tokens: dict[str, dict] = {}  # refresh_token -> metadata

    # --- Clients ---

    def seed_clients(self, clients: dict[str, str], redirect_uris: Optional[dict[str, list[str]]] = None) -> None:
        """Seed pre-registered clients. Empty redirect_uris means any URI is allowed."""
        redirect_uris = redirect_uris or {}
        if clients and not any(redirect_uris.values()):
            warnings.warn(
                "OAuthProvider: clients seeded with no redirect_uris — "
                "any redirect_uri will be accepted. Specify allowed URIs in production.",
                UserWarning,
                stacklevel=3,
            )
        for client_id, secret in clients.items():
            allowed_redirect_uris = list(redirect_uris.get(client_id, []))
            self._clients[client_id] = {
                "secret": secret,
                "redirect_uris": allowed_redirect_uris,
                "token_endpoint_auth_method": "client_secret_post",
                "client_metadata": {},
            }
            if not allowed_redirect_uris:
                warnings.warn(
                    f"OAuthProvider: client '{client_id}' seeded with no redirect_uris — "
                    "any redirect_uri will be accepted. Specify allowed URIs in production.",
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
        """Dynamically register a new client (public mode)."""
        self._clients[client_id] = {
            "secret": client_secret,
            "redirect_uris": list(redirect_uris),
            "token_endpoint_auth_method": token_endpoint_auth_method,
            "client_metadata": client_metadata or {},
        }

    def get_client_secret(self, client_id: str) -> Optional[str]:
        entry = self._clients.get(client_id)
        return entry["secret"] if entry else None

    def get_client_auth_method(self, client_id: str) -> Optional[str]:
        entry = self._clients.get(client_id)
        return entry.get("token_endpoint_auth_method", "client_secret_post") if entry else None

    def get_client_metadata(self, client_id: str) -> Optional[dict]:
        entry = self._clients.get(client_id)
        return entry.get("client_metadata", {}) if entry else None

    def client_exists(self, client_id: str) -> bool:
        return client_id in self._clients

    def is_redirect_uri_allowed(self, client_id: str, redirect_uri: str) -> bool:
        """Return True if redirect_uri is allowed for the client. No stored URIs means any is allowed."""
        entry = self._clients.get(client_id)
        if entry is None:
            return False
        allowed = entry["redirect_uris"]
        return not allowed or redirect_uri in allowed

    # --- Auth codes ---

    def _cleanup_expired(self) -> None:
        now = _now()
        self._codes = {k: v for k, v in self._codes.items() if v["expires_at"] > now}
        self._tokens = {k: v for k, v in self._tokens.items() if v["expires_at"] > now}
        self._refresh_tokens = {k: v for k, v in self._refresh_tokens.items() if v["expires_at"] > now}

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
        self._codes[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "resource": resource,
            "scope": scope,
            "expires_at": _now() + 60,  # codes expire in 60 seconds
        }
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
        self._tokens[token] = {
            "client_id": client_id,
            "resource": resource,
            "scope": scope,
            "expires_at": _now() + self.token_ttl,
        }
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
        self._refresh_tokens[token] = {
            "client_id": client_id,
            "resource": resource,
            "scope": scope,
            "expires_at": _now() + self.refresh_token_ttl,
        }
        return token

    def exchange_refresh_token(self, refresh_token: str) -> Optional[dict]:
        """Return and consume a refresh token (rotation). None if missing or expired."""
        entry = self._refresh_tokens.pop(refresh_token, None)
        if entry is None:
            return None
        if _now() > entry["expires_at"]:
            return None
        return entry
