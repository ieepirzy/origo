import secrets
import time
import warnings
from typing import Optional


def _now() -> float:
    return time.time()


class OAuthStorage:
    def __init__(self, token_ttl: int = 3600):
        self.token_ttl = token_ttl
        self._clients: dict[str, dict] = {}        # client_id -> {secret, redirect_uris}
        self._codes: dict[str, dict] = {}          # code -> metadata
        self._tokens: dict[str, dict] = {}         # token -> metadata

    # --- Clients ---

    def seed_clients(self, clients: dict[str, str]) -> None:
        """Seed pre-registered clients. Empty redirect_uris means any URI is allowed."""
        if clients:
            warnings.warn(
                "OAuthProvider: clients seeded with no redirect_uris — "
                "any redirect_uri will be accepted. Specify allowed URIs in production.",
                UserWarning,
                stacklevel=3,
            )
        for client_id, secret in clients.items():
            self._clients[client_id] = {"secret": secret, "redirect_uris": []}
            warnings.warn(
                f"OAuthProvider: client '{client_id}' seeded with no redirect_uris — "
                "any redirect_uri will be accepted. Specify allowed URIs in production.",
                UserWarning,
                stacklevel=2,
            )

    def register_client(self, client_id: str, client_secret: str, redirect_uris: list[str] = ()) -> None:
        """Dynamically register a new client (public mode)."""
        self._clients[client_id] = {"secret": client_secret, "redirect_uris": list(redirect_uris)}

    def get_client_secret(self, client_id: str) -> Optional[str]:
        entry = self._clients.get(client_id)
        return entry["secret"] if entry else None

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

    def store_code(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
    ) -> str:
        self._cleanup_expired()
        code = secrets.token_urlsafe(32)
        self._codes[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
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

    def store_token(self, client_id: str) -> str:
        self._cleanup_expired()
        token = secrets.token_urlsafe(48)
        self._tokens[token] = {
            "client_id": client_id,
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
