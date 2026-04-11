import secrets
from datetime import datetime, timezone
from typing import Optional


def _now() -> float:
    return datetime.now(timezone.utc).timestamp()


class OAuthStorage:
    def __init__(self, token_ttl: int = 3600):
        self.token_ttl = token_ttl
        self._clients: dict[str, str] = {}        # client_id -> client_secret
        self._codes: dict[str, dict] = {}          # code -> metadata
        self._tokens: dict[str, dict] = {}         # token -> metadata

    # --- Clients ---

    def seed_clients(self, clients: dict[str, str]) -> None:
        """Seed pre-registered clients."""
        self._clients.update(clients)

    def register_client(self, client_id: str, client_secret: str) -> None:
        """Dynamically register a new client (public mode)."""
        self._clients[client_id] = client_secret

    def get_client_secret(self, client_id: str) -> Optional[str]:
        return self._clients.get(client_id)

    def client_exists(self, client_id: str) -> bool:
        return client_id in self._clients

    # --- Auth codes ---

    def store_code(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
    ) -> str:
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