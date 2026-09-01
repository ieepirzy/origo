import json
import logging

import anyio
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("origo")


def _redact(value, keep_start: int = 8, keep_end: int = 4) -> str:
    """Preview a secret-bearing value for logs without exposing it.

    Never returns enough of `value` to reconstruct or brute-force it — just
    enough to correlate log lines with a specific token/header across a
    request flow (e.g. "is this the same bearer token retried, or a second,
    different one?").
    """
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return f"<{len(value)} bytes, undecodable>"
    if not value:
        return "<empty>"
    if len(value) <= keep_start + keep_end:
        return f"<{len(value)} chars>"
    return f"{value[:keep_start]}…{value[-keep_end:]} ({len(value)} chars)"


def _is_client_disconnect(exc: BaseException) -> bool:
    """Return True if exc is (or wraps only) anyio.ClosedResourceError."""
    if isinstance(exc, anyio.ClosedResourceError):
        return True
    if hasattr(exc, "exceptions"):  # ExceptionGroup / BaseExceptionGroup (Python 3.11+)
        return all(_is_client_disconnect(e) for e in exc.exceptions)
    return False


# Paths that must be publicly accessible for the OAuth flow to work.
# This is an exact-match set derived directly from the route table in OAuthProvider.
# Using exact matching (not prefix/startswith) prevents prefix-confusion attacks
# where a path like /token_info or /.well-known-decoy/x would bypass auth.
_PUBLIC_PATHS = {
    "/register",
    "/authorize",
    "/token",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-protected-resource",
    "/.well-known/jwks.json",
}


async def _send_json(send: Send, body: dict, status: int, extra_headers: list[tuple[bytes, bytes]] = ()):
    encoded = json.dumps(body).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(encoded)).encode()),
        *extra_headers,
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": encoded, "more_body": False})


class OAuthMiddleware:
    """
    Validates Bearer tokens on all requests except OAuth flow endpoints.

    Usage:
        app.add_middleware(OAuthMiddleware, provider=my_oauth_provider)

    Debugging a rejected/misbehaving request (e.g. a client getting
    unexpected 400s/401s, or a downstream app 400ing after auth passes):
        app.add_middleware(OAuthMiddleware, provider=my_oauth_provider, debug=True)

    With debug=True, every request logs, at DEBUG level on the "origo" logger,
    which decision the middleware made and why: which header names were
    present, how many Authorization headers were seen, the auth scheme
    prefix if the Bearer check failed, why token verification failed (no
    such token/expired vs. resource mismatch), the authenticated client_id/
    scope on success, and the downstream app's response status once it
    responds. Secret values (bearer tokens, header contents) are never
    logged in full — only short, non-reconstructable previews via
    `_redact()` (e.g. "8f3a91c2…b7e4 (71 chars)"), enough to tell two
    requests apart without exposing the credential. If no handler is
    configured on the "origo" logger yet, debug=True attaches a StreamHandler
    so output is visible by default; if your app already configures logging,
    that configuration is left alone.
    """

    def __init__(self, app: ASGIApp, provider, debug: bool = False):
        self.app = app
        self.provider = provider
        self.debug = debug
        if debug:
            logger.setLevel(logging.DEBUG)
            if not logger.handlers:
                handler = logging.StreamHandler()
                handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(message)s"))
                logger.addHandler(handler)
        # RFC 9728's path-suffixed metadata URL, e.g.
        # /.well-known/oauth-protected-resource/mcp. It depends on mcp_path, so it
        # cannot live in the static _PUBLIC_PATHS set. Still matched exactly, so
        # the prefix-confusion protection below is preserved.
        self._resource_metadata_path = (
            f"/.well-known/oauth-protected-resource{provider.mcp_path}"
        )

    def _www_authenticate(self, error: str | None = None) -> bytes:
        parts = [
            f'realm="{self.provider.base_url}"',
            f'resource_metadata="{self.provider.protected_resource_metadata_url}"',
        ]
        if self.provider.scopes_supported:
            parts.append(f'scope="{" ".join(self.provider.scopes_supported)}"')
        if error:
            parts.append(f'error="{error}"')
        return ("Bearer " + ", ".join(parts)).encode()

    def _log(self, method: str, path: str, msg: str, *args) -> None:
        if self.debug:
            logger.debug(f"%s %s: {msg}", method, path, *args)

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", scope["type"])

        if path in _PUBLIC_PATHS or path == self._resource_metadata_path:
            self._log(method, path, "public path, bypassing auth")
            await self.app(scope, receive, send)
            return

        raw_headers = scope.get("headers", [])
        auth_headers = [v for k, v in raw_headers if k.lower() == b"authorization"]

        if self.debug:
            header_names = sorted({k.decode("latin-1", "replace") for k, _ in raw_headers})
            self._log(method, path, "headers present: %s (Authorization count=%d)", header_names, len(auth_headers))

        if len(auth_headers) > 1:
            self._log(
                method, path, "REJECTED 400 multiple_authorization_headers: %s",
                [_redact(h) for h in auth_headers],
            )
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                await _send_json(
                    send,
                    {"error": "invalid_request", "error_description": "Multiple Authorization headers present."},
                    400,
                )
            return

        auth_bytes = auth_headers[0] if auth_headers else b""

        if not auth_bytes.startswith(b"Bearer "):
            self._log(
                method, path, "REJECTED 401 missing_bearer_scheme: header=%s",
                _redact(auth_bytes) if auth_bytes else "<no Authorization header>",
            )
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                await _send_json(
                    send,
                    {"error": "unauthorized", "error_description": "Bearer token required."},
                    401,
                    [(b"www-authenticate", self._www_authenticate())],
                )
            return

        try:
            token = auth_bytes[len(b"Bearer "):].decode("ascii")
        except UnicodeDecodeError:
            token = ""

        token_metadata = (
            self.provider.verify_token(token, resource=self.provider.resource_identifier)
            if token
            else None
        )
        if token_metadata is None:
            if self.debug:
                self._log(
                    method, path, "REJECTED 401 invalid_token: token=%s reason=%s expected_resource=%s",
                    _redact(token), self._diagnose_invalid_token(token), self.provider.resource_identifier,
                )
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                await _send_json(
                    send,
                    {"error": "invalid_token", "error_description": "Token is invalid or expired."},
                    401,
                    [(b"www-authenticate", self._www_authenticate("invalid_token"))],
                )
            return

        # Expose only non-secret authorization context to the protected ASGI app.
        # Starlette Request.state reads from this per-request scope dictionary.
        request_state = scope.setdefault("state", {})
        request_state["client_id"] = token_metadata.get("client_id")
        request_state["oauth_scope"] = token_metadata.get("scope", "")

        self._log(
            method, path, "AUTHENTICATED client_id=%s scope=%r, forwarding to app",
            token_metadata.get("client_id"), token_metadata.get("scope", ""),
        )

        send_downstream = self._wrap_send_for_debug(method, path, send) if self.debug else send

        try:
            await self.app(scope, receive, send_downstream)
        except BaseException as exc:
            if _is_client_disconnect(exc):
                self._log(method, path, "client disconnected")
                return
            self._log(method, path, "downstream app raised %r", exc)
            raise

    def _diagnose_invalid_token(self, token: str) -> str:
        """Best-effort reason a token failed verification, for debug logs only.

        Distinguishes "no such token / expired" from "resource mismatch" (a
        token that's otherwise valid but was issued for a different
        resource_identifier) — the latter looks identical to a normal auth
        failure from the outside, but is a config/contract mismatch, not a
        bad credential.
        """
        if not token:
            return "empty token"
        raw = self.provider.storage.verify_token(token)
        if raw is None:
            return "no such token, or expired"
        actual = raw.get("resource")
        expected = self.provider.resource_identifier
        if actual not in (None, expected):
            return f"resource mismatch: token issued for {actual!r}, this server expects {expected!r}"
        return "unknown (passed storage lookup but provider.verify_token still rejected it)"

    def _wrap_send_for_debug(self, method: str, path: str, send: Send) -> Send:
        async def logging_send(message):
            if message["type"] == "http.response.start":
                self._log(method, path, "downstream app responded %d", message["status"])
            await send(message)

        return logging_send
