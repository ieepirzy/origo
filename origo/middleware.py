import json

import anyio
from starlette.types import ASGIApp, Receive, Scope, Send


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
    """

    def __init__(self, app: ASGIApp, provider):
        self.app = app
        self.provider = provider
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
        if error:
            parts.append(f'error="{error}"')
        return ("Bearer " + ", ".join(parts)).encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        if path in _PUBLIC_PATHS or path == self._resource_metadata_path:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        auth_bytes = headers.get(b"authorization", b"")

        if not auth_bytes.startswith(b"Bearer "):
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

        if not token or self.provider.verify_token(token, resource=self.provider.resource_identifier) is None:
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

        try:
            await self.app(scope, receive, send)
        except BaseException as exc:
            if _is_client_disconnect(exc):
                return
            raise
