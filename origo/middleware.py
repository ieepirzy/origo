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


# Paths that must be publicly accessible for the OAuth flow to work
_PUBLIC_PATHS = {
    "/register",
    "/authorize",
    "/token",
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

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        if path in _PUBLIC_PATHS or path.startswith("/.well-known/"):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode()

        if not auth.startswith("Bearer "):
            await _send_json(
                send,
                {"error": "unauthorized", "error_description": "Bearer token required."},
                401,
                [(b"www-authenticate", f'Bearer realm="{self.provider.base_url}"'.encode())],
            )
            return

        token = auth[len("Bearer "):]
        if self.provider.verify_token(token) is None:
            await _send_json(
                send,
                {"error": "invalid_token", "error_description": "Token is invalid or expired."},
                401,
                [(b"www-authenticate", f'Bearer realm="{self.provider.base_url}" error="invalid_token"'.encode())],
            )
            return

        try:
            await self.app(scope, receive, send)
        except BaseException as exc:
            if _is_client_disconnect(exc):
                return
            raise