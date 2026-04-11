from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Paths that must be publicly accessible for the OAuth flow to work
_PUBLIC_PREFIXES = (
    "/.well-known/",
    "/register",
    "/authorize",
    "/token",
)


class OAuthMiddleware(BaseHTTPMiddleware):
    """
    Validates Bearer tokens on all requests except OAuth flow endpoints.

    Usage:
        app.add_middleware(OAuthMiddleware, provider=my_oauth_provider)
    """

    def __init__(self, app, provider):
        super().__init__(app)
        self.provider = provider

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Let OAuth flow endpoints through unauthenticated
        if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse(
                {"error": "unauthorized", "error_description": "Bearer token required."},
                status_code=401,
                headers={"WWW-Authenticate": f'Bearer realm="{self.provider.base_url}"'},
            )

        token = auth[len("Bearer "):]
        if self.provider.verify_token(token) is None:
            return JSONResponse(
                {"error": "invalid_token", "error_description": "Token is invalid or expired."},
                status_code=401,
                headers={"WWW-Authenticate": f'Bearer realm="{self.provider.base_url}" error="invalid_token"'},
            )

        return await call_next(request)