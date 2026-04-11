import warnings
from typing import Optional

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.routing import Route

from .endpoints import (
    authorize,
    oauth_metadata,
    protected_resource_metadata,
    register,
    token,
)
from .middleware import OAuthMiddleware
from .storage import OAuthStorage


class OAuthProvider:
    """
    Drop-in OAuth 2.1 provider for MCP servers.

    Args:
        base_url:            Public base URL of your server (no trailing slash).
        clients:             Pre-registered {client_id: client_secret} dict.
                             Required when public_registration=False.
        public_registration: Allow dynamic client registration (DCR).
                             Default False.
        auto_approve:        Skip consent page, approve all valid clients.
                             Default False.
        token_ttl:           Access token lifetime in seconds. Default 3600.
        mcp_path:            Path where MCP endpoint is mounted. Default "/mcp".
    """

    def __init__(
        self,
        base_url: str,
        clients: Optional[dict[str, str]] = None,
        public_registration: bool = False,
        auto_approve: bool = False,
        token_ttl: int = 3600,
        mcp_path: str = "/mcp",
    ):
        self.base_url = base_url.rstrip("/")
        self.public_registration = public_registration
        self.auto_approve = auto_approve
        self.mcp_path = mcp_path

        self.storage = OAuthStorage(token_ttl=token_ttl)

        if clients:
            self.storage.seed_clients(clients)
        elif not public_registration:
            warnings.warn(
                "OAuthProvider: public_registration=False but no clients provided. "
                "No client will be able to authenticate.",
                UserWarning,
                stacklevel=2,
            )

        self._app = self._build_app()

    def _build_app(self) -> Starlette:
        app = Starlette(
            routes=[
                Route("/.well-known/oauth-authorization-server", oauth_metadata, methods=["GET"]),
                Route("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]),
                Route("/register", register, methods=["POST"]),
                Route("/authorize", authorize, methods=["GET", "POST"]),
                Route("/token", token, methods=["POST"]),
            ],
        )
        app.state.base_url = self.base_url
        app.state.mcp_path = self.mcp_path
        app.state.storage = self.storage
        app.state.public_registration = self.public_registration
        app.state.auto_approve = self.auto_approve
        return app

    def asgi_app(self) -> Starlette:
        """Return the OAuth ASGI app for mounting."""
        return self._app

    def verify_token(self, token: str) -> Optional[dict]:
        """Verify a bearer token. Returns metadata dict or None."""
        return self.storage.verify_token(token)

    def middleware(self) -> OAuthMiddleware:
        """Return configured OAuthMiddleware bound to this provider."""
        return OAuthMiddleware