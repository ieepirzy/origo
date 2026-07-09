import functools
import warnings
from typing import Optional

from starlette.applications import Starlette
from starlette.routing import Route

from .endpoints import (
    authorize,
    oauth_metadata,
    protected_resource_metadata,
    register,
    token,
    userinfo,
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
        client_redirect_uris: Optional {client_id: [redirect_uri, ...]} allowlist for pre-registered clients.
        public_registration: Allow dynamic client registration (DCR).
                             Default False.
        auto_approve:        Skip consent page, approve all valid clients.
                             Default False.
        token_ttl:           Access token lifetime in seconds. Default 3600.
        mcp_path:            Path where MCP endpoint is mounted. Default "/mcp".
        scopes_supported:    OAuth scopes advertised to clients.
        resource_documentation: Optional protected resource documentation URL.
        user_email:          Optional static OIDC email claim for lightweight domain claiming.
        allow_private_cimd:  Allow CIMD client_id documents to be fetched from
                             private/loopback/link-local hosts. Off by default (SSRF
                             hardening) since client_id is attacker-controlled input.
                             Enable only when your CIMD documents are intentionally
                             served from inside your own network (e.g. an agent
                             deployment colocated with origo) — see README.
        custom_redirect_uri_schemes: Optional list of private-use URI schemes (RFC 8252
                             §7.1, e.g. ["myapp"]) to accept as redirect_uris during
                             dynamic (DCR/CIMD) client registration, for native/mobile
                             app clients. Off by default — an unconfigured scheme could
                             be claimed by another app on the same device, so schemes
                             must be declared explicitly by the operator.
    """

    def __init__(
        self,
        base_url: str,
        clients: Optional[dict[str, str]] = None,
        client_redirect_uris: Optional[dict[str, list[str]]] = None,
        public_registration: bool = False,
        auto_approve: bool = False,
        token_ttl: int = 3600,
        mcp_path: str = "/mcp",
        scopes_supported: Optional[list[str]] = None,
        resource_documentation: Optional[str] = None,
        user_email: Optional[str] = None,
        user_subject: Optional[str] = None,
        allow_private_cimd: bool = False,
        custom_redirect_uri_schemes: Optional[list[str]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.public_registration = public_registration
        self.auto_approve = auto_approve
        self.mcp_path = mcp_path
        self.scopes_supported = list(scopes_supported or [])
        self.resource_documentation = resource_documentation
        self.user_email = user_email
        self.user_subject = user_subject or user_email or "origo-user"
        self.allow_private_cimd = allow_private_cimd

        if isinstance(custom_redirect_uri_schemes, str):
            raise TypeError("custom_redirect_uri_schemes must be a list of strings, not a single string")
        schemes = []
        for scheme in custom_redirect_uri_schemes or []:
            if not isinstance(scheme, str):
                raise TypeError("custom_redirect_uri_schemes must contain only strings")
            sanitized = scheme.rstrip(":/").lower()
            if sanitized:
                schemes.append(sanitized)
        self.custom_redirect_uri_schemes = frozenset(schemes)

        self.storage = OAuthStorage(token_ttl=token_ttl)

        if clients:
            self.storage.seed_clients(clients, client_redirect_uris)
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
                Route("/.well-known/openid-configuration", oauth_metadata, methods=["GET"]),
                Route("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]),
                Route("/register", register, methods=["POST"]),
                Route("/authorize", authorize, methods=["GET", "POST"]),
                Route("/token", token, methods=["POST"]),
                Route("/userinfo", userinfo, methods=["GET", "POST"]),
            ],
        )
        app.state.base_url = self.base_url
        app.state.mcp_path = self.mcp_path
        app.state.storage = self.storage
        app.state.public_registration = self.public_registration
        app.state.auto_approve = self.auto_approve
        app.state.scopes_supported = self.scopes_supported
        app.state.resource_documentation = self.resource_documentation
        app.state.user_email = self.user_email
        app.state.user_subject = self.user_subject
        app.state.allow_private_cimd = self.allow_private_cimd
        app.state.custom_redirect_uri_schemes = self.custom_redirect_uri_schemes
        return app

    def asgi_app(self) -> Starlette:
        """Return the OAuth ASGI app for mounting."""
        return self._app

    def verify_token(self, token: str, resource: Optional[str] = None) -> Optional[dict]:
        """Verify a bearer token. Returns metadata dict or None."""
        meta = self.storage.verify_token(token)
        if meta is None:
            return None
        if resource is not None and meta.get("resource") not in (None, resource):
            return None
        return meta

    @property
    def protected_resource_metadata_url(self) -> str:
        return f"{self.base_url}/.well-known/oauth-protected-resource"

    @property
    def resource_identifier(self) -> str:
        return f"{self.base_url}{self.mcp_path}"

    def middleware(self):
        """Return a partial usable with Starlette's add_middleware.

        Usage: app.add_middleware(provider.middleware())
        """
        return functools.partial(OAuthMiddleware, provider=self)