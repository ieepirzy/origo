import functools
import warnings
from typing import Optional

from starlette.applications import Starlette
from starlette.routing import Route
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .endpoints import (
    authorize,
    jwks,
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
        refresh_token_ttl:   Refresh token lifetime in seconds. Default 30 days.
                             Refresh tokens are single-use and rotated on every
                             /token request (a new one is issued each time).
        client_ttl:          Lifetime in seconds for dynamically-registered clients
                             (via DCR /register or CIMD auto-registration). Default
                             None (no expiration). Pre-registered clients passed via
                             `clients=` are always permanent and unaffected.
        max_dynamic_clients: Maximum number of dynamically-registered clients (DCR
                             and CIMD) kept in memory at once; the oldest is evicted
                             when a new one would exceed this cap. Default 1000.
                             Pre-registered clients passed via `clients=` don't count
                             against this cap.
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
        storage:             Optional storage instance. Inject a shared implementation
                             before running multiple replicas; the default OAuthStorage
                             is process-local memory.
        private_key:         Optional persistent RSA signing key. The default is generated
                             per process and is therefore unsuitable for interchangeable
                             replicas.
    """

    def __init__(
        self,
        base_url: str,
        clients: Optional[dict[str, str]] = None,
        client_redirect_uris: Optional[dict[str, list[str]]] = None,
        public_registration: bool = False,
        auto_approve: bool = False,
        token_ttl: int = 3600,
        refresh_token_ttl: int = 30 * 24 * 3600,
        client_ttl: Optional[int] = None,
        max_dynamic_clients: int = 1000,
        mcp_path: str = "/mcp",
        scopes_supported: Optional[list[str]] = None,
        resource_documentation: Optional[str] = None,
        user_email: Optional[str] = None,
        user_subject: Optional[str] = None,
        allow_private_cimd: bool = False,
        custom_redirect_uri_schemes: Optional[list[str]] = None,
        storage: Optional[OAuthStorage] = None,
        private_key: Optional[RSAPrivateKey] = None,
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

        self.private_key = private_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)

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

        self.storage = storage or OAuthStorage(
            token_ttl=token_ttl,
            refresh_token_ttl=refresh_token_ttl,
            client_ttl=client_ttl,
            max_dynamic_clients=max_dynamic_clients,
        )

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
                # RFC 9728 builds the metadata URL by INSERTING the well-known
                # segment into the resource path: a resource at https://host/mcp
                # is described at https://host/.well-known/oauth-protected-resource/mcp.
                # Clients (Claude among them) try this form first, so serve it as
                # well as the bare path.
                Route(
                    f"/.well-known/oauth-protected-resource{self.mcp_path}",
                    protected_resource_metadata,
                    methods=["GET"],
                ),
                Route("/.well-known/jwks.json", jwks, methods=["GET"]),
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
        app.state.private_key = self.private_key
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
