import functools
import hashlib
import os
import sqlite3
import warnings
from typing import Optional

from starlette.applications import Starlette
from starlette.routing import Route
from cryptography.hazmat.primitives.asymmetric import rsa

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
from .sqlite_storage import SQLiteOAuthStorage
from .storage import OAuthStorage

# Distinguishes "storage_path not passed" (persist by default, at an
# automatically-derived path) from the explicit, permanent opt-out
# storage_path=None (always in-memory). A plain default of None could not
# make that distinction.
_AUTO_STORAGE_PATH = object()


def _default_storage_dir() -> Optional[str]:
    """Directory persistent storage defaults into when storage_path isn't
    passed. ORIGO_STORAGE_PATH overrides it; set to the empty string, it
    forces in-memory storage without touching code (an operational opt-out
    alongside the code-level storage_path=None one)."""
    if "ORIGO_STORAGE_PATH" in os.environ:
        env_value = os.environ["ORIGO_STORAGE_PATH"]
        return env_value or None
    return ".origo"


def _default_storage_path(base_url: str, mcp_path: str) -> Optional[str]:
    """A default per-deployment file path, namespaced by the one pair of
    values that already identifies an OAuthProvider instance. Hashed rather
    than used verbatim so the path never embeds a public URL directly on
    disk, and so it's filesystem-safe regardless of what base_url looks like."""
    base_dir = _default_storage_dir()
    if base_dir is None:
        return None
    digest = hashlib.sha256(f"{base_url}|{mcp_path}".encode()).hexdigest()[:16]
    return os.path.join(base_dir, f"{digest}.db")


class OAuthProvider:
    """
    Drop-in OAuth 2.1 provider for MCP servers.

    Args:
        base_url:            Public base URL of your server (no trailing slash).
        clients:             Pre-registered {client_id: client_secret} dict.
                             Required when public_registration=False.
        client_redirect_uris: Optional {client_id: [redirect_uri, ...]} allowlist for
                             pre-registered clients. Exact-match, fail-closed. A
                             confidential (secret-holding) client may instead map to
                             the ANY_REDIRECT_URI sentinel ("any", as the bare string
                             or sole list element) to accept every redirect URI that
                             passes scheme validation — see the sentinel's docs in
                             origo.storage for the security trade-off. Rejected and
                             wildcard-accepted redirect URIs are logged on the
                             "origo" logger so their exact values can be collected
                             into an allowlist.
        public_registration: Allow dynamic client registration (DCR).
                             Default False.
        auto_approve:        Skip consent page, approve all valid clients.
                             Default False.
        token_ttl:           Access token lifetime in seconds. Default 3600.
        refresh_token_ttl:   Refresh token lifetime in seconds. Default 30 days.
                             Refresh tokens are single-use and rotated on every
                             /token request (a new one is issued each time).
                             Replaying an already-used refresh token revokes
                             every token descended from the same grant.
        storage_path:        Path to a SQLite database file for persistent storage
                             (tokens, refresh tokens, and dynamically-registered
                             clients survive restarts — stored hashed, in a
                             0600-mode file — instead of living in memory; still
                             in-process, no extra service). When omitted (the
                             default), origo persists automatically to a path
                             derived from base_url/mcp_path under ./.origo (see
                             ORIGO_STORAGE_PATH in the README to relocate or
                             disable this without a code change). Pass
                             storage_path=None explicitly to force in-memory
                             storage regardless of that default.
        client_ttl:          Lifetime in seconds for dynamically-registered clients
                             (via DCR /register or CIMD auto-registration). Default
                             None (no expiration). Pre-registered clients passed via
                             `clients=` are always permanent and unaffected.
        max_dynamic_clients: Maximum number of dynamically-registered clients (DCR
                             and CIMD) kept at once; registration attempts past the
                             cap are rejected (HTTP 429) until existing ones expire
                             via client_ttl. Default 1000. Pre-registered clients
                             passed via `clients=` don't count against this cap.
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
        # New parameters go at the end: inserting one mid-signature would
        # silently rebind existing callers' positional arguments.
        storage_path: Optional[str] = _AUTO_STORAGE_PATH,
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

        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

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

        is_auto = storage_path is _AUTO_STORAGE_PATH
        resolved_path = _default_storage_path(self.base_url, self.mcp_path) if is_auto else storage_path

        def _memory_storage() -> OAuthStorage:
            return OAuthStorage(
                token_ttl=token_ttl,
                refresh_token_ttl=refresh_token_ttl,
                client_ttl=client_ttl,
                max_dynamic_clients=max_dynamic_clients,
            )

        if resolved_path is None:
            # Either an explicit storage_path=None (permanent code-level
            # opt-out) or the ORIGO_STORAGE_PATH="" operational opt-out.
            self.storage = _memory_storage()
        else:
            try:
                storage_dir = os.path.dirname(resolved_path)
                if storage_dir:
                    os.makedirs(storage_dir, exist_ok=True)
                self.storage = SQLiteOAuthStorage(
                    resolved_path,
                    token_ttl=token_ttl,
                    refresh_token_ttl=refresh_token_ttl,
                    client_ttl=client_ttl,
                    max_dynamic_clients=max_dynamic_clients,
                )
            except (OSError, sqlite3.Error) as exc:
                # OSError: can't create the directory, or open/create the
                # file (permissions, read-only fs). sqlite3.Error: the file
                # exists but isn't a usable database -- e.g. corrupt, a
                # non-SQLite file sitting at that path, or a locked file
                # SQLite can't get a handle on (sqlite3.DatabaseError /
                # OperationalError are not OSError subclasses).
                if not is_auto:
                    # storage_path was passed explicitly: persistence was
                    # requested, not merely defaulted, so a failure to
                    # provide it must not be silently downgraded.
                    raise
                warnings.warn(
                    f"OAuthProvider: could not initialize persistent storage at "
                    f"'{resolved_path}' ({exc}) — falling back to in-memory "
                    f"storage for this run (tokens will not survive a restart). "
                    f"Pass storage_path=None to choose in-memory storage "
                    f"deliberately and silence this warning, or fix/relocate the "
                    f"path via the ORIGO_STORAGE_PATH environment variable.",
                    UserWarning,
                    stacklevel=2,
                )
                self.storage = _memory_storage()
            else:
                if public_registration and client_ttl is None:
                    warnings.warn(
                        "OAuthProvider: public_registration=True with persistent storage "
                        "and no client_ttl — dynamically-registered clients now survive "
                        "restarts, so once max_dynamic_clients is reached registration "
                        "stays blocked forever (a restart no longer clears it). Set "
                        "client_ttl so abandoned registrations expire.",
                        UserWarning,
                        stacklevel=2,
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
        routes = [
            Route("/.well-known/oauth-authorization-server", oauth_metadata, methods=["GET"]),
            Route("/.well-known/openid-configuration", oauth_metadata, methods=["GET"]),
            Route("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]),
            Route("/.well-known/jwks.json", jwks, methods=["GET"]),
            Route("/register", register, methods=["POST"]),
            Route("/authorize", authorize, methods=["GET", "POST"]),
            Route("/token", token, methods=["POST"]),
            Route("/userinfo", userinfo, methods=["GET", "POST"]),
        ]

        # RFC 9728 §3.1: when the resource identifier has a path component, the
        # metadata lives at the well-known URI with that path *inserted after*
        # it — https://host/.well-known/oauth-protected-resource/mcp for a
        # resource at https://host/mcp. That is the URL a client constructs
        # from the resource identifier it was challenged with. Without this
        # route the request fell through to the mounted application and came
        # back 401 from OAuthMiddleware, so a client following the challenge
        # correctly was told to authenticate in order to discover how to
        # authenticate. Observed in production at
        # https://mcp.muutto365.fi/.well-known/oauth-protected-resource/mcp.
        #
        # Same handler and same document as the un-suffixed route: this adds a
        # spec-mandated address for the metadata, not a second version of it.
        if self._protected_resource_metadata_path != "/.well-known/oauth-protected-resource":
            routes.append(Route(
                self._protected_resource_metadata_path,
                protected_resource_metadata,
                methods=["GET"],
            ))

        app = Starlette(routes=routes)
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
    def _protected_resource_metadata_path(self) -> str:
        """RFC 9728 §3.1 path-inserted metadata path, e.g. /.well-known/oauth-protected-resource/mcp.

        mcp_path is stored exactly as the caller passed it and is not
        normalized anywhere, so it may arrive as "/mcp", "mcp" or "/mcp/".
        Stripping both ends covers all three: the segments cannot concatenate
        into a double slash, and there is no trailing slash to stop the
        middleware's exact `==` comparison from matching the request path.

        When mcp_path is empty or "/" the resource identifier has no path
        component, RFC 9728 §3.1 does not apply, and this collapses to the
        un-suffixed path — _build_app checks for that and does not register a
        duplicate route.
        """
        suffix = self.mcp_path.strip("/")
        return f"/.well-known/oauth-protected-resource/{suffix}" if suffix else "/.well-known/oauth-protected-resource"

    @property
    def protected_resource_metadata_path(self) -> str:
        """Public alias of the above, used by OAuthMiddleware to leave this path unauthenticated."""
        return self._protected_resource_metadata_path

    @property
    def protected_resource_metadata_url(self) -> str:
        # Kept pointing at the un-suffixed URL: it is what this provider has
        # always advertised, both routes serve the same document, and changing
        # what goes into WWW-Authenticate is a behavioural change for existing
        # clients rather than the bug fix this is.
        return f"{self.base_url}/.well-known/oauth-protected-resource"

    @property
    def resource_identifier(self) -> str:
        return f"{self.base_url}{self.mcp_path}"

    def middleware(self):
        """Return a partial usable with Starlette's add_middleware.

        Usage: app.add_middleware(provider.middleware())
        """
        return functools.partial(OAuthMiddleware, provider=self)