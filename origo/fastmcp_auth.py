"""FastMCP ``TokenVerifier`` adapter over an :class:`origo.OAuthProvider`.

For hosts that mount a FastMCP server whose ``auth=`` verifier they control
— and want origo-issued bearer tokens accepted on it, possibly alongside
the host's own credential classes. ``OAuthMiddleware`` stays the right tool
when origo is the *only* gate in front of an app; this adapter exists for
composition, where the host must consult more than one validator per token
(e.g. MiraRun's run-scoped credentials first, origo operator tokens as the
fallback) and a wrapping middleware would reject the other class before the
app ever saw it.

Requires the ``fastmcp`` extra: ``pip install 'origo[fastmcp]'``. Import
this module explicitly (``from origo.fastmcp_auth import ...``) — it is
deliberately not re-exported from the package root, so origo's core stays
importable without fastmcp installed.
"""

from __future__ import annotations

try:
    from fastmcp.server.auth import AccessToken, TokenVerifier
except ImportError as _error:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "origo.fastmcp_auth requires the 'fastmcp' extra: pip install 'origo[fastmcp]'"
    ) from _error


class OrigoTokenVerifier(TokenVerifier):
    """Accepts tokens the given provider issued for its own MCP resource.

    Verification is the same in-memory lookup ``OAuthMiddleware`` performs
    — including the resource check, so a token minted for a different
    ``resource`` value is rejected here exactly as it would be there.
    """

    def __init__(self, provider) -> None:
        super().__init__()
        self._provider = provider

    async def verify_token(self, token: str) -> AccessToken | None:
        meta = self._provider.verify_token(
            token, resource=self._provider.resource_identifier
        )
        if meta is None:
            return None
        scope = meta.get("scope") or ""
        expires_at = meta.get("expires_at")
        return AccessToken(
            token=token,
            client_id=str(meta.get("client_id")),
            scopes=scope.split(),
            expires_at=int(expires_at) if expires_at is not None else None,
            # The raw origo metadata rides along so hosts can distinguish
            # this credential class from their own in tool bodies (origo
            # claims carry client_id/resource/scope, never host-domain
            # identifiers).
            claims=dict(meta),
        )
