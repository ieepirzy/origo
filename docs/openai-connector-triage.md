# OpenAI, ChatGPT, Grok, and hosted MCP connector triage

This document records how the current Origo implementation maps to the connector-related GitHub issues. It is intentionally implementation-focused so future PRs can distinguish Origo responsibilities from MCP server or deployment responsibilities.

## Scope boundary

Origo is an OAuth/OIDC and bearer-token protection layer for ASGI applications. It does not implement MCP transports or tools by itself. A deployment still needs an MCP server/framework to expose the actual MCP endpoint, such as `/mcp` for streamable HTTP or `/sse` for server-sent events. Origo's responsibility is to:

- advertise the protected resource that the connector calls;
- expose OAuth/OIDC discovery and token endpoints;
- validate authorization requests, redirect URIs, PKCE, scopes, and resources;
- issue and verify bearer tokens for the protected MCP app;
- provide middleware that can wrap any ASGI MCP transport route.

## Issue status

| Issue | Status in this branch | Notes |
| --- | --- | --- |
| [#21 CIMD support](https://github.com/ieepirzy/origo/issues/21) | Implemented for public PKCE clients | HTTPS `client_id` values can be fetched as Client ID Metadata Documents, validated, and registered as `token_endpoint_auth_method=none` public PKCE clients. |
| [#22 SSE support for deployments that want a `/sse` endpoint](https://github.com/ieepirzy/origo/issues/22) | Documented as deployment/framework responsibility | Origo can protect `/sse` by setting `mcp_path="/sse"` and wrapping the SSE ASGI app with `OAuthMiddleware`. Origo should not invent the MCP SSE transport because it does not own MCP tool execution or session semantics. |
| [#23 OpenID support](https://github.com/ieepirzy/origo/issues/23) | Lightweight support implemented | OIDC discovery, unsigned `id_token` issuance for `openid` requests, and `/userinfo` for configured `user_email` are available for simple connector/domain-claiming flows. |
| [#24 Client-supplied callback URLs](https://github.com/ieepirzy/origo/issues/24) | Improved | DCR and CIMD clients are restricted to registered `redirect_uris`; pre-registered private clients can now use `client_redirect_uris` to avoid the historical unrestricted redirect behavior. |
| [#25 OpenAI/ChatGPT secure tunnels](https://github.com/ieepirzy/origo/issues/25) | OAuth side supported; tunnel transport remains external | OpenAI Secure MCP Tunnel is provided by OpenAI's `tunnel-client`. Origo supports the OAuth metadata, resource binding, `WWW-Authenticate` `resource_metadata`, and protected-resource configuration that the tunnel path preserves. |
| [#26 Grok-style MCP servers using `/sse`](https://github.com/ieepirzy/origo/issues/26) | Documented usage pattern | The README now includes `/sse` guidance. Actual Grok auth characteristics were not publicly documented in the issue, so Origo exposes the generic pattern: protect the MCP SSE ASGI app and advertise `/sse` as the protected resource. |

## Correct `/sse` usage

For `/sse` connector surfaces, the deployment should expose an MCP SSE ASGI application and configure Origo with the same externally visible path:

```python
auth = OAuthProvider(
    base_url="https://mcp.yourdomain.com",
    clients={"client-id": "client-secret"},
    mcp_path="/sse",
)

sse_app.add_middleware(OAuthMiddleware, provider=auth)
app = Starlette(routes=[
    Mount("/sse", app=sse_app),
    Mount("/", app=auth.asgi_app()),
])
```

With that setup, `/.well-known/oauth-protected-resource` advertises `https://mcp.yourdomain.com/sse`, and middleware validates bearer tokens for the protected SSE MCP route.

## Remaining follow-ups

- If a specific hosted connector requires a non-standard `/sse` handshake, add that support in the MCP server/framework layer or a separate adapter package rather than inside Origo's OAuth layer.
- For local agents whose CIMD metadata document is intentionally hosted on private or loopback infrastructure, set `allow_private_cimd=True`; leave it disabled for internet-facing providers to keep SSRF protections on by default.
- If a connector requires signed OIDC ID tokens or `private_key_jwt`, add a dedicated signing/verification implementation with explicit key configuration and tests; do not silently extend the current lightweight unsigned-token behavior.
- If one deployment must expose both `/mcp` and `/sse` as separate public resources, use separate `OAuthProvider` instances or separate base URLs so each provider has one canonical protected-resource identifier.
