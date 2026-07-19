# origo

[![CI](https://github.com/ieepirzy/origo/actions/workflows/ci.yml/badge.svg)](https://github.com/ieepirzy/origo/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/origo)](https://pypi.org/project/origo/)
[![Python versions](https://img.shields.io/pypi/pyversions/origo)](https://pypi.org/project/origo/)

> Implements the OAuth2.1 + PKCE flow as a drop-in Starlette based middleware layer, with public and private registration modes.

Drop-in OAuth 2.1 provider, originally developed for use in custom/private MCP servers. Handles the full Authorization Code + PKCE flow with no external identity provider required.

Works with **FastMCP**, **FastAPI**, the raw **MCP SDK**, and MCP clients on the **OpenAI platform** such as ChatGPT connectors.

## Install

```bash
pip install origo
```

## Quickstart

### FastMCP

```python
from fastmcp import FastMCP
from origo import OAuthProvider, OAuthMiddleware
from starlette.routing import Mount
from starlette.applications import Starlette
import os

auth = OAuthProvider(
    base_url="https://mcp.yourdomain.com",
    clients={os.getenv("MCP_CLIENT_ID"): os.getenv("MCP_CLIENT_SECRET")},
)

mcp = FastMCP("my-server")

# ... define tools ...

mcp_app = mcp.streamable_http_app()
mcp_app.add_middleware(OAuthMiddleware, provider=auth)

# OAuth must be at root so /.well-known/ discovery works for MCP clients
root = Starlette(routes=[
    Mount("/mcp", app=mcp_app),      # protected MCP endpoint
    Mount("/", app=auth.asgi_app()), # /.well-known/, /authorize, /token, /register
])
```

### FastAPI

```python
from fastapi import FastAPI
from origo import OAuthProvider, OAuthMiddleware
from starlette.routing import Mount
from starlette.applications import Starlette
import os

auth = OAuthProvider(
    base_url="https://api.yourdomain.com",
    clients={os.getenv("OAUTH_CLIENT_ID"): os.getenv("OAUTH_CLIENT_SECRET")},
)

api = FastAPI()
api.add_middleware(OAuthMiddleware, provider=auth)

# ... define routes on api ...

app = Starlette(routes=[
    Mount("/api", app=api),          # protected API routes
    Mount("/", app=auth.asgi_app()), # OAuth at root
])
```


### MCP over SSE (`/sse`) deployments

Some MCP clients and hosted connector surfaces expect an SSE MCP endpoint such as `https://mcp.yourdomain.com/sse` instead of a streamable HTTP endpoint such as `/mcp`. Origo does not implement the MCP transport itself; your MCP server or deployment chooses whether `/sse`, `/mcp`, or both exist. Origo should wrap that MCP ASGI app with `OAuthMiddleware`, and `mcp_path` must match the externally visible protected MCP route so `/.well-known/oauth-protected-resource` advertises the same resource URI the client will request.

```python
from fastmcp import FastMCP
from origo import OAuthMiddleware, OAuthProvider
from starlette.applications import Starlette
from starlette.routing import Mount
import os

auth = OAuthProvider(
    base_url="https://mcp.yourdomain.com",
    clients={os.getenv("MCP_CLIENT_ID"): os.getenv("MCP_CLIENT_SECRET")},
    mcp_path="/sse",  # resource metadata becomes https://mcp.yourdomain.com/sse
)

mcp = FastMCP("my-server")

# Use your MCP framework's SSE ASGI app here. The exact constructor varies by
# framework/version; for FastMCP this may be `sse_app()` in SSE deployments.
sse_app = mcp.sse_app()
sse_app.add_middleware(OAuthMiddleware, provider=auth)

app = Starlette(routes=[
    Mount("/sse", app=sse_app),       # protected SSE MCP endpoint
    Mount("/", app=auth.asgi_app()), # OAuth and /.well-known/ discovery
])
```

If your server exposes both `/mcp` and `/sse`, create the protected-resource metadata for the endpoint your connector is configured to call. For multiple public MCP resources on one host, use separate `OAuthProvider` instances or deploy separate base URLs so each provider advertises one canonical `resource` value.

## How this differs from enterprise OAuth

Traditional OAuth deployments separate the authorization server from the resource server — the MCP server asks a dedicated auth service "is this token valid?" on every request (RFC 7662 token introspection). This is correct for multi-tenant systems where tokens need to be revoked instantly across many services.

`origo` collapses this into a single process. Token validation is an in-memory lookup. Fast, zero network overhead, no second service to run. The tradeoff is that token revocation requires a server restart, and there's no centralized auth service to share across multiple resource servers. This also introduce a single point of failure and security relies on the shared memory with the application it is authenticating for.

**Use this when:**

- You're running a personal or private server (ex. MCP server) with simple OAuth requirements
- You control who gets client credentials
- Operational simplicity matters more than enterprise auth guarantees

**Use a proper auth server (Keycloak, Auth0, etc.) when:**

- Multiple users need independent identities
- You need instant token revocation
- You're sharing one auth service across many servers (ex. MCP servers)
- Compliance requirements mandate it

## Two Modes

### Private (default)

Only pre-registered clients can authenticate. Pass a `clients` dict:

```python
auth = OAuthProvider(
    base_url="https://mcp.yourdomain.com",
    clients={"my-client-id": "my-client-secret"},
    public_registration=False,  # default
)
```

### Public

Anyone can register as a client dynamically (DCR). A consent page is shown before access is granted:

```python
auth = OAuthProvider(
    base_url="https://mcp.yourdomain.com",
    public_registration=True,
)
```

Dynamically registered clients must supply `redirect_uris` at registration time. The `/authorize` endpoint validates the `redirect_uri` parameter against that registered list and rejects any URI not on it. Pre-registered clients (supplied via `clients=`) have no such restriction — any redirect URI is accepted, since the operator controls both sides.

By default, dynamically registered `redirect_uris` must use `https` (or `http://localhost`/`127.0.0.1`/`::1` for the RFC 8252 §7.3 native-app loopback exemption). Native/mobile app clients that use a private-use URI scheme instead (RFC 8252 §7.1, e.g. `myapp://callback`) are rejected unless the operator explicitly opts in:

```python
auth = OAuthProvider(
    base_url="https://mcp.yourdomain.com",
    public_registration=True,
    custom_redirect_uri_schemes=["myapp"],
)
```

Only schemes listed here are accepted — arbitrary `foo://` schemes are always rejected, since an unclaimed scheme could be registered by another app on the same device.

## Options

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `base_url` | `str` | required | Public base URL, no trailing slash |
| `clients` | `dict` | `None` | Pre-registered `{client_id: client_secret}` |
| `client_redirect_uris` | `dict` | `None` | Optional redirect URI allowlist for pre-registered clients |
| `public_registration` | `bool` | `False` | Allow dynamic client registration |
| `auto_approve` | `bool` | `False` | Skip consent page, auto-approve all valid clients |
| `token_ttl` | `int` | `3600` | Access token lifetime in seconds |
| `refresh_token_ttl` | `int` | `2592000` (30 days) | Refresh token lifetime in seconds. Refresh tokens are single-use and rotated on every `/token` request |
| `client_ttl` | `int` | `None` | Lifetime in seconds for dynamically-registered clients (DCR `/register` or CIMD). `None` means no expiration. Pre-registered `clients=` are always permanent |
| `max_dynamic_clients` | `int` | `1000` | Max number of dynamically-registered clients (DCR/CIMD) kept in memory; oldest is evicted on overflow. Pre-registered `clients=` don't count against this cap |
| `mcp_path` | `str` | `"/mcp"` | Path where MCP endpoint is mounted |
| `scopes_supported` | `list[str]` | `[]` | OAuth/OIDC scopes advertised in metadata |
| `resource_documentation` | `str` | `None` | Optional URL added to protected resource metadata |
| `user_email` | `str` | `None` | Optional static email claim returned by lightweight OIDC `/userinfo` |
| `allow_private_cimd` | `bool` | `False` | Allow CIMD `client_id` documents to be fetched from private/loopback/link-local hosts (see [CIMD and SSRF hardening](#cimd-and-ssrf-hardening)) |
| `custom_redirect_uri_schemes` | `list[str]` | `None` | Private-use URI schemes (RFC 8252 §7.1, e.g. `["myapp"]`) accepted as `redirect_uris` during dynamic registration, for native app clients |

## OAuth Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /.well-known/oauth-authorization-server` | OAuth discovery |
| `GET /.well-known/openid-configuration` | OpenID Connect discovery |
| `GET /.well-known/oauth-protected-resource` | Resource metadata |
| `POST /register` | Dynamic client registration (public mode only) |
| `GET /authorize` | Show consent page (or redirect immediately if `auto_approve=True`) |
| `POST /authorize` | Submit consent form |
| `POST /token` | Token exchange |
| `GET/POST /userinfo` | Lightweight OIDC userinfo endpoint for `openid` tokens |


## OpenAI platform compatibility

`origo` includes the OAuth behavior needed by OpenAI platform MCP clients that connect to protected MCP servers:

- Protected resource metadata advertises the canonical MCP resource and optional scopes/documentation.
- OAuth discovery advertises PKCE (`S256`), Client ID Metadata Document (CIMD) support, Dynamic Client Registration (DCR), OpenID Connect discovery, and token endpoint authentication methods including public PKCE clients (`none`).
- Dynamic client registration accepts `token_endpoint_auth_method=none` for clients that should exchange authorization codes without a client secret.
- CIMD clients can use an HTTPS metadata document URL as `client_id`; `origo` fetches it, validates redirect URIs, and treats it as a public PKCE client when the document requests `token_endpoint_auth_method=none`.
- The optional OAuth `resource` parameter is preserved from `/authorize` to `/token` and stored with the issued access token metadata, so applications can verify which MCP resource the token was minted for.
- `/token` issues a `refresh_token` alongside every access token. Long-lived MCP clients can exchange it (`grant_type=refresh_token`) for a new access token without a full interactive re-authorization once `token_ttl` expires. Refresh tokens are single-use — each `/token` call rotates in a new one — and are scoped to the same `client_id`/`resource` as the token they replaced.
- `WWW-Authenticate` challenges include `resource_metadata` so ChatGPT can discover OAuth metadata when an unauthenticated tool call reaches the server.
- Optional lightweight OIDC support exposes `/.well-known/openid-configuration`, returns an unsigned `id_token` for `openid` requests, and serves `/userinfo` with `sub` plus `email` when `user_email` is configured and the token has the `email` scope.

For ChatGPT connectors, register the redirect URI shown in ChatGPT (for example, `https://chatgpt.com/connector/oauth/{callback_id}`) and use your public MCP endpoint as the `resource` value, typically `https://your-domain.example/mcp`.

### CIMD and SSRF hardening

A CIMD `client_id` is a URL supplied by whoever is calling `/authorize` — it isn't something `origo` chose, so it's attacker-controlled input. By default `origo` refuses to fetch a CIMD document from a hostname that resolves to a private, loopback, link-local, reserved, or multicast address, and it never follows HTTP redirects when fetching one. Both protections close the same class of bug: a malicious `client_id` URL trying to make your server issue a request to something on its internal network (cloud metadata endpoints, internal admin panels, etc.) instead of a legitimate public client registry.

Some deployments genuinely need to relax the host check — for example, an agent runtime and its `origo` instance colocated on the same private network or host, where the agent's CIMD document is intentionally served from an internal address rather than a public one. For that case, set `allow_private_cimd=True`:

```python
auth = OAuthProvider(
    base_url="https://mcp.internal.example.com",
    public_registration=True,
    allow_private_cimd=True,  # only if your CIMD documents are meant to live on your private network
)
```

`allow_private_cimd` only lifts the private-host restriction — the redirect-refusing fetch still applies unconditionally, so a CIMD host (private or public) still can't retarget the request via a 302 after the fact. Only enable it when you control, or otherwise trust, every host reachable from wherever `origo` runs; on a shared or multi-tenant network it reopens the SSRF surface the default configuration exists to close.

### Secure MCP tunnels

OpenAI Secure MCP Tunnel support is transport-level: run OpenAI's `tunnel-client` next to your private MCP server and point it at the local Origo-protected MCP URL. Origo's OAuth endpoints still need to be reachable for browser-facing authorization flows, either publicly or from wherever `tunnel-client` can forward discovery and MCP requests. Origo does not vendor or replace `tunnel-client`; it provides the OAuth/MCP metadata behavior the tunnel path preserves.

For the issue-by-issue compatibility triage behind this guidance, see [`docs/openai-connector-triage.md`](docs/openai-connector-triage.md).
