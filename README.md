# origo

[![CI](https://github.com/ieepirzy/origo/actions/workflows/ci.yml/badge.svg)](https://github.com/ieepirzy/origo/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/origo)](https://pypi.org/project/origo/)
[![Python versions](https://img.shields.io/pypi/pyversions/origo)](https://pypi.org/project/origo/)

> Implements the OAuth2.1 + PKCE flow as a drop-in Starlette based middleware layer, with public and private registration modes.

Drop-in OAuth 2.1 provider, originally developed for use in custom/private MCP servers. Handles the full Authorization Code + PKCE flow with no external identity provider required.

Works with **FastMCP**, **FastAPI**, and the raw **MCP SDK**.

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

## Options

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `base_url` | `str` | required | Public base URL, no trailing slash |
| `clients` | `dict` | `None` | Pre-registered `{client_id: client_secret}` |
| `public_registration` | `bool` | `False` | Allow dynamic client registration |
| `auto_approve` | `bool` | `False` | Skip consent page, auto-approve all valid clients |
| `token_ttl` | `int` | `3600` | Access token lifetime in seconds |
| `mcp_path` | `str` | `"/mcp"` | Path where MCP endpoint is mounted |

## OAuth Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /.well-known/oauth-authorization-server` | Discovery |
| `GET /.well-known/oauth-protected-resource` | Resource metadata |
| `POST /register` | Dynamic client registration (public mode only) |
| `GET /authorize` | Show consent page (or redirect immediately if `auto_approve=True`) |
| `POST /authorize` | Submit consent form |
| `POST /token` | Token exchange |
