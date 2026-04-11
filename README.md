# origo
> Implements the OAuth flow for a MCP server as a Starlette based middleware layer, with public and private registeration modes.

Drop-in OAuth 2.1 provider for MCP servers. Handles the full Authorization Code + PKCE flow with no external identity provider required.

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

app = mcp.streamable_http_app()
app.add_middleware(OAuthMiddleware, provider=auth)

# Mount OAuth endpoints at root
root = Starlette(routes=[
    Mount("/oauth", app=auth.asgi_app()),
    Mount("/", app=app),
])
```

### FastAPI

```python
from fastapi import FastAPI
from origo import OAuthProvider, OAuthMiddleware
import os

auth = OAuthProvider(
    base_url="https://api.yourdomain.com",
    clients={os.getenv("MCP_CLIENT_ID"): os.getenv("MCP_CLIENT_SECRET")},
)

app = FastAPI()
app.add_middleware(OAuthMiddleware, provider=auth)
app.mount("/oauth", auth.asgi_app())
```

## How this differs from enterprise OAuth
Traditional OAuth deployments separate the authorization server from the resource server — the MCP server asks a dedicated auth service "is this token valid?" on every request (RFC 7662 token introspection). This is correct for multi-tenant systems where tokens need to be revoked instantly across many services.

`origo` collapses this into a single process. Token validation is an in-memory lookup. Fast, zero network overhead, no second service to run. The tradeoff is that token revocation requires a server restart, and there's no centralized auth service to share across multiple resource servers. This also introduce a single point of failure and security relies on the shared memory with the application it is authenticating for.


**Use this when:**

- You're running a personal or private MCP server
- You control who gets client credentials
- Operational simplicity matters more than enterprise auth guarantees

**Use a proper auth server (Keycloak, Auth0, etc.) when:**

- Multiple users need independent identities
- You need instant token revocation
- You're sharing one auth service across many MCP servers
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

## Options

| Parameter | Type | Default | Description |
|---|---|---|---|
| `base_url` | `str` | required | Public base URL, no trailing slash |
| `clients` | `dict` | `None` | Pre-registered `{client_id: client_secret}` |
| `public_registration` | `bool` | `False` | Allow dynamic client registration |
| `auto_approve` | `bool` | `False` | Skip consent page, auto-approve all valid clients |
| `token_ttl` | `int` | `3600` | Access token lifetime in seconds |
| `mcp_path` | `str` | `"/mcp"` | Path where MCP endpoint is mounted |

## OAuth Endpoints

| Endpoint | Description |
|---|---|
| `GET /.well-known/oauth-authorization-server` | Discovery |
| `GET /.well-known/oauth-protected-resource` | Resource metadata |
| `POST /register` | Dynamic client registration (public mode only) |
| `GET /authorize` | Authorization + consent |
| `POST /token` | Token exchange |


