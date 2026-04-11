# oauth-mcp
> Implements the OAuth flow for a MCP server as a Starlette based middleware layer, with public and private registeration modes.

Drop-in OAuth 2.1 provider for MCP servers. Handles the full Authorization Code + PKCE flow with no external identity provider required.

Works with **FastMCP**, **FastAPI**, and the raw **MCP SDK**.

## Install

```bash
pip install oauth-mcp
```

## Quickstart

### FastMCP

```python
from fastmcp import FastMCP
from oauth_mcp import OAuthProvider, OAuthMiddleware
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
from starlette.routing import Mount
from starlette.applications import Starlette
root = Starlette(routes=[
    Mount("/oauth", app=auth.asgi_app()),
    Mount("/", app=app),
])
```

### FastAPI

```python
from fastapi import FastAPI
from oauth_mcp import OAuthProvider, OAuthMiddleware
import os

auth = OAuthProvider(
    base_url="https://api.yourdomain.com",
    clients={os.getenv("MCP_CLIENT_ID"): os.getenv("MCP_CLIENT_SECRET")},
)

app = FastAPI()
app.add_middleware(OAuthMiddleware, provider=auth)
app.mount("/oauth", auth.asgi_app())
```

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
