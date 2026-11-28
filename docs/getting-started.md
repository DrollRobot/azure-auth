# Getting started

## Install

Requires Python 3.11 or newer.

```bash
uv add git+https://github.com/DrollRobot/azure-auth.git
```

The package is in beta: until 1.0.0, a minor release may contain breaking changes. Pin a
release tag, and read the
[changelog](https://github.com/DrollRobot/azure-auth/blob/main/CHANGELOG.md) before moving to
a new minor version:

```bash
uv add git+https://github.com/DrollRobot/azure-auth.git --tag v0.13.1
```

## How it works

You use two objects:

- `AuthContext` signs in to Microsoft Entra ID and gets tokens. Its arguments say which
  tenant to sign in to, and who signs in: a user, an app, or a managed identity.
- A client calls one service, such as `GraphClient` for Microsoft Graph or `ExchangeClient`
  for Exchange Online. You pass it an `AuthContext`, and it gets its tokens from it.

Several clients can share one `AuthContext`.

```python
from azure_auth import AuthContext, ExchangeClient, GraphClient

auth = AuthContext("contoso.com", username="admin@contoso.com")
graph = GraphClient(auth, scopes=["User.Read.All"])
exchange = ExchangeClient(auth)
```

## First request

This example signs a user in through the browser, then counts the tenant's users through
Microsoft Graph.

```python
import asyncio

from azure_auth import AuthContext, GraphClient


async def main() -> None:
    auth = AuthContext("contoso.com", username="admin@contoso.com")
    async with GraphClient(auth, scopes=["User.Read.All"]) as graph:
        users = await graph.get_all("/users", params={"$select": "displayName"})
    print(len(users))


asyncio.run(main())
```

## Next

Pick the page for your use case on the [home page](index.md#use-cases), or go
straight to the [clients](clients.md).
