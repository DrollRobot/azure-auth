# azure-auth

Authentication for Microsoft cloud services, so that other packages do not have to deal with
it. Create one `AuthContext`, hand it to the client for the resource you need, and make
requests. The client gets, caches and refreshes tokens.

## Installation

```bash
uv add git+https://github.com/DrollRobot/azure-auth.git

# optional extras: keyvault, broker
uv add "azure-auth[keyvault,broker] @ git+https://github.com/DrollRobot/azure-auth.git"
```

## Quick start

```python
import asyncio
from azure_auth import AuthContext, GraphClient


async def main() -> None:
    auth = AuthContext("contoso.onmicrosoft.com", username="admin@contoso.com", cache="disk")
    async with GraphClient(auth, scopes=["User.Read.All"]) as graph:
        users = await graph.get_all("/users", params={"$select": "displayName"})
    print(len(users))


asyncio.run(main())
```

The first request opens the browser. With `cache="disk"` later runs are silent.

Continue with the [guide](guide.md), or look things up in the [reference](reference/auth.md).
