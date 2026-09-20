# azure-auth

Authentication for Microsoft cloud services, so that other packages do not have to deal with
it. Create one `AuthContext`, hand it to the client for the resource you need, and make
requests. The client gets, caches and refreshes tokens.

- Microsoft Graph, Azure Resource Manager, Exchange Online, Security & Compliance and Key
  Vault clients, plus any `azure-*` SDK client through the `credential` argument.
- User sign-in through the browser or the Windows broker. App sign-in with a secret, a
  PEM/PFX certificate, or a non-exportable certificate in the Windows certificate store.
- Microsoft first-party client ids by default, your own with `client_id=`.
- In-memory cache, or an encrypted disk cache. Never an unencrypted one.
- GDAP: one partner sign-in, silent access to customer tenants.
- Async clients, with generated blocking versions in `azure_auth.sync`.

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
