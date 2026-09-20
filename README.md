# azure-auth

[![CI](https://github.com/DrollRobot/azure-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/DrollRobot/azure-auth/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.14%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Authentication for Microsoft cloud services, so that other packages do not have to deal with
it. Create one `AuthContext`, hand it to the client for the resource you need, and make
requests. The client gets, caches and refreshes tokens.

- **Resources:** Microsoft Graph, Azure Resource Manager, Exchange Online, Security &
  Compliance (IPPS) and Key Vault. Any `azure-*` SDK client also accepts the context as its
  `credential`.
- **User sign-in:** browser, or the Windows broker (WAM) with a browser fallback.
- **App sign-in:** client secret, PEM/PFX certificate, or a certificate in the Windows
  certificate store whose private key cannot be exported (TPM-backed keys included).
- **No app registration needed for users:** each client defaults to the matching Microsoft
  first-party client id. Pass `client_id=` to use your own.
- **Caching:** in memory, or an encrypted file so a script does not prompt on every run.
  There is no unencrypted disk cache.
- **Multi-tenant (GDAP):** sign in once to the partner tenant, then reach customer tenants
  without further prompts.
- **Async first,** with generated blocking clients in `azure_auth.sync`.

> **Status:** the unit and integration suites pass, including signing with a real
> non-exportable key. Nothing has been run against a live tenant yet. The Exchange and
> Security & Compliance clients use an undocumented endpoint; see
> [the guide](docs/guide.md#exchange-online-and-security--compliance).

## Installation

```bash
uv add git+https://github.com/DrollRobot/azure-auth.git

# optional extras
uv add "azure-auth[keyvault] @ git+https://github.com/DrollRobot/azure-auth.git"  # Key Vault
uv add "azure-auth[broker] @ git+https://github.com/DrollRobot/azure-auth.git"    # Windows broker
```

## Usage

Sign in as a user and call Microsoft Graph:

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

The first request opens the browser. With `cache="disk"` later runs are silent. Call
`await graph.login()` to choose when the prompt appears.

Sign in as an application with a certificate from the Windows certificate store:

```python
auth = AuthContext(
    "contoso.onmicrosoft.com",
    client_id="00000000-0000-0000-0000-000000000000",
    certificate_thumbprint="A1B2C3...",  # CurrentUser\My; the key may be non-exportable
)
```

Run an Exchange Online cmdlet without PowerShell:

```python
from azure_auth import ExchangeClient

async with ExchangeClient(auth) as exchange:
    mailboxes = await exchange.run("Get-Mailbox", ResultSize=10)
```

Work through GDAP customers from one sign-in:

```python
partner = GraphClient(auth, scopes=["DelegatedAdminRelationship.Read.All"])
await partner.login()
for tenant_id in await partner.list_customer_tenant_ids():
    customer = GraphClient(auth.for_tenant(tenant_id), scopes=["User.Read.All"])
    ...
```

Use an Azure SDK client, or the blocking clients:

```python
from azure.keyvault.secrets.aio import SecretClient
from azure_auth.sync import GraphClient as BlockingGraphClient

secrets = SecretClient("https://contoso.vault.azure.net", credential=auth.aio)
users = BlockingGraphClient(auth, scopes=["User.Read.All"]).get_all("/users")
```

See [the guide](docs/guide.md) for client ids, scopes, caching, certificates and errors.

## Development

```bash
uv sync --all-extras                        # create the venv, install everything
uv run pre-commit install                   # commit hooks
uv run pre-commit install --hook-type pre-push
uv run pytest -m "not live"                 # offline tests
uv run python scripts/generate_sync.py      # after changing anything in src/azure_auth/clients
```

The blocking clients in `src/azure_auth/_sync` are generated from the async clients in
`src/azure_auth/clients`. Never edit them by hand. A test fails when they are out of date.

Live tests need a tenant and are configured through environment variables; see the docstring
of `tests/live/test_live.py`. The Windows certificate signer test creates and deletes a
certificate in `Cert:\CurrentUser\My`, so it only runs with `--run-destructive-local`.

## License

MIT. See [LICENSE](LICENSE). The Windows certificate signer follows the design of
[microsoft/entrabot](https://github.com/microsoft/entrabot) (MIT).
