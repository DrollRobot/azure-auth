# Managed identity

Code on an Azure host signs in with the host's managed identity: no secret, no certificate,
nothing stored on disk. Azure gives the host its tokens through a local endpoint. There are two
ways to use it:

| | [Sign in as the identity](#sign-in-as-the-identity) | [The identity as an app's credential](#a-managed-identity-as-an-apps-credential) |
|---|---|---|
| Signs in as | the identity | an application registration |
| Permissions are given to | the identity | the application |
| Identity type | system- or user-assigned | user-assigned only |
| Arguments | `managed_identity=True` | `client_id=`, `managed_identity_client_id=` |

Sign in as the identity, unless an application registration already has the permissions you
need, such as one that also runs outside Azure with a [certificate](app-certificate.md).

Supported hosts: Container Apps and their jobs, App Service and Functions, virtual machines and
scale sets, Azure Arc, Service Fabric and Azure Machine Learning. The context finds the
endpoint from the host's environment variables.

## Sign in as the identity

### Azure setup

1. Turn on the host's system-assigned identity, or attach a user-assigned identity to it.
2. Give the identity a role on each resource it uses:

```bash
az role assignment create \
  --assignee-object-id <identity principal id> \
  --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets User" \
  --scope <vault resource id>
```

The Azure portal can't give Microsoft Graph application permissions to a managed identity. An
administrator can do it with this package:

```python
from azure_auth import AuthContext, GraphClient

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

admin = AuthContext("contoso.com", username="admin@contoso.com")
scopes = ["Application.Read.All", "AppRoleAssignment.ReadWrite.All"]
async with GraphClient(admin, scopes=scopes) as graph:
    graph_sp = await graph.get(f"/servicePrincipals(appId='{GRAPH_APP_ID}')")
    role = next(role for role in graph_sp["appRoles"] if role["value"] == "User.Read.All")
    await graph.post(
        f"/servicePrincipals/{IDENTITY_PRINCIPAL_ID}/appRoleAssignments",
        json={
            "principalId": IDENTITY_PRINCIPAL_ID,
            "resourceId": graph_sp["id"],
            "appRoleId": role["id"],
        },
    )
```

### Example

```python
import asyncio

from azure_auth import AuthContext
from azure_auth.clients.keyvault import KeyVaultClient

TENANT_ID = "<tenant id>"
IDENTITY_CLIENT_ID = "<client id of the user-assigned identity>"


async def main() -> None:
    auth = AuthContext(TENANT_ID, managed_identity=True, client_id=IDENTITY_CLIENT_ID)
    async with KeyVaultClient(auth, "https://contoso.vault.azure.net") as vault:
        password = await vault.get_secret("service-password")


asyncio.run(main())
```

Every client works with it: `GraphClient(auth)`, `ArmClient(auth)`, and the Azure SDK clients
with `credential=auth`.

### System-assigned or user-assigned

```python
auth = AuthContext(TENANT_ID, managed_identity=True)  # system-assigned
auth = AuthContext(TENANT_ID, managed_identity=True, client_id=IDENTITY_CLIENT_ID)
```

- `client_id=` selects a user-assigned identity. Without it, the context uses the
  system-assigned identity, and reads its client id from the first token. The context never
  picks the identity from environment variables.
- On a virtual machine with exactly one user-assigned identity, a request for the
  system-assigned identity may get a token for the user-assigned one.

### Tenant or cloud

```python
auth = AuthContext(TENANT_ID, managed_identity=True)  # looks the tenant up
auth = AuthContext(cloud="Commercial", managed_identity=True)  # no lookup
```

A managed identity only gets tokens for its own tenant, so it doesn't need the tenant to sign
in. The clients do need the cloud, to know which service URLs to call. `cloud=` skips the
tenant lookup; `auth.tenant.id` is then `None` until the first token. If unsure, pass the
tenant.

### Fail at startup

Otherwise, a missing identity fails at the first request. To find out at startup, ask for a
token:

```python
await auth.aio.acquire_token_silently(["https://vault.azure.net/.default"])
```

Getting a token shows that the identity is on the host, not that it has the roles it needs. A
missing role fails later, as a 403 from the resource (`KeyVaultError`, `GraphError`, ...).

### Limits

- Each token is for one resource, as `<resource>/.default`. The clients already ask this way.
  Passing delegated scopes raises `ValueError`.
- Own tenant only. `get_tenant_context()` raises `ValueError` for any other tenant. A vault in
  another tenant fails with an `AuthError` that says so.
- `cache="disk"` works but doesn't help: the endpoint is on the host.

### Errors

| Error | Cause |
|---|---|
| `ManagedIdentityUnavailable` | Not on an Azure host, or the host has no identity. Fails within two seconds. |
| `AuthError` | The endpoint refused, for example because the client id isn't assigned to the host. The message names the identity, the endpoint and the reason. |
| `NetworkError` | The endpoint the host advertises did not answer. |

The context never falls back to another sign-in method.

## A managed identity as an app's credential

An application registration signs in with the host's user-assigned identity as its credential,
instead of a secret or certificate. The tokens are for the application, so the identity itself
needs no roles.

### Entra setup

1. Attach a user-assigned identity to the host.
2. On the application registration, add a federated credential that trusts the identity:
   Certificates & secrets, Federated credentials, scenario "Managed identity".
3. Give the application the permissions and roles it needs, as for any
   [app sign-in](app-certificate.md#entra-setup).

Step 2 from the command line:

```bash
az ad app federated-credential create --id <application client id> --parameters credential.json
```

```json
{
  "name": "host-identity",
  "issuer": "https://login.microsoftonline.com/<tenant id>/v2.0",
  "subject": "<identity principal id>",
  "audiences": ["api://AzureADTokenExchange"]
}
```

The audience is `api://AzureADTokenExchangeUSGov` in US Government (GCC High and DoD) and
`api://AzureADTokenExchangeChina` in China, with that cloud's sign-in host in the issuer. A new
federated credential can take a few minutes to start working.

### Example

```python
import asyncio

from azure_auth import AuthContext
from azure_auth.clients.keyvault import KeyVaultClient


async def main() -> None:
    auth = AuthContext(
        TENANT_ID,
        client_id=APP_CLIENT_ID,
        managed_identity_client_id=IDENTITY_CLIENT_ID,
    )
    # Fail now if the identity or the trust is missing.
    await auth.aio.acquire_token_silently(["https://vault.azure.net/.default"])

    async with KeyVaultClient(auth, "https://contoso.vault.azure.net") as vault:
        password = await vault.get_secret("service-password")


asyncio.run(main())
```

- It works like any other app sign-in: every client works, with `<resource>/.default`.
- The identity's token is kept in memory only, not in the context's cache. The context reuses
  it for every resource until it is close to expiring.
- Own tenant only, for now: `get_tenant_context()` raises `ValueError` for any other tenant.

### Errors

| Error | Cause |
|---|---|
| `ManagedIdentityUnavailable` | Not on an Azure host. |
| `AuthError` from the endpoint | The host does not have that identity. Raised before anything is sent to Entra. |
| `AuthError`, AADSTS70021 or 700213 | The application has federated credentials, but none trusts this identity. |
| `AuthError`, AADSTS70025 | The application has no federated credential at all. |

Errors from Entra start with Entra's reason, and name the application and the identity. They
are not retried, and the context doesn't fall back to another sign-in method.
