# Clients

Every client takes an `AuthContext` and gets its tokens from it. The clients are async;
[blocking versions](#blocking-clients) have the same names and methods. Use a client in an
`async with` block, or call `await client.aclose()` when done.

```python
async with GraphClient(auth, scopes=["User.Read.All"]) as graph:
    users = await graph.get_all("/users")
```

Every client retries throttled requests, gets a new token when the service asks for one, and
never sends its token to a different host. See [errors and retries](errors.md).

## Microsoft Graph

```python
from azure_auth import GraphClient

async with GraphClient(auth, scopes=["User.Read.All"], api_version="beta") as graph:
    me = await graph.get("/me")
    users = await graph.get_all("/users", params={"$top": 999})  # follows @odata.nextLink
    async for page in graph.iter_pages("/groups"):
        ...
    created = await graph.post("/groups", json=new_group)
    results = await graph.batch([{"method": "GET", "url": "/me"}, ...])  # 20 per call
```

- `get`, `post`, `patch`, `put` and `delete` return the parsed JSON body.
- `batch()` returns one response per request, in request order. Failed requests in the batch
  are returned with their status, not raised.
- `api_version` is `v1.0` (default) or `beta`.

## Azure Resource Manager

Every call needs the resource provider's `api_version`.

```python
from azure_auth import ArmClient

async with ArmClient(auth) as arm:
    groups = await arm.get_all(f"/subscriptions/{sub}/resourcegroups", api_version="2021-04-01")
    started = await arm.send("PUT", path, api_version="2021-04-01", json=body)
    resource = await arm.wait(started)  # polls Azure-AsyncOperation or Location
```

To use the Azure management SDKs instead, see [Azure SDKs](#azure-sdks).

## Exchange Online and Security & Compliance

```python
from azure_auth import ExchangeClient, IppsClient

async with ExchangeClient(auth) as exchange:
    mailboxes = await exchange.run("Get-Mailbox", IncludeInactive=True)
    print(exchange.last_warnings)

async with IppsClient(auth) as ipps:
    labels = await ipps.run("Get-Label")
```

- Cmdlet parameters are keyword arguments: a string or number for a plain parameter, a list
  for a multi-valued one, `True` for a switch. Results are dictionaries.
- `run()` fetches every page and returns all results. `iter_pages()` returns one page at a
  time, so you can stop early.
- After each `run()`, `last_warnings` holds the warnings the cmdlet returned.
- A failed cmdlet raises `InvokeCommandError`. The message starts with the cmdlet name and
  Exchange's reason; `status`, `code` and the full `body` are on the exception. Exchange
  answers an unknown cmdlet and a cmdlet the account's roles don't allow with the same 403 and
  no body, so the message names both possible causes.

**`ResultSize` does nothing.** The PowerShell module applies it itself instead of sending it,
so the service ignores it. To limit results, stop reading `iter_pages()` yourself. Each page
has its results under `value`:

```python
mailboxes = []
async for page in exchange.iter_pages("Get-Mailbox"):
    mailboxes.extend(page["value"])
    if len(mailboxes) >= 10:
        break
```

### Reading Exchange objects without a cmdlet

These methods use the same REST endpoints as the module's faster `Get-EXO*` cmdlets. They
return only the properties you ask for, while `Get-Mailbox` returns every property of every
mailbox.

```python
async with ExchangeClient(auth) as exchange:
    audited = await exchange.mailboxes(
        PropertySet="Audit",
        RecipientTypeDetails=["UserMailbox", "SharedMailbox"],
        select=["UserPrincipalName", "DefaultAuditSet"],
    )
    one = await exchange.mailboxes("someone@contoso.com")
    permissions = await exchange.mailbox_permissions("someone@contoso.com")
```

- One method per cmdlet: `mailboxes`, `cas_mailboxes`, `recipients`, `mailbox_permissions`,
  `mailbox_folder_permissions`, `mailbox_statistics`, `mailbox_folder_statistics`,
  `mobile_device_statistics` and `recipient_permissions`.
- Options use the same names the cmdlets send. A list is sent comma-separated, `True` is a
  switch, and `select`, `filter` and `expand` are OData's `$select`, `$filter` and `$expand`.
- An identity can be any form the cmdlets accept: UPN, SMTP address, GUID, external directory
  object id or name.
- `get(path, ...)` reads any path under the service root; `iter_get_pages()` returns one page
  at a time.

### The endpoint is undocumented

Both clients use the `InvokeCommand` REST endpoint behind the ExchangeOnlineManagement
PowerShell module. **Microsoft does not document it.** The request format was taken from module
version 3.10.1, and may change without notice. The request details are in the
[reference](reference/clients.md).

- Exchange routes each request by its `X-AnchorMailbox` header. The client sets it to the
  signed-in user in their own tenant, and to the tenant's system mailbox for app sign-ins and
  GDAP customers. To set another, pass `anchor_mailbox=`:

```python
exchange = ExchangeClient(auth, anchor_mailbox="UPN:someone@contoso.com")
```

- Security & Compliance redirects the first call to a regional host. The client follows the
  redirect and keeps using that host.
- Cmdlets can be slow: the default timeout is 300 seconds. `page_size=` sets the preferred
  page size (default 1000).

For app sign-ins, see the [per-resource setup](app-certificate.md#per-resource-setup).

## Key Vault

Needs the `keyvault` extra.

```python
from azure_auth.clients.keyvault import KeyVaultClient

async with KeyVaultClient(auth, "https://contoso.vault.azure.net") as vault:
    password = await vault.get_secret("service-password")
    certificate_der = await vault.get_certificate("signing")  # public part only
    signature = await vault.sign("signing-key", "PS256", digest)
    valid = await vault.verify("signing-key", "PS256", digest, signature)
```

A small wrapper around the Azure SDK. It raises `KeyVaultError` and `NetworkError`, not the
SDK's exceptions. For anything else, use the SDK clients directly (below).

## Azure SDKs

`AuthContext` is an Azure SDK `TokenCredential`, and `auth.aio` an `AsyncTokenCredential`.
Pass either as `credential=`:

```python
from azure.keyvault.secrets import SecretClient
from azure.keyvault.secrets.aio import SecretClient as AsyncSecretClient
from azure.mgmt.resource import ResourceManagementClient

secrets = SecretClient("https://contoso.vault.azure.net", credential=auth)
resources = ResourceManagementClient(credential=auth, subscription_id=sub)

async with AsyncSecretClient("https://contoso.vault.azure.net", credential=auth.aio) as client:
    secret = await client.get_secret("service-password")
```

- User sign-ins use the Azure PowerShell client id, unless the context sets another.
- The SDK clients raise their own exceptions, not this package's.
- Every token supports continuous access evaluation, whether or not the SDK asks for it.

## Blocking clients

`azure_auth.sync` has the same classes and methods without `await`. They are generated from the
async clients, so they behave the same.

```python
from azure_auth import AuthContext
from azure_auth.sync import GraphClient
from azure_auth.sync.keyvault import KeyVaultClient

auth = AuthContext("contoso.com", username="admin@contoso.com")

with GraphClient(auth, scopes=["User.Read.All"]) as graph:
    users = graph.get_all("/users")

with KeyVaultClient(auth, "https://contoso.vault.azure.net") as vault:
    password = vault.get_secret("service-password")
```

Close a blocking client with a `with` block or `close()`. `AuthContext` itself is synchronous;
`auth.aio` is its async interface.

## Common client options

| Argument | Default | Does |
|---|---|---|
| `client_id=` | see [client ids](client-ids-and-consent.md#client-ids) | The application to sign in to. |
| `scopes=` | `<resource>/.default` | Delegated scopes, for user sign-ins. |
| `timeout=` | 100 seconds (300 for Exchange) | Timeout for each HTTP request. |
| `max_retries=` | 3 | How often a throttled request is retried. |
| `max_retry_wait=` | 120 seconds | Longest wait before one retry. |

```python
graph = GraphClient(auth, scopes=["User.Read.All"], timeout=30, max_retries=5)
```
