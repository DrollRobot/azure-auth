# Guide

## How it fits together

`AuthContext` holds one tenant, one set of credentials, one token cache and, for user flows,
one account. Resource clients hold an `AuthContext` and ask it for tokens. Nothing talks to
the network until the first token is needed.

```python
auth = AuthContext("contoso.onmicrosoft.com", username="admin@contoso.com")
graph = GraphClient(auth, scopes=["User.Read.All"])
exchange = ExchangeClient(auth)
```

## Flows

A context runs exactly one flow, decided by its arguments.

| Flow | Arguments |
|---|---|
| User | `username=` (required), optional `broker=True` |
| App, secret | `client_id=`, `client_secret=` |
| App, PEM | `client_id=`, `certificate_pem=`, `private_key_pem=`, optional `certificate_password=` |
| App, PFX | `client_id=`, `certificate_pfx=` (bytes or path), optional `certificate_password=` |
| App, Windows certificate store | `client_id=`, `certificate_thumbprint=`, optional `certificate_store="LocalMachine"` |

Secrets and key material are only held in memory. Load them from Key Vault or a keyring, not
from source or a plain-text file.

### Signing in

Signing in is lazy: the first request prompts if it has to. To choose the moment, call
`await client.login()`. Pass `force=True` to prompt even when a token is cached.

`username` selects the cached account and pre-fills the sign-in page. If somebody else signs
in, the context raises `AuthError`, because their tokens would never be found again.

### The Windows broker

`broker=True` signs in through the Windows Web Account Manager. It needs the `broker` extra.
When the broker is missing or fails, the context falls back to the browser. Pass
`broker_fallback=False` to get `BrokerUnavailable` instead. A user who cancels the broker
prompt is not sent to the browser.

## Client ids and scopes

Each client picks its client id in this order:

1. `client_id=` on the client.
2. `client_id=` on the `AuthContext`.
3. The first-party default of the client (user flows only).

App flows never use a first-party id; without a client id they raise `ValueError`.

| Client | Default client id (user flows) | Default scope |
|---|---|---|
| `GraphClient` | Microsoft Graph PowerShell | `scopes=` argument, else `https://graph.microsoft.com/.default` |
| `AzureClient`, `KeyVaultClient`, Azure SDK clients | Azure PowerShell | `https://management.azure.com/.default`, `https://vault.azure.net/.default` |
| `ExchangeClient` | Exchange Online PowerShell | `https://outlook.office365.com/.default` |
| `IppsClient` | Exchange Online PowerShell | `https://ps.compliance.protection.outlook.com/.default` |

Two things follow from that table:

- **Each distinct client id needs its own sign-in.** Using Graph and Exchange means two
  prompts. Browser single sign-on makes the second one quick. Giving the context your own
  `client_id` with all the permissions you need avoids it.
- **Pass `scopes=` to `GraphClient` in user flows.** The Microsoft Graph PowerShell
  application works by dynamic consent. `.default` only returns scopes that were consented to
  in the tenant before, which in a fresh tenant is close to nothing. Short names such as
  `User.Read.All` are qualified for you. App flows always use `.default`.

### Consent

Entra shows a consent screen by itself the first time an application is asked for delegated
scopes it has not been granted, so in an ordinary interactive sign-in consent happens without
this package doing anything. Asking for more scopes later works the same way: the cached token
does not match the new scopes, the silent attempt fails, and the browser opens again.

The screen decides what is granted, not this package:

- A user who may consent for themselves grants it for themselves.
- An administrator sees a **Consent on behalf of your organization** checkbox. For a
  permission that requires admin consent there is no other form: Entra grants those to the
  whole tenant or not at all, so every user in the tenant gets them through that client id.

**This package never grants consent on its own and offers no way to do so without that
click.** Granting consent is a tenant-wide security change, not something a token request
should do as a side effect.

When a sign-in ends without a token, what comes back is usually `access_denied`, with no
error code to say why. A user who may not consent is shown **Need admin approval**, and
leaving that page produces exactly the same `access_denied` as pressing Cancel on an ordinary
consent screen. The two cannot be told apart, so the library does not reopen the browser on
either — it raises `AuthError` naming the scopes and the tenant, and saying both things it can
mean.

Sibling contexts from `for_tenant()` never prompt at all, so they report `ConsentRequired` and
stop. Consent for a customer tenant has to be granted in that tenant.

## Token cache

| `cache=` | Behaviour |
|---|---|
| `"memory"` (default) | Tokens live as long as the process. |
| `"disk"` | Tokens are kept in an encrypted file: DPAPI on Windows, Keychain on macOS, libsecret on Linux. |

`cache_path=` sets the file. The default is a file in the per-user cache directory.

There is no unencrypted disk cache. Where the platform cannot encrypt, for example Linux
without libsecret, `cache="disk"` raises `CacheEncryptionUnavailable`. It never falls back to
plain text and never silently switches to the memory cache.

## Multi-tenant access (GDAP)

`auth.for_tenant(tenant_id)` returns a sibling context for another tenant. It shares the
credentials, the cache and the username, and makes no network call, so it is cheap to call
in a loop.

```python
partner = GraphClient(auth, scopes=["DelegatedAdminRelationship.Read.All"])
await partner.login()

for tenant_id in await partner.list_customer_tenant_ids():
    graph = GraphClient(auth.for_tenant(tenant_id), scopes=["User.Read.All"])
    try:
        users = await graph.get_all("/users")
    except (ConsentRequired, InteractionRequired) as error:
        print(f"skipping {error.tenant_id}: {error}")
```

- A sibling **never prompts.** When a token cannot be obtained silently it raises
  `InteractionRequired` or `ConsentRequired`, and the error carries the tenant id. Sign in on
  a client of the root context first.
- `list_customer_tenant_ids()` reads `GET /tenantRelationships/delegatedAdminCustomers` and
  needs `DelegatedAdminRelationship.Read.All` consented in the partner tenant.
- The application must be consented to in each customer tenant for the scopes you request.
- In app flows each sibling builds its own client assertion, because the assertion audience
  is the tenant's token endpoint.

## Certificates in the Windows certificate store

With `certificate_thumbprint=` the private key never leaves the key storage provider, so
non-exportable and TPM-backed keys work. Only CNG keys are supported, not legacy CryptoAPI
keys.

The client assertion is signed **PS256** first, which is what Microsoft documents together
with the `x5t#S256` header. If the key provider refuses PSS padding, or Entra ID rejects the
signature (`AADSTS700027`), the credential switches to **RS256** and stays there.

For `certificate_store="LocalMachine"` the account running the process needs read access to
the private key (certlm.msc, certificate, All Tasks, Manage Private Keys).

On other platforms use `certificate_pem=` or `certificate_pfx=`.

## Requests, retries and errors

Every client:

- retries 429 and 503, waiting for `Retry-After` when the service sends it (`max_retries=`,
  `max_retry_wait=`);
- answers a 401 that carries a claims challenge (continuous access evaluation) by getting a
  new token with those claims, and any other 401 by refreshing the token once;
- refuses to send its token to another host. A next link or operation URL that points
  elsewhere raises `ValueError`.

Errors:

```
AuthError
├── InteractionRequired(tenant_id, scopes)
├── ConsentRequired(tenant_id, scopes)
├── AccountSelectionRequired
├── CertificateUnavailable
├── CacheEncryptionUnavailable
└── BrokerUnavailable
ResourceError(status, code, request_id, body)
├── GraphError
├── AzureError
└── InvokeCommandError
```

MSAL result dictionaries never reach your code.

## Microsoft Graph

```python
async with GraphClient(auth, scopes=["User.Read.All"], api_version="beta") as graph:
    me = await graph.get("/me")
    users = await graph.get_all("/users", params={"$top": 999})  # follows @odata.nextLink
    async for page in graph.iter_pages("/groups"):
        ...
    results = await graph.batch([{"method": "GET", "url": "/me"}, ...])  # 20 per call
```

`batch()` returns one response per request in request order. Failed items come back with
their status; they are not raised.

## Azure Resource Manager

Every call needs the `api_version` of the resource provider.

```python
async with AzureClient(auth) as arm:
    groups = await arm.get_all(f"/subscriptions/{sub}/resourcegroups", api_version="2021-04-01")
    started = await arm.send("PUT", path, api_version="2021-04-01", json=body)
    resource = await arm.wait(started)  # polls Azure-AsyncOperation or Location
```

For the typed management SDKs no client is needed: pass `credential=auth` (or `auth.aio`).

## Exchange Online and Security & Compliance

```python
async with ExchangeClient(auth) as exchange:
    mailboxes = await exchange.run("Get-Mailbox", IncludeInactive=True)
    print(exchange.last_warnings)

async with IppsClient(auth) as ipps:
    labels = await ipps.run("Get-Label")
```

Cmdlet parameters are keyword arguments; use `True` for switch parameters. Results are
dictionaries.

Both clients use the `InvokeCommand` REST endpoint behind the ExchangeOnlineManagement
PowerShell module. **Microsoft does not document this endpoint.** The request shape was read
from module version 3.10.1:

- URL: `https://<host>/adminapi/beta/<tenant GUID>/InvokeCommand`. The GUID is read from the
  token, so a domain name works as `tenant_id`. `api_version="v1.0"` is also accepted.
- Routing header `X-AnchorMailbox`: `UPN:<username>` for a user in their own tenant, and the
  tenant's system mailbox for app flows and for sibling (GDAP) contexts. Override it with
  `anchor_mailbox=`.
- Security & Compliance redirects the first call to a regional host. The client follows that
  redirect itself, because HTTP libraries drop the `Authorization` header on a cross-host
  redirect, and keeps using the regional host.

- Paging works by POSTing the same body again to `@odata.nextLink`. Confirmed against a live
  tenant: 13 pages with `page_size=2`, each page after the first fetched from the link.
  `run()` walks every page, so it returns the whole result set; use `iter_pages()` to stop
  early.

`ResultSize` does nothing here. In the PowerShell module it is a client-side cap applied
while consuming pages, not a cmdlet parameter, so `InvokeCommand` ignores it — silently, with
no warning, in every spelling (`10`, `"10"`, `"Unlimited"`). `run("Get-Mailbox", ResultSize=10)`
returns every mailbox in the tenant. To limit results, break out of `iter_pages()` yourself.

The `X-ResponseFormat` and `X-CmdletName` headers were reconstructed from memory rather than
found in the module assemblies. Live calls succeed with them, which shows they are accepted,
not that they are required or correct.

App flows need the `Exchange.ManageAsApp` application permission and an Exchange
administrator role on the service principal.

## Key Vault

Needs the `keyvault` extra.

```python
from azure_auth.clients.keyvault import KeyVaultClient

async with KeyVaultClient(auth, "https://contoso.vault.azure.net") as vault:
    password = await vault.get_secret("service-password")
    certificate_der = await vault.get_certificate("signing")
    signature = await vault.sign("signing-key", "PS256", digest)
```

This is a thin wrapper over the Azure SDK. For anything else use the SDK clients directly
with `credential=auth.aio`.

## Blocking clients

`azure_auth.sync` has the same classes and methods without `await`. They are generated from
the async clients, so behaviour is identical.

```python
from azure_auth.sync import GraphClient
from azure_auth.sync.keyvault import KeyVaultClient

with GraphClient(auth, scopes=["User.Read.All"]) as graph:
    users = graph.get_all("/users")
```

`AuthContext` itself is synchronous and is an Azure SDK `TokenCredential`. `auth.aio` is the
async view and an `AsyncTokenCredential`.
