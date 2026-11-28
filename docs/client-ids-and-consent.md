# Client ids and consent

## Client ids

Each client uses the first client id that is set, in this order:

1. `client_id=` on the client.
2. `client_id=` on the `AuthContext`.
3. The client's Microsoft default (user sign-ins only).

```python
auth = AuthContext("contoso.com", username="admin@contoso.com")
GraphClient(auth).client_id  # Microsoft Graph Command Line Tools

auth = AuthContext("contoso.com", username="admin@contoso.com", client_id=MY_APP_ID)
GraphClient(auth).client_id  # MY_APP_ID
GraphClient(auth, client_id=OTHER_APP_ID).client_id  # OTHER_APP_ID
```

App sign-ins never use a Microsoft default; without a client id they raise `ValueError`.

| Client | Default client id (user sign-ins) | Default scope (commercial cloud) |
|---|---|---|
| `GraphClient` | Microsoft Graph Command Line Tools | `scopes=` argument, else `https://graph.microsoft.com/.default` |
| `ArmClient`, `KeyVaultClient`, Azure SDK clients | Azure PowerShell | `https://management.azure.com/.default`, `https://vault.azure.net/.default` |
| `ExchangeClient` | Exchange Online PowerShell | `https://outlook.office365.com/.default` |
| `IppsClient` | Exchange Online PowerShell | `https://ps.compliance.protection.outlook.com/.default` |

In other clouds, the scopes use that cloud's URLs; each client's `resource` property shows its
own.

**Each client id needs its own sign-in.** So with the defaults, using Graph and Exchange means
two sign-ins; the second is quick because the browser is already signed in. To sign in once,
give the context one application of your own that has every permission you need.

## Scopes

**Pass `scopes=` to `GraphClient` in user sign-ins.** Without it, the client asks for
`.default`, which returns only the scopes the tenant has already consented to for Graph
Command Line Tools. In a new tenant, that is almost nothing. Short scope names get the Graph
URL added for you.

```python
graph = GraphClient(auth, scopes=["User.Read.All"])
graph.scopes  # ("https://graph.microsoft.com/User.Read.All",)
```

To ask for more scopes later, add them to `scopes=`. The cached token doesn't include them, so
the sign-in and the consent screen run again. App sign-ins always use `.default`, and passing
`scopes=` raises `ValueError`.

## Consent

Entra shows its consent screen the first time an application asks for delegated scopes it
hasn't been granted. What gets granted is decided on that screen, not by this package:

- A user who is allowed to consent grants the scopes for themselves only.
- An administrator also sees a **Consent on behalf of your organization** checkbox. A
  permission that requires admin consent can only be granted to the whole tenant, so every
  user in the tenant gets it through that client id.

To show the screen again, such as when an administrator consented for themselves only and now
needs to grant the scopes for the whole tenant:

```python
await graph.login(consent=True)
```

**This package never grants consent unless you ask it to.** Granting consent changes security
for the whole tenant, so it never happens as a side effect of a token request. The only way to
ask is `GraphClient(..., grant_when_possible=True)`, and only in
[GDAP](gdap.md#grant-a-missing-scope-yourself) customer tenants.

## When a sign-in ends without a token

```python
from azure_auth import AuthError, ConsentRequired

try:
    await graph.login()
except ConsentRequired as error:
    ...  # pressed Cancel on the consent screen
except AuthError as error:
    ...  # "Need admin approval", or nobody finished the sign-in
```

| What happened | Error |
|---|---|
| A user who isn't allowed to consent was shown **Need admin approval**, and left. | `AuthError` naming the scopes and tenant. Entra sends only `access_denied`, with no AADSTS code. |
| Someone pressed **Cancel** on the consent screen. | `ConsentRequired` (AADSTS65004), with the scopes and tenant. |
| The window was closed, or nobody finished the sign-in. | `AuthError`, after `browser_timeout` seconds (default 120). |

The context doesn't open the browser again after any of these: asking again can't fix the
first, the second is the user's choice, and the third means nobody is there.

## Check what a tenant has granted

In a user sign-in, a Graph client given `scopes=` first gets a `.default` token, without a
prompt. That token lists exactly the scopes the application has been granted in the tenant.
The client compares them with the scopes you asked for:

- **All granted:** it gets a token for your scopes, with no prompt.
- **Some missing, in a context that can prompt:** the sign-in and consent screen run, as usual.
- **Some missing, in a [GDAP](gdap.md) customer context:** it raises `ConsentRequired` right
  away, with `granted` and `missing` listing the short scope names.
- **Not signed in yet:** a context that can prompt signs in; a customer context raises
  `InteractionRequired`.

`granted_scopes()` asks Entra each time, with no caching, returns the short names, and never
prompts.

```python
async with GraphClient(auth) as graph:
    print(sorted(await graph.granted_scopes()))  # ["Group.Read.All", "User.Read", ...]
```

A token lists the scopes granted when it was issued, and doesn't change until it expires. So if
the cached `.default` token lacks a scope you asked for, the client gets a new token from Entra
before it raises, grants or prompts. Through the Windows broker, the broker's own cache answers
that request, so a scope granted in the last hour may still be missing.
