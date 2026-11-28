# Interactive sign-in

A user signs in through the browser or the Windows sign-in broker. The code then makes requests
as that user, with that user's permissions.

If nobody is there to sign in, use a [managed identity](managed-identity.md) on an Azure host,
or an [app sign-in](app-certificate.md) elsewhere. To sign in once and work in many customer
tenants, see [GDAP](gdap.md).

## Entra setup

None. By default, each client uses a Microsoft application that exists in every tenant (see
[client ids](client-ids-and-consent.md#client-ids)). The first time the code asks for a scope,
Entra shows its consent screen, where an administrator can grant the scope for the whole
tenant.

Pass the Graph scopes you need to `GraphClient`, so the consent screen asks for them:

```python
graph = GraphClient(auth, scopes=["User.Read.All", "Group.Read.All"])
```

To use your own application registration instead, see [below](#your-own-application).

## Example

```python
import asyncio

from azure_auth import AuthContext, ExchangeClient, GraphClient


async def main() -> None:
    auth = AuthContext("contoso.com", username="admin@contoso.com", cache="disk")

    async with GraphClient(auth, scopes=["User.Read.All"]) as graph:
        users = await graph.get_all("/users", params={"$select": "userPrincipalName"})

    async with ExchangeClient(auth) as exchange:
        mailboxes = await exchange.mailboxes(select=["UserPrincipalName"])

    print(len(users), len(mailboxes))


asyncio.run(main())
```

- `username` picks the account's tokens from the cache, and is filled in on the sign-in page.
  If a different account signs in, the context raises `AuthError`: it finds cached tokens by
  `username`, so it could never use that account's tokens.
- The tenant can be a domain name or a GUID, in any Microsoft cloud. See
  [clouds](clouds.md).

## Choose when to sign in

The context signs in at the first request, and opens the browser only if the cache has no
usable token. To sign in earlier, such as before a long run starts, call `login()`:

```python
graph = GraphClient(auth, scopes=["User.Read.All"])
await graph.login()  # opens the browser now, unless the cache has a usable token
```

## Keep the sign-in between runs

`cache="disk"` saves tokens to an encrypted file, so the next run signs in without a prompt.
The file is written when the process exits. To write it sooner, so that a killed process
doesn't lose the sign-in, call `flush_cache()`:

```python
auth = AuthContext("contoso.com", username="admin@contoso.com", cache="disk")
async with GraphClient(auth, scopes=["User.Read.All"]) as graph:
    await graph.login()
auth.flush_cache()  # otherwise written at exit
```

The file holds a refresh token, which can get new tokens for the user. See
[token cache](token-cache.md) for where the file is, a reminder shortcut, and deleting it.

## Force a new sign-in

These `login()` arguments sign in again even when the cache has a usable token:

```python
await graph.login(pick_account=True)  # show the account picker
await graph.login(reauthenticate=True)  # ask for the password, and MFA, again
await graph.login(consent=True)  # show the consent screen again
await graph.login(fresh=True)  # get a new token from Entra, not the cached one
```

| Argument | Use it when |
|---|---|
| `pick_account` | The broker or a signed-in browser would otherwise pick an account without asking. |
| `reauthenticate` | A Conditional Access policy rejects the last sign-in as too old (AADSTS50078, AADSTS70043). Uses the browser even with `broker=True`. |
| `consent` | An administrator consented for themselves only, and now needs to grant the scopes for the whole tenant ("Consent on behalf of your organization"). Uses the browser even with `broker=True`. |
| `fresh` | You want to confirm the sign-in still works before starting work. A cached token doesn't show that: a Conditional Access policy may have started refusing the refresh token after it was cached. |

Only one of `pick_account`, `reauthenticate` and `consent` can be set at a time.

## Choose the browser

Browser sign-ins use the system default browser. To use another, pass `browser=`: the
program's absolute path, or a list of the path and its arguments. The sign-in URL is added as
the last argument.

```python
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

auth = AuthContext("contoso.com", username="admin@contoso.com", browser=EDGE)
auth = AuthContext(
    "contoso.com",
    username="admin@contoso.com",
    browser=[EDGE, "--profile-directory=Profile 2"],
)
```

This applies to this context only.

## Run code before the window opens

`before_browser_opens=` takes a function that runs right before each browser sign-in window
opens. For example, it can open the page where the account's password is stored. It doesn't
run when the token comes from the cache or the broker. If it raises an exception, the sign-in
fails and no window opens.

```python
import webbrowser

auth = AuthContext(
    "contoso.com",
    username="admin@contoso.com",
    before_browser_opens=lambda: webbrowser.open(PASSWORD_PAGE),
)
```

## Browser timeout

If a browser sign-in doesn't finish within `browser_timeout` seconds (default 120), it fails
with `AuthError`. This happens when the window is closed, left open, or stopped at an error
page such as a Conditional Access block.

```python
auth = AuthContext("contoso.com", username="admin@contoso.com", browser_timeout=300)
```

## The Windows broker

`broker=True` signs in through the Windows Web Account Manager, which can use the account
already signed in to Windows. It needs the `broker` extra, which doesn't support Python 3.15
yet.

```python
auth = AuthContext("contoso.com", username="admin@contoso.com", broker=True)

# Fail instead of falling back to the browser:
auth = AuthContext("contoso.com", username="admin@contoso.com", broker=True, broker_fallback=False)
```

- If the broker is missing or fails, the context uses the browser instead. With
  `broker_fallback=False`, it raises `BrokerUnavailable`. If the user cancels the broker's
  prompt, the browser does not open.
- The context turns on the broker's PII logging, so broker errors include Entra's reason (such
  as `AADSTS65001` for missing consent). This setting applies to the whole process, so the
  broker's DEBUG log records (logger `msal.broker`) include the user's name. Tokens are still
  masked.

## Several resources, several sign-ins

By default, each client uses a different Microsoft application, and each application needs its
own sign-in. So using Graph and Exchange means two sign-ins; the second is quick because the
browser is already signed in. To sign in once, use one application of your own that has every
permission you need:

```python
auth = AuthContext("contoso.com", username="admin@contoso.com", client_id=MY_APP_ID)
graph = GraphClient(auth, scopes=["User.Read.All"])  # signs in to MY_APP_ID
exchange = ExchangeClient(auth)  # reuses that sign-in
```

## Your own application

1. In Entra, App registrations, register a single-tenant application.
2. Under Authentication, add the platform **Mobile and desktop applications** with the redirect
   URI `http://localhost`. For the broker, also add
   `ms-appx-web://microsoft.aad.brokerplugin/<client id>`.
3. Under API permissions, add the delegated permissions the code uses.

```python
auth = AuthContext("contoso.com", username="admin@contoso.com", client_id=MY_APP_ID)
```

A client can also set its own: `GraphClient(auth, client_id=OTHER_APP_ID)`. See
[client ids](client-ids-and-consent.md#client-ids) for which one is used when both are set.

## Errors

```python
from azure_auth import AuthError, ConsentRequired

try:
    await graph.login()
except ConsentRequired as error:
    print(f"Consent declined for {error.scopes} in {error.tenant_id}")
except AuthError as error:
    print(f"Sign-in failed: {error} (trace id {error.trace_id})")
```

| Error | Cause |
|---|---|
| `AuthError`, `access_denied` | The user isn't allowed to consent and left the "Need admin approval" page, or cancelled the sign-in. In the first case, an administrator has to grant the scopes. |
| `ConsentRequired` | The user pressed Cancel on the consent screen (AADSTS65004). |
| `AuthError`, after `browser_timeout` | Nobody finished the sign-in in the browser. |
| `AuthError`, another account | Someone other than `username` signed in. |
| `AccountSelectionRequired` | Two cached accounts match `username`. |
| `BrokerUnavailable` | The broker failed, with `broker_fallback=False`. |
| `CacheEncryptionUnavailable` | `cache="disk"` cannot be encrypted on this platform. |

After any of these, the context doesn't open the browser again by itself. See
[errors](errors.md) for the fields every error carries.
