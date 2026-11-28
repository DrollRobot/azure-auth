# GDAP: many customer tenants

A user of the partner's tenant (the home tenant) signs in once. The code can then make requests
in every customer tenant that the partner's GDAP relationships cover, without signing in to
each one. For a customer that GDAP can't reach, the code can sign in through the browser with
an account that belongs to that customer.

## Entra setup

- **Relationships:** a GDAP relationship with each customer, with the Entra roles the work
  needs, assigned to a security group the partner user is in. This package does not create or
  manage relationships.
- **Home tenant:** `DelegatedAdminRelationship.Read.All` for `list_customers()`. The first
  sign-in asks for it.
- **Each customer tenant:** consent for the application and the scopes you use. For Graph with
  the default client id, the application is Microsoft Graph Command Line Tools. Only an
  account in the customer tenant can consent; Entra refuses a partner user (AADSTS90099). So
  each customer may have granted different scopes, or none.

```python
async with GraphClient(partner, scopes=["DelegatedAdminRelationship.Read.All"]) as home:
    await home.login()  # the home sign-in; asks for consent the first time
```

## Example

```python
import asyncio

from azure_auth import AuthContext, ConsentRequired, GraphClient, InteractionRequired


async def main() -> None:
    partner = AuthContext("partner.com", username="admin@partner.com", cache="disk")

    async with GraphClient(partner, scopes=["DelegatedAdminRelationship.Read.All"]) as home:
        customers = await home.list_customers()

    for customer in customers:
        customer_auth = partner.get_tenant_context(customer["tenantId"])
        async with GraphClient(customer_auth, scopes=["User.Read.All"]) as graph:
            try:
                users = await graph.get_all("/users", params={"$select": "id"})
            except (ConsentRequired, InteractionRequired) as error:
                print(f"skipped {customer['displayName']}: {error}")
                continue
        print(customer["displayName"], len(users))


asyncio.run(main())
```

- `get_tenant_context()` returns a context for the customer tenant that uses the home sign-in:
  the same credentials, cache, username and cloud. A tenant GUID needs no network request; a
  domain name is looked up once, then remembered. Calling it again for the same tenant returns
  the same context object.
- **A customer context never opens a sign-in window**, so a loop over fifty customers can't
  open fifty windows. If it can't get a token without one, it raises `InteractionRequired` or
  `ConsentRequired`, with the customer's `tenant_id`.
- `list_customers()` returns each customer once, even when several relationships cover it, as
  the object Graph returns (`tenantId`, `displayName`, and the rest).
- `customer_auth.home` is the context you created (`partner`). To check whether a context came
  from `get_tenant_context()`, test `auth.home is not auth`.

## Other clients in customer tenants

Every client works with a customer context. Each client id needs one sign-in, in the home
tenant.

```python
async with ExchangeClient(customer_auth) as exchange:
    config = await exchange.run("Get-OrganizationConfig")

async with ArmClient(customer_auth) as arm:
    subscriptions = await arm.get_all("/subscriptions", api_version="2022-12-01")
```

The Exchange client sends a customer's requests through that tenant's system mailbox, with no
setup.

## Check what each customer allows

A Graph client given `scopes=` first checks which scopes the customer has granted. If any are
missing, it raises `ConsentRequired` right away, listing the granted and missing scopes:

```python
try:
    users = await graph.get_all("/users")
except ConsentRequired as error:
    print("granted:", error.granted, "missing:", error.missing)
```

`granted_scopes()` asks Entra each time, with no caching, and never opens a sign-in window. Use
it to list what each customer allows before starting work:

```python
for customer in customers:
    async with GraphClient(partner.get_tenant_context(customer["tenantId"])) as graph:
        print(customer["displayName"], sorted(await graph.granted_scopes()))
```

## A customer wants a newer sign-in

`InteractionRequired` with AADSTS code 50078 or 70043 means the customer's Conditional Access
policy rejects the home sign-in as too old. Sign in again in the home tenant with
`login(reauthenticate=True)`, through a client with the same client id, then retry. New
customer tokens then use the new sign-in.

```python
STALE_SIGN_IN = {50078, 70043}

try:
    users = await graph.get_all("/users")
except InteractionRequired as error:
    if not error.error_codes & STALE_SIGN_IN:
        raise
    async with GraphClient(partner, scopes=["DelegatedAdminRelationship.Read.All"]) as home:
        await home.login(reauthenticate=True)
    users = await graph.get_all("/users")
```

## Fall back to an interactive sign-in

GDAP can't reach a customer that hasn't consented to the application. For those customers,
sign in through the browser with an account in that customer's tenant. The package never does
this by itself; your code decides when sign-in windows may open.

The example below first tries every customer through GDAP, which opens no windows. It then
signs in through the browser once for each customer that GDAP couldn't reach:

```python
import asyncio
from typing import Any

from azure_auth import AuthContext, AuthError, ConsentRequired, GraphClient, InteractionRequired

HOME_SCOPES = ["DelegatedAdminRelationship.Read.All"]
SCOPES = ["User.Read.All"]
STALE_SIGN_IN = {50078, 70043}

# For each customer GDAP may not reach: an account in that customer's tenant.
CUSTOMER_ACCOUNTS = {"<customer tenant id>": "admin@fabrikam.com"}

Customer = dict[str, Any]


async def list_users(auth: AuthContext) -> list[dict[str, Any]]:
    async with GraphClient(auth, scopes=SCOPES) as graph:
        return await graph.get_all("/users", params={"$select": "id"})


async def gdap_pass(
    partner: AuthContext, customers: list[Customer]
) -> list[tuple[Customer, AuthError]]:
    """Try each customer through GDAP; return the ones it could not reach."""
    unreached: list[tuple[Customer, AuthError]] = []
    for customer in customers:
        try:
            users = await list_users(partner.get_tenant_context(customer["tenantId"]))
        except (ConsentRequired, InteractionRequired) as error:
            unreached.append((customer, error))
            continue
        print(customer["displayName"], len(users))
    return unreached


async def main() -> None:
    partner = AuthContext("partner.com", username="admin@partner.com", cache="disk")
    async with GraphClient(partner, scopes=HOME_SCOPES) as home:
        customers = await home.list_customers()

        unreached = await gdap_pass(partner, customers)

        # A customer rejected the home sign-in as too old: sign in again at home, once.
        if any(error.error_codes & STALE_SIGN_IN for _, error in unreached):
            await home.login(reauthenticate=True)
            unreached = await gdap_pass(partner, [customer for customer, _ in unreached])

    # Sign in through the browser to each customer GDAP could not reach.
    for customer, error in unreached:
        username = CUSTOMER_ACCOUNTS.get(customer["tenantId"])
        if username is None:
            print(f"skipped {customer['displayName']}: {error}")
            continue
        auth = AuthContext(customer["tenantId"], username=username, cache="disk")
        users = await list_users(auth)
        print(customer["displayName"], len(users))


asyncio.run(main())
```

- The fallback needs an account in the customer tenant. A partner user can't sign in there
  through the browser: they have no user object in the customer tenant, and Entra refuses them
  (AADSTS90099).
- If that account is an administrator of the customer, they can tick **Consent on behalf of
  your organization** on the consent screen. GDAP then reaches that customer on later runs,
  without the fallback. `login(consent=True)` shows the consent screen even if the
  administrator already consented for themselves only:

```python
async with GraphClient(auth, scopes=SCOPES) as graph:
    await graph.login(consent=True)
```

## Grant a missing scope yourself

If a customer has granted the application `DelegatedPermissionGrant.ReadWrite.All`, the
application can grant itself more scopes in that tenant. With `grant_when_possible=True`, the
client does that when the check above finds a missing scope:

```python
graph = GraphClient(
    partner.get_tenant_context(customer["tenantId"]),
    scopes=["Sites.Read.All"],
    grant_when_possible=True,
)
sites = await graph.get_all("/sites")
```

- The client adds the missing scopes, then asks for a new token every ten seconds until one
  includes them. This usually takes about a minute, and at most three, because Entra only adds
  a new grant to tokens it issues afterwards. `wait_for_grant=False` skips the wait: the first
  request fails with `ConsentRequired`, and a request about a minute later succeeds.
- Without `DelegatedPermissionGrant.ReadWrite.All`, or if the grant can't be read or changed,
  the client raises `ConsentRequired`, the same as without the flag.
- **The grant applies to the whole tenant.** Every user of that application in the customer
  tenant gets the scopes, still limited by their own roles. For a shared Microsoft application
  such as Graph Command Line Tools, that means everyone in that tenant who uses Graph
  PowerShell.
- Off by default. It only works in customer contexts, which can't show a consent screen.

## An application across tenants

A multi-tenant application that each tenant has consented to can loop over tenants the same
way. Each tenant's context signs in separately, with the same credential.

```python
partner = AuthContext("partner.com", client_id=APP_ID, certificate_thumbprint=THUMBPRINT)

for tenant_id in tenant_ids:
    async with GraphClient(partner.get_tenant_context(tenant_id)) as graph:
        organization = await graph.get("/organization")
```

This is not GDAP: GDAP roles don't apply to application tokens. An application that uses a
managed identity as its credential can only reach its own tenant.

## Errors

| Error | Cause | What to do |
|---|---|---|
| `ConsentRequired` | The customer has not granted the application some of the scopes. `granted` and `missing` list them. | Ask the customer to consent, use `grant_when_possible`, or fall back to a customer account. |
| `InteractionRequired`, AADSTS 50078 or 70043 | The customer's policy rejects the home sign-in as too old. | `login(reauthenticate=True)` at home, then retry. |
| `InteractionRequired`, other | Nobody has signed in at home yet, or the home sign-in expired. | Sign in at home first. |
| `ResourceError` 403 (`GraphError`, ...) | The token is fine, but the GDAP roles do not allow the call. | Add the role to the relationship. |

`error_codes` holds Entra's AADSTS codes, so code can check the reason without parsing the
message. See [errors](errors.md).
