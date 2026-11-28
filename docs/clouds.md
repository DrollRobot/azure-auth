# Clouds and tenants

You don't need to say which Microsoft cloud a tenant is in. When you create a context with a
tenant GUID or domain name, it looks up the tenant's cloud, and every client using the context
calls that cloud's service URLs. The lookup sends one request to each of the three sign-in
hosts, in parallel, and needs no sign-in.

The result is in `auth.tenant`:

```python
auth = AuthContext("contoso.us", username="admin@contoso.us")  # the lookup finds GCC High

auth.tenant.id  # the tenant GUID
auth.tenant.cloud  # the cloud: US_GOV here
auth.tenant.domain  # "contoso.us"; None when the context was given a GUID
auth.tenant.oidc  # the tenant's OpenID Connect configuration, from the lookup
auth.tenant.region_sub_scope  # "GCC", "DODCON" (GCC High), "DOD", or None
```

Error messages name the tenant by its domain when it is known, otherwise by its GUID.

## The clouds

| Cloud | Constant | Name | Sign-in | Graph |
|---|---|---|---|---|
| Commercial, including GCC | `COMMERCIAL` | `Commercial` | `login.microsoftonline.com` | `graph.microsoft.com` |
| US Government GCC High | `US_GOV` | `USGov` | `login.microsoftonline.us` | `graph.microsoft.us` |
| US Government DoD | `US_GOV_DOD` | `USGovDoD` | `login.microsoftonline.us` | `dod-graph.microsoft.us` |
| China (21Vianet) | `CHINA` | `China` | `login.chinacloudapi.cn` | `microsoftgraph.chinacloudapi.cn` |

Each constant has every service URL for its cloud, including Resource Manager, Exchange and
Security & Compliance:

```python
from azure_auth.clouds import COMMERCIAL, US_GOV

US_GOV.graph  # "https://graph.microsoft.us"
COMMERCIAL.arm  # "https://management.azure.com"
```

## Look a tenant up without signing in

`Tenant.lookup()` runs the same lookup without creating a context. It works for any tenant's
domain name or GUID, not only yours, and uses only public endpoints.

```python
from azure_auth import Tenant

tenant = Tenant.lookup("contoso.com")
tenant.id  # the GUID, also when looked up by domain
tenant.cloud.name  # "Commercial", "USGov", "USGovDoD" or "China"
tenant.cloud.graph  # that cloud's Graph
```

## Give a context a `Tenant`

A context also accepts a `Tenant` instead of a string, and then does no lookup. Use this to
check the tenant before signing in, to pick the right tenant when a name exists in two clouds,
or to skip the lookup:

```python
from azure_auth import AuthContext, Tenant
from azure_auth.clouds import CHINA, COMMERCIAL, US_GOV

# Check the tenant before signing in.
tenant = Tenant.lookup("contoso.com")
if tenant.cloud is CHINA:
    raise SystemExit("no service in this cloud")
auth = AuthContext(tenant, username="admin@contoso.com")

# A name used by different tenants in two clouds: look it up in the cloud you mean.
auth = AuthContext(Tenant.lookup("21vianet.com", CHINA), username="admin@21vianet.com")

# GUID and cloud already known: no lookup request.
auth = AuthContext(Tenant("<tenant GUID>", US_GOV), username="admin@contoso.us")

# A multi-tenant authority, which has no single tenant to look up.
auth = AuthContext(Tenant("organizations", COMMERCIAL), username="someone@contoso.com")
```

A `Tenant` you build yourself is not checked. If its cloud is wrong, an app sign-in fails right
away (AADSTS700023). A user sign-in succeeds, but the first request fails: the wrong cloud's
Graph answers `401 InvalidAuthenticationToken: InvalidCloudInstance`.

## Leave a cloud out

Each sign-in host only knows its own cloud's tenants, so the lookup asks all three and waits
for the slowest answer. If none of your tenants are in a cloud, leave it out, by constant or by
name. Then a network that blocks the China host doesn't slow the lookup down with a timeout:

```python
tenant = Tenant.lookup("contoso.com", clouds=[COMMERCIAL, US_GOV])
auth = AuthContext("contoso.com", username="admin@contoso.com", lookup_clouds=["Commercial"])
```

A context's `lookup_clouds` also applies to its `get_tenant_context()` lookups.

## When the lookup fails

If the lookup can't find the tenant's cloud, creating the context raises one of these:

```python
from azure_auth import AmbiguousTenant, AuthContext, NetworkError, TenantNotFound

try:
    auth = AuthContext(name, username=username)
except TenantNotFound:
    print(f"No tenant is called {name} in any cloud")
except AmbiguousTenant as error:
    print(f"{name} is a different tenant in each of: {error.candidates}")
except NetworkError:
    print("A sign-in host did not answer; the tenant may be behind it")
```

| Error | Cause |
|---|---|
| `TenantNotFound` | No tenant has that id or domain name in any cloud. |
| `AmbiguousTenant` | Each cloud has its own tenants, so one name can belong to different tenants in two clouds. Look it up in the cloud you mean (above). |
| `NetworkError` | A host couldn't be reached, and the others didn't find the tenant. An unreachable host is skipped with a warning (logger `azure_auth.auth.tenant`), and the hosts that answered decide the result. |
| `ValueError` | `common`, `organizations` and `consumers` name no single tenant. Build the `Tenant` yourself (above). |

## Graph in China

Microsoft Graph Command Line Tools, the default Graph client id, does not exist in the China
cloud. There, `GraphClient` needs an application of your own:

```python
graph = GraphClient(auth, client_id=MY_APP_ID, scopes=["User.Read.All"])
```

The Azure PowerShell and Exchange Online PowerShell client ids exist in every cloud.
