# Errors and retries

## The errors

The package raises its own exceptions, never those of `httpx2`, `requests` (used by MSAL) or
the Azure SDK. The original exception is kept as `__cause__`, so tracebacks still show it.

```
AuthError(error, error_codes, suberror, correlation_id, trace_id, claims)
|-- InteractionRequired(tenant_id, scopes)
|-- ConsentRequired(tenant_id, scopes, granted, missing)
|-- AccountSelectionRequired
|-- CertificateUnavailable
|-- CacheEncryptionUnavailable
|-- CacheFileEmpty(path)
|-- BrokerUnavailable
|-- ManagedIdentityUnavailable
|-- TenantNotFound(name)
`-- AmbiguousTenant(name, candidates)
ResourceError(status, code, request_id, body)
|-- GraphError
|-- ArmError
|-- InvokeCommandError
`-- KeyVaultError
NetworkError
```

| Raised | When |
|---|---|
| `AuthError` | Entra ID, or a managed identity endpoint, refused a token. |
| `ResourceError` | The service answered with an error status. Each client raises its own subclass. |
| `NetworkError` | A host could not be reached, the TLS handshake failed, or the request timed out, for token requests and service calls alike. |

```python
from azure_auth import AuthError, GraphError, NetworkError

try:
    users = await graph.get_all("/users")
except GraphError as error:
    print(f"Graph answered {error.status} {error.code} (request id {error.request_id})")
except AuthError as error:
    print(f"No token: {error}")
except NetworkError as error:
    print(f"Unreachable: {error}")
```

Each use-case page lists its errors:
[interactive sign-in](interactive-sign-in.md#errors), [GDAP](gdap.md#errors),
[managed identity](managed-identity.md#errors), [app sign-in](app-certificate.md#errors).

## Error details from Entra

When Entra refuses a token, the `AuthError` keeps Entra's full message and puts the details in
fields, so code can check the reason without parsing the message. You never get MSAL's raw
result dictionaries.

```python
try:
    await graph.login()
except AuthError as error:
    if 50078 in error.error_codes:
        ...  # the multi-factor sign-in is too old
    print(error.correlation_id, error.trace_id)  # what Microsoft support asks for
```

| Field | Holds |
|---|---|
| `error` | The OAuth error, such as `invalid_grant`. |
| `error_codes` | The AADSTS codes, as integers. |
| `suberror` | Entra's sub-error, such as `consent_required`. |
| `correlation_id`, `trace_id` | The ids Microsoft support asks for. The sign-in logs call the trace id the request id. |
| `claims` | A claims challenge that a new sign-in has to meet. |

A field is empty when Entra didn't send it. The Windows broker returns only `error`, plus
`error_codes` and `suberror` when its PII logging is on (the default).

## Retries

Every client retries `429` and `503` responses. When the service sends a `Retry-After` header,
the client waits that long first:

```python
graph = GraphClient(auth, max_retries=5, max_retry_wait=60)
```

On a `401` with a claims challenge (from continuous access evaluation), the client gets a new
token that meets the challenge. On any other `401`, it gets a new token once. Every sign-in
tells Entra it can handle these challenges. In return, Graph and Exchange can cut off a
disabled or signed-out user within minutes instead of when the token expires, and issue tokens
that last longer.

## Tokens stay on their host

A client only sends its token to its own service's host. A URL for any other host, including a
next-page link or an operation URL, raises `ValueError`:

```python
await graph.get("https://example.com/steal")  # ValueError, no request is sent
```
