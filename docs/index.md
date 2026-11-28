# azure-auth

A Python library that signs in to Microsoft cloud services and makes requests to them, so your
code doesn't handle tokens. Create an `AuthContext`, pass it to the client for the service you
need, such as `GraphClient`, and make requests.

!!! warning "Beta"
    Until 1.0.0, a minor release (such as 0.14.0) may contain breaking changes. A patch
    release (such as 0.13.2) never does. Pin a release tag, and read the
    [changelog](https://github.com/DrollRobot/azure-auth/blob/main/CHANGELOG.md) before moving
    to a new minor version.

Start with [getting started](getting-started.md): the install and a first request.

## Use cases

- [Interactive sign-in](interactive-sign-in.md): browser and Windows broker sign-in, forcing a
  new sign-in, choosing the browser.
- [GDAP](gdap.md): a partner user signs in once and works in many customer tenants, with a
  fallback to signing in with a customer's own account.
- [Managed identity](managed-identity.md): code on an Azure host signs in with the host's
  identity, with no secret or certificate.
- [App sign-in](app-certificate.md): code signs in as an application, with a certificate or a
  client secret.

## Shared topics

- [Clouds and tenants](clouds.md): how a tenant's cloud is found, and looking tenants up.
- [Token cache](token-cache.md): memory or encrypted disk cache, writing and deleting it.
- [Client ids and consent](client-ids-and-consent.md): which application each client signs in
  to, scopes, and the consent screen.
- [Clients](clients.md): Graph, Resource Manager, Exchange, Security & Compliance, Key Vault,
  the Azure SDKs, and the blocking clients.
- [Errors and retries](errors.md): the exceptions, their fields, and what is retried.

## More

- [Reference](reference/auth.md): every class and function, from the docstrings.
- [Development](development.md): set up, run the tests, contribute.
