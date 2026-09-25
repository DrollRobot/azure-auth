# azure-auth

[![CI](https://github.com/DrollRobot/azure-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/DrollRobot/azure-auth/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.14%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Authentication library for Microsoft cloud services, with the goal of making common
workflows simple, so other packages don't have to deal with it.

## Project Goals

The high-level goals of this package.

- Supports delegated user and application auth.
- For delegated user, supports interactive browser auth.
- For applications, supports secret and non-exportable certificate auth.
- Provides clients for Graph, Exchange, IPPS, Azure (ARM) and Keyvault.
- Azure auth object from this library can be passed to Azure SDKs.
- Defaults to first-party Microsoft client ids, but can connect to any client id.
- Supports saving the MSAL cache in memory, or on disk. Refuses to save tokens/credentials
  unencrypted.
- Supports async operation wherever possible.
- Platform support: Windows, Linux, MacOs

### Non-goals

- Device code flow.

### Todo

- Supports using WAM credentials on Windows systems.
  Built, but untested: `broker=True` has never been run against a live tenant, and whether a
  broker sign-in can reach a managed tenant silently through `for_tenant()` is unverified.
- Exchange and IPPS clients.
  Delegated user access is live-tested end to end: the sign-in, cmdlets with every kind of
  parameter, paging, failures reported with the cmdlet's own reason, the Security & Compliance
  regional redirect, and the blocking mirrors. Still open: the `InvokeCommand` endpoint is
  undocumented, `ResultSize` is not a cmdlet parameter there so results cannot be capped, and
  the app-only and GDAP paths have not been run.
- Azure (ARM) and Keyvault clients.
  Built, but untested: ARM needs a user with a subscription, Key Vault needs a vault.
- Supports accessing multiple tenants through GDAP.
  Built, but untested: live testing is on hold until an account with sign-in rights to a
  GDAP partner tenant is available.
- Platform support: Linux, MacOs
- Supports all Microsoft clouds: Commercial, Gov, DoD, etc.
  Today `authority_host=` can point at another cloud's sign-in endpoint, but the resource
  URLs (Graph, ARM, Exchange, IPPS) are fixed to the commercial cloud. Needs urls for all
  clouds, function for OIDC lookup.

## Documentation

See the [documentation](docs/index.md).

## License

MIT. See [LICENSE](LICENSE). The Windows certificate signer follows the design of
[microsoft/entrabot](https://github.com/microsoft/entrabot) (MIT).
