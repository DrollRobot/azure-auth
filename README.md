# azure-auth

[![CI](https://github.com/DrollRobot/azure-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/DrollRobot/azure-auth/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Authentication library for Microsoft cloud services, with the goal of making common
workflows simple, so other packages don't have to deal with it.

## Project Goals

The high-level goals of this package.

- Supports delegated user and application auth.
- For delegated user, supports interactive browser auth.
- For applications, supports secret and certificate auth. (including TMP-bound certs)
- Provides clients for Graph, Exchange, IPPS, Azure (ARM) and Keyvault.
- Azure auth object from this library can be passed to Azure SDKs.
- Defaults to first-party Microsoft client ids, but can connect to any client id.
- Supports saving the MSAL cache in memory, or on disk.
- Supports async operation wherever possible.
- Supports accessing multiple tenants through GDAP permissions.
- Platform support: Windows, Linux, MacOs
- Supports all Microsoft clouds: Commercial, Gov, DoD, China.

### Non-goals

- Device code flow.

### Todo

- Supports using WAM credentials on Windows systems.
  Sign-in through the broker is live-tested. Still unverified: whether a broker sign-in can
  reach a customer tenant silently through `for_tenant()`.
- Exchange(done) and IPPS clients.
  Delegated user access is live-tested end to end: the sign-in, cmdlets with every kind of
  parameter, paging, failures reported with the cmdlet's own reason, the Security & Compliance
  regional redirect, and the blocking mirrors. Still open: the `InvokeCommand` endpoint is
  undocumented, `ResultSize` is not a cmdlet parameter there so results cannot be capped, and
  the app-only and GDAP paths have not been run.
- Azure (ARM) and Keyvault clients.
  Key Vault is live-tested. ARM is built, but untested: it needs a user with a subscription.
- Supports accessing multiple tenants through GDAP permissions.
  Built, but untested: live testing is on hold until an account with sign-in rights to a
  GDAP partner tenant is available.
- Platform support: Linux, MacOs


## Documentation

See the [documentation](docs/index.md).

## License

MIT. See [LICENSE](LICENSE). The Windows certificate signer follows the design of
[microsoft/entrabot](https://github.com/microsoft/entrabot) (MIT).
