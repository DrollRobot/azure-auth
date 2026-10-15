# azure-auth

[![CI](https://github.com/DrollRobot/azure-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/DrollRobot/azure-auth/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Authentication library for Microsoft cloud services, with the goal of making common
workflows simple, so other packages don't have to deal with it.

## Project Goals

The high-level goals of this package.

- Support delegated user and application auth.
- For delegated user, support interactive browser auth.
- For applications, supports secret and certificate auth. (including TMP-bound certs)
- Provides clients for Graph, Exchange, IPPS, Azure (ARM) and Keyvault.
- Support for the Exchange REST endpoints.
- Azure auth object from this library can be passed to Azure SDKs.
- Defaults to first-party Microsoft client ids, but can connect to any client id.
- Supports saving the MSAL cache in memory, or on disk.
- Supports async operation wherever possible.
- Supports accessing multiple tenants through GDAP permissions.
- Platform support: Windows, Linux
- Supports all Microsoft clouds: Commercial, Gov, DoD, China.

### Non-goals

- Device code flow.

### Todo

- Platform support: Linux

## Documentation

See the [documentation](docs/index.md).

## License

MIT. See [LICENSE](LICENSE). The Windows certificate signer follows the design of
[microsoft/entrabot](https://github.com/microsoft/entrabot) (MIT).
