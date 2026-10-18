# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-10-18 - Graph consent check, choice of browser

### Added

- Browser sign-ins can use a browser other than the system default, such as a particular
  Edge profile.
- Before asking for Graph scopes, a client checks what the tenant has already granted. In a
  GDAP customer tenant a missing scope now fails at once, naming what is granted and what is
  missing.
- An opt-in setting lets the application grant itself a missing Graph scope in a GDAP customer
  tenant, where that tenant already allows it to manage its own grants.

### Changed

- **Breaking:** several classes, methods and arguments are renamed, so that each thing has one
  name.

## [0.4.1] - 2026-10-16 - Broker fix for GDAP customers

### Fixed

- Through the Windows broker, an Exchange token from a GDAP customer tenant made every later
  silent token request fail with "No cached token", in every tenant.

## [0.4.0] - 2026-10-15 - Exchange REST reads, tenant object

### Added

- Support for the Exchange Online REST endpoints behind the `Get-EXO*` cmdlets.

### Changed

- **Breaking:** the tenant's ID, cloud and domain name are kept together in one tenant
  object. To choose a cloud, pass a tenant built for that cloud instead of a separate cloud
  setting.
- **Breaking:** GDAP customers are listed with their display names, and everything else Graph
  says about them, in place of their tenant IDs alone.
- Continuous access evaluation is on. Graph and Exchange can now cut off a user within
  minutes of the account being disabled, the password changed or a sign-out forced, instead
  of when the token expires; the clients recover on their own when the user is still allowed.
  Their tokens live longer between renewals.

### Fixed

- When Exchange refuses a cmdlet, the error now says the account may lack the role for it,
  not only that the name may be wrong.

## [0.3.0] - 2026-10-08 - Key Vault client, tenant held by ID

### Added

- Key Vault client, for reading secrets.

### Changed

- AuthContext's tenant ID is always the tenant's GUID, even when it was initialized with a
  domain name.
- Switching to another tenant accepts a domain name as well as a GUID.

### Fixed

- Azure SDK clients failed with a sign-in error when the context was created with a domain
  name.
- Closing the Windows broker's sign-in window opened a browser instead of cancelling.
- A forced sign-in could finish without showing the account picker.

## [0.2.0] - 2026-09-29 - every Microsoft cloud, Exchange validated

### Added

- Validated with a delegated user sign-in: the Exchange Online and Security & Compliance
  clients, and their blocking versions.
- Every Microsoft cloud: Commercial (with GCC), US Government GCC High and DoD, and China.
  The tenant's cloud is found automatically, and every client uses that cloud's services;
  naming the cloud skips the lookup. Signing in has only been tried in the commercial cloud.
- Look up any tenant by domain name or ID, without signing in: its ID, its cloud, and
  whether it is a GCC tenant.

### Changed

- Runs on Python 3.11 and newer, not only 3.14.
- A failed Exchange or Security & Compliance cmdlet now says which cmdlet failed and why,
  in the service's own words, and cmdlet warnings are collected from wherever the service
  puts them.

### Removed

- The API version option of the Exchange and Security & Compliance clients. Only one
  version answers cmdlets, so there was nothing to choose.
- The option to point sign-in at another host, and the commercial resource URL constants.
  Choosing the cloud replaces both.

### Fixed

- An unknown Exchange cmdlet surfaced as a transport error instead of a failed request.
  Every failed request now reports its status, even when its body cannot be read.

## [0.1.0] - 2026-09-25 - initial release

### Added

- Interactive delegated user browser sign-in to Microsoft Graph on Windows. Validated
  features: asynchronous clients, memory and disk cache.

Also included, but not yet verified: application sign-in with a secret or certificate, the
Windows broker, clients for Azure Resource Manager, Exchange Online, Security & Compliance
and Key Vault, blocking versions of every client, and GDAP access to managed tenants.

[Unreleased]: https://github.com/DrollRobot/azure-auth/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/DrollRobot/azure-auth/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/DrollRobot/azure-auth/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/DrollRobot/azure-auth/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/DrollRobot/azure-auth/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/DrollRobot/azure-auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/DrollRobot/azure-auth/releases/tag/v0.1.0
