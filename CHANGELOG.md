# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The context keeps what the tenant lookup found: the tenant's ID, its cloud, and whether it
  is a GCC tenant. A tenant looked up first, with `discover_tenant()`, can be handed to the
  context in place of its name, so nothing is looked up twice.

### Changed

- A context names its tenant by ID, whether it was given the ID or a domain name; the name
  given is kept beside it for messages. Naming the cloud skips the lookup only with the ID.
- Another tenant can be named to `for_tenant()` by domain name, which is looked up once.

### Fixed

- A context given a domain name could not sign in for Key Vault, or any other Azure SDK
  client that names the tenant by ID; it reported that a sign-in was needed instead.
- The Key Vault client could not make a request: a package the Azure SDK needs for async
  HTTP was missing from the `keyvault` extra. The blocking client was unaffected.

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

[Unreleased]: https://github.com/DrollRobot/azure-auth/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/DrollRobot/azure-auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/DrollRobot/azure-auth/releases/tag/v0.1.0
