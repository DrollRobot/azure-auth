# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Validated with a delegated user sign-in: the Exchange Online and Security & Compliance
  clients, and their blocking versions.

### Changed

- A failed Exchange or Security & Compliance cmdlet now says which cmdlet failed and why,
  in the service's own words, and cmdlet warnings are collected from wherever the service
  puts them.

### Removed

- The API version option of the Exchange and Security & Compliance clients. Only one
  version answers cmdlets, so there was nothing to choose.

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

[Unreleased]: https://github.com/DrollRobot/azure-auth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DrollRobot/azure-auth/releases/tag/v0.1.0
