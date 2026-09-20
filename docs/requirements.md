# Requirements

The high-level goals of this package. A change that breaks one of these needs a decision, not
just a code review.

## Requirements

- Supports delegated user and application auth.
- For delegated user, supports interactive browser auth.
- For applications, supports secret and non-exportable certificate auth.
- Supports accessing multiple tenants through GDAP.
- Provides clients for Graph, Azure (ARM), Exchange, IPPS, Keyvault.
- Azure auth object from this library can be passed to Azure SDKs.
- Defaults to first-party Microsoft client ids, but can connect to any client id.
- Supports saving the MSAL cache in memory, or on disk. Refuses to save tokens/credentials
  unencrypted.
- Supports using WAM credentials on Windows systems.
- Supports async operation wherever possible.
- Platform support: Windows

## Non-goals

- Device code flow.
- Certificates held in Key Vault as the application credential.

## Todo

- Platform support: Linux, MacOs
- Supports all Microsoft clouds: Commercial, Gov, DoD, etc.
  Today `authority_host=` can point at another cloud's sign-in endpoint, but the resource
  URLs (Graph, ARM, Exchange, IPPS) are fixed to the commercial cloud. Needs urls for all
  clouds, function for OIDC lookup.
