# App sign-in

For code that runs with nobody there, such as a scheduled job, a service or a pipeline. The
code signs in as an application registration instead of a user, and has the application's
permissions.

Use, in order of preference:

1. [A certificate in the Windows certificate store](#windows-certificate-store), with its
   private key in the TPM. The key cannot be copied off the machine.
2. [A PEM or PFX certificate](#pem-or-pfx), on Linux and macOS.
3. [A client secret](#a-client-secret), only if you can't use a certificate.

On an Azure host, use a [managed identity](managed-identity.md) instead: there is no
credential to store.

## Entra setup

1. Register a single-tenant application.
2. Upload the public certificate (`.cer` or `.pem`) under Certificates & secrets.
3. Under API permissions, add the **application** permissions it needs, then grant admin
   consent.
4. Set up each resource it uses (see [below](#per-resource-setup)).

Steps 1 to 3 from the command line:

```bash
az ad app create --display-name my-app --sign-in-audience AzureADMyOrg
az ad sp create --id <application client id>
az ad app credential reset --id <application client id> --cert @my-app.cer --append
az ad app permission add --id <application client id> \
  --api 00000003-0000-0000-c000-000000000000 --api-permissions <app role id>=Role
az ad app permission admin-consent --id <application client id>
```

`00000003-0000-0000-c000-000000000000` is Microsoft Graph.

## Windows certificate store

[`New-TPMEntraCertificate.ps1`](https://github.com/DrollRobot/azure-auth/blob/main/scripts/New-TPMEntraCertificate.ps1)
creates a certificate whose private key is generated in the TPM and can't be exported. Run it
on the machine that will run your code: the script works on its own, without this package. It
saves only the public `.cer` file, which you upload in step 2 above.

```powershell
.\New-TPMEntraCertificate.ps1 -Subject my-app
```

Then sign in with the certificate's thumbprint:

```python
import asyncio

from azure_auth import AuthContext, GraphClient

TENANT = "contoso.com"
APP_CLIENT_ID = "<application client id>"
THUMBPRINT = "<certificate thumbprint>"


async def main() -> None:
    auth = AuthContext(TENANT, client_id=APP_CLIENT_ID, certificate_thumbprint=THUMBPRINT)
    async with GraphClient(auth) as graph:
        organization = await graph.get("/organization")
    print(organization["value"][0]["displayName"])


asyncio.run(main())
```

- Windows signs with the private key itself, so the key is never exported. That is why
  non-exportable and TPM keys work. Only CNG keys are supported, not older CryptoAPI keys.
- The thumbprint is not a secret; it can go in configuration files.
- The sign-in request is signed with PS256. If the key provider refuses PS256, or signs it
  incorrectly (a TPM 2.0 outside FIPS mode does), the context switches to RS256 and keeps using
  it.

For code that runs as a service account, put the certificate in the machine store, and give
that account read access to the private key (certlm.msc, the certificate, All Tasks, Manage
Private Keys).

```python
auth = AuthContext(
    TENANT,
    client_id=APP_CLIENT_ID,
    certificate_thumbprint=THUMBPRINT,
    certificate_store="LocalMachine",
)
```

## PEM or PFX

On Linux and macOS, pass the certificate and its private key. Keep the private key in the
system keyring (libsecret, Keychain), never in a plain-text file.

```python
from pathlib import Path

import keyring

auth = AuthContext(
    TENANT,
    client_id=APP_CLIENT_ID,
    certificate_pem=Path("my-app.pem").read_bytes(),  # the public certificate
    private_key_pem=keyring.get_password("my-app", "private-key"),
)
```

For an encrypted private key, also pass `certificate_password=`. For a PFX file, pass its bytes
or path, and its password from the keyring:

```python
auth = AuthContext(
    TENANT,
    client_id=APP_CLIENT_ID,
    certificate_pfx=Path("my-app.pfx"),
    certificate_password=keyring.get_password("my-app", "pfx-password"),
)
```

## A client secret

Anyone who has the secret can sign in as the application, from any machine, until it expires.
Use a certificate if you can. If you can't, keep the secret in the keyring:

```python
import keyring

auth = AuthContext(
    TENANT,
    client_id=APP_CLIENT_ID,
    client_secret=keyring.get_password("my-app", "client-secret"),
)
```

On Windows, this command stores the secret in Credential Manager, where `keyring` reads it.
`/pass` with no value prompts for the secret:

```powershell
cmdkey /generic:my-app /user:client-secret /pass
```

## Per-resource setup

Every client works with an app sign-in. An app sign-in always asks for `<resource>/.default`,
so passing `scopes=` raises `ValueError`. The application's permissions in Entra decide what the
token allows.

```python
async with GraphClient(auth) as graph:
    users = await graph.get_all("/users")

async with ExchangeClient(auth) as exchange:
    mailboxes = await exchange.mailboxes(select=["UserPrincipalName"])
```

| Resource | Needs |
|---|---|
| Microsoft Graph | Graph application permissions, admin consent. |
| Exchange Online, Security & Compliance | The `Exchange.ManageAsApp` application permission (Office 365 Exchange Online), and an Exchange administrator role for the application's service principal. |
| Resource Manager, Key Vault | An Azure role for the application's service principal, on the subscription, resource group or vault. |

Security & Compliance needs the tenant's domain name. If the context was given a GUID, the
client asks Exchange for the domain once, so the application also needs an Exchange role that
can read the organization's settings.

A multi-tenant application can reach several tenants from one context: see
[GDAP](gdap.md#an-application-across-tenants).

## Errors

| Error | Cause |
|---|---|
| `ValueError` | No `client_id`, or `scopes=` given to a client. |
| `CertificateUnavailable` | The certificate or its private key cannot be used: wrong thumbprint, no read access to the key, an unreadable PFX. |
| `AuthError`, AADSTS700016 | No such application in the tenant: wrong client id, or wrong tenant. |
| `AuthError`, AADSTS700027 | Entra cannot verify the signed request: the certificate is not uploaded to this application. |
| `AuthError`, AADSTS7000215 | Wrong client secret. |
| `AuthError`, AADSTS7000222 | The client secret has expired. |
| `ResourceError` 403 (`GraphError`, ...) | Signed in, but the application lacks the permission or role. |

If Entra refuses the sign-in, the context does not retry with RS256. See [errors](errors.md).
