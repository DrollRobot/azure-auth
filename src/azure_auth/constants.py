"""Well-known identifiers for Microsoft cloud resources.

The client ids are Microsoft first-party public client applications. They are used by
default for user flows so that callers do not have to register an application. App flows
(secret or certificate) always need the caller's own application id.
"""

from __future__ import annotations

DEFAULT_AUTHORITY_HOST = "https://login.microsoftonline.com"

# Microsoft Graph Command Line Tools, which the portal and the directory both call it. It was
# named "Microsoft Graph PowerShell" when Microsoft first published it and much of the
# documentation still says so; the application is the same one. Works by dynamic consent: the
# scopes a token carries are the ones already consented to in the tenant.
GRAPH_CLI_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

# Azure PowerShell. Pre-authorised for Azure Resource Manager and Key Vault.
AZURE_POWERSHELL_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2"

# Exchange Online PowerShell. Pre-authorised for Exchange Online and Security & Compliance.
EXCHANGE_POWERSHELL_CLIENT_ID = "fb78d390-0c51-40cd-8e17-fdbfab77341b"

GRAPH_RESOURCE = "https://graph.microsoft.com"
ARM_RESOURCE = "https://management.azure.com"
KEY_VAULT_RESOURCE = "https://vault.azure.net"
EXCHANGE_RESOURCE = "https://outlook.office365.com"
IPPS_RESOURCE = "https://ps.compliance.protection.outlook.com"
