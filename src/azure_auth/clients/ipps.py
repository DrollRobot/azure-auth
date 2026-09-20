"""Client for Security & Compliance (IPPS) cmdlets."""

from __future__ import annotations

from typing import ClassVar

from azure_auth.clients.invoke_command import InvokeCommandClient
from azure_auth.constants import IPPS_RESOURCE


class IppsClient(InvokeCommandClient):
    """Run Security & Compliance cmdlets without PowerShell.

    The service redirects the first call to a regional host. The client follows that
    redirect itself and keeps using the regional host, while tokens stay scoped to the
    global host.

    Example:
        >>> ipps = IppsClient(auth)  # doctest: +SKIP
        >>> labels = await ipps.run("Get-Label")  # doctest: +SKIP
    """

    RESOURCE: ClassVar[str] = IPPS_RESOURCE
    HOST: ClassVar[str] = "ps.compliance.protection.outlook.com"
