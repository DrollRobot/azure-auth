"""Client for Security & Compliance (IPPS) cmdlets."""

from __future__ import annotations

from azure_auth.clients.invoke_command import InvokeCommandClient
from azure_auth.clouds import Cloud


class IppsClient(InvokeCommandClient):
    """Run Security & Compliance cmdlets without PowerShell.

    The service redirects the first call to a regional host. The client follows that
    redirect itself and keeps using the regional host, while tokens stay scoped to the
    global host.

    Example:
        >>> ipps = IppsClient(auth)  # doctest: +SKIP
        >>> labels = await ipps.run("Get-Label")  # doctest: +SKIP
    """

    @classmethod
    def service(cls, cloud: Cloud) -> tuple[str, str]:
        """Name Security & Compliance in a cloud.

        Args:
            cloud: The cloud.

        Returns:
            The resource, and the host requests go to first.
        """
        return cloud.ipps, cloud.ipps_host
