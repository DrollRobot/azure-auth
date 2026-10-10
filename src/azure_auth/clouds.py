"""The Microsoft clouds: where each one signs in, and where its services live.

A :class:`Cloud` is one isolated instance of Entra ID and the services that trust it. A tenant
lives in exactly one, and a token from one is worthless in another, so an
:class:`~azure_auth.AuthContext` and every client built on it address a single cloud.

GCC ("GCC Moderate") is not a cloud of its own: its tenants live in :data:`COMMERCIAL` and
differ only in :attr:`azure_auth.Tenant.region_sub_scope`. GCC High and DoD share a sign-in
host but not their Graph, Exchange or Security & Compliance hosts, so they are two clouds
here.

Sources: the Exchange hosts are the ExchangeOnlineManagement module's own environment table
(3.10.1), and the IPPS hosts its ``Connect-IPPSSession`` connection URIs. Every host below
was checked live on 2026-09-26: each answers an unauthenticated request with a challenge
naming its cloud's sign-in host (``tests/live/test_clouds.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from azure_auth.constants import (
    AZURE_POWERSHELL_CLIENT_ID,
    EXCHANGE_POWERSHELL_CLIENT_ID,
    GRAPH_CLI_CLIENT_ID,
)

_EVERY_CLIENT_ID = frozenset(
    {GRAPH_CLI_CLIENT_ID, AZURE_POWERSHELL_CLIENT_ID, EXCHANGE_POWERSHELL_CLIENT_ID}
)


@dataclass(frozen=True)
class Cloud:
    """The endpoints of one Microsoft cloud.

    Every service URL is also the resource identifier its tokens are issued for, so
    ``<url>/.default`` is the service's default scope.

    Attributes:
        name: Short name, as :func:`get_cloud` accepts it.
        authority_host: Entra ID sign-in host, as a URL.
        login_hosts: Every host name this cloud's Entra ID answers from or signs as, including
            aliases such as ``login.windows.net``. Used to recognise the cloud from a
            discovery document or a resource's challenge.
        graph: Microsoft Graph.
        arm: Azure Resource Manager.
        exchange: Exchange Online. Requests go to this host.
        ipps: Security & Compliance, as the resource tokens are issued for.
        ipps_host: Host that Security & Compliance requests are sent to first. Usually the
            host of ``ipps``; DoD sends them to a prefixed host.
        first_party_client_ids: The package's default client ids (see
            :mod:`azure_auth.constants`) that Microsoft publishes in this cloud. A client
            whose default is missing needs ``client_id=`` of the caller's own application.
    """

    name: str
    authority_host: str
    login_hosts: frozenset[str]
    graph: str
    arm: str
    exchange: str
    ipps: str
    ipps_host: str
    first_party_client_ids: frozenset[str] = _EVERY_CLIENT_ID

    @property
    def graph_host(self) -> str:
        """Host name of Microsoft Graph, as discovery documents report it."""
        return urlsplit(self.graph).hostname or ""


COMMERCIAL = Cloud(
    name="Commercial",
    authority_host="https://login.microsoftonline.com",
    login_hosts=frozenset(
        {"login.microsoftonline.com", "login.windows.net", "login.microsoft.com", "sts.windows.net"}
    ),
    graph="https://graph.microsoft.com",
    arm="https://management.azure.com",
    exchange="https://outlook.office365.com",
    ipps="https://ps.compliance.protection.outlook.com",
    ipps_host="ps.compliance.protection.outlook.com",
)
"""The worldwide cloud, including GCC."""

US_GOV = Cloud(
    name="USGov",
    authority_host="https://login.microsoftonline.us",
    login_hosts=frozenset({"login.microsoftonline.us", "login.usgovcloudapi.net"}),
    graph="https://graph.microsoft.us",
    arm="https://management.usgovcloudapi.net",
    exchange="https://outlook.office365.us",
    ipps="https://ps.compliance.protection.office365.us",
    ipps_host="ps.compliance.protection.office365.us",
)
"""US Government GCC High."""

US_GOV_DOD = Cloud(
    name="USGovDoD",
    authority_host="https://login.microsoftonline.us",
    login_hosts=frozenset({"login.microsoftonline.us", "login.usgovcloudapi.net"}),
    graph="https://dod-graph.microsoft.us",
    # Azure Government serves DoD from the same Resource Manager as GCC High.
    arm="https://management.usgovcloudapi.net",
    exchange="https://outlook-dod.office365.us",
    # The module strips the "l5." prefix to get the token audience, and so does this table.
    ipps="https://ps.compliance.protection.office365.us",
    ipps_host="l5.ps.compliance.protection.office365.us",
)
"""US Government DoD."""

CHINA = Cloud(
    name="China",
    authority_host="https://login.chinacloudapi.cn",
    login_hosts=frozenset({"login.chinacloudapi.cn", "login.partner.microsoftonline.cn"}),
    graph="https://microsoftgraph.chinacloudapi.cn",
    arm="https://management.chinacloudapi.cn",
    exchange="https://partner.outlook.cn",
    ipps="https://ps.compliance.protection.partner.outlook.cn",
    ipps_host="ps.compliance.protection.partner.outlook.cn",
    # Microsoft Graph Command Line Tools does not exist here: its device code request is
    # refused like a made-up id's (AADSTS50059), while the other two are answered (measured
    # 2026-09-27).
    first_party_client_ids=frozenset({AZURE_POWERSHELL_CLIENT_ID, EXCHANGE_POWERSHELL_CLIENT_ID}),
)
"""Microsoft 365 and Azure operated by 21Vianet."""

CLOUDS: tuple[Cloud, ...] = (COMMERCIAL, US_GOV, US_GOV_DOD, CHINA)
"""Every cloud this package knows, in the order discovery tries them."""


def get_cloud(cloud: Cloud | str) -> Cloud:
    """Look a cloud up by name.

    Args:
        cloud: A :class:`Cloud`, returned as it is, or the name of a known one, in any case:
            ``Commercial``, ``USGov``, ``USGovDoD`` or ``China``.

    Returns:
        The cloud.

    Raises:
        ValueError: If no known cloud has that name.
    """
    if isinstance(cloud, Cloud):
        return cloud
    for known in CLOUDS:
        if known.name.lower() == cloud.lower():
            return known
    names = ", ".join(known.name for known in CLOUDS)
    raise ValueError(f"Unknown cloud {cloud!r}; expected one of {names}")
