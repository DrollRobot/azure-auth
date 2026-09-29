"""Find the cloud a tenant lives in, from its public OpenID Connect discovery document.

Discovery is unauthenticated: ``https://<login host>/<tenant>/v2.0/.well-known/
openid-configuration`` describes any tenant to anybody. No single sign-in host answers for
every tenant (measured 2026-09-26 and 09-29):

* The commercial host answers for commercial and US government tenants, by GUID or by
  domain name, and for China tenants by GUID only.
* The US government host answers for US government and commercial tenants.
* The China host answers for China tenants, and falls back to the worldwide directory for
  a name it does not hold, so it answers for commercial tenants too.

Whichever answers, the document describes the tenant's own cloud (the issuer is on the
tenant's sign-in host, ``msgraph_host`` is its Graph), and the cloud is read from the
document rather than from the host that was asked.

One name can be a different tenant in each of two clouds, and each host then answers with
its own. A domain can be verified in a commercial tenant and in a China tenant
(``21vianet.com``), and a GUID can be both a commercial and a US government tenant
(``f8cdef31-a31e-4b4a-93e4-5f571e91255a``: the commercial host answers with the commercial
one). So all three sign-in hosts are asked, and two answers are never merged unless they
are the same tenant in the same cloud.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx

from azure_auth.auth.errors import AmbiguousTenant, AuthError, TenantNotFound
from azure_auth.clouds import CHINA, CLOUDS, COMMERCIAL, US_GOV, Cloud, TenantInfo

# Tenant ids and domain names; anything else would change the URL's path.
_TENANT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*")

# The sign-in hosts asked; GCC High and DoD share US_GOV's. See the module docstring for why
# every one of them is asked.
_DISCOVERY_CLOUDS = (COMMERCIAL, US_GOV, CHINA)


def tenant_from_document(document: Mapping[str, Any]) -> TenantInfo:
    """Read a tenant's id and cloud out of its discovery document.

    The cloud is the one whose sign-in hosts include the issuer's host and whose Graph host
    is the document's ``msgraph_host``. Both are needed: GCC High and DoD share a sign-in
    host and differ only in Graph. The region fields are kept but not used to decide.

    Args:
        document: The parsed discovery document.

    Returns:
        The tenant.

    Raises:
        AuthError: If the issuer holds no tenant GUID, or the document matches no known
            cloud.
    """
    issuer = urlsplit(str(document.get("issuer", "")))
    tenant_id = issuer.path.strip("/").split("/")[0]
    try:
        tenant_id = str(uuid.UUID(tenant_id))
    except ValueError:
        raise AuthError(
            f"The discovery document's issuer {issuer.geturl()!r} names no tenant"
        ) from None
    issuer_host = (issuer.hostname or "").lower()
    graph_host = str(document.get("msgraph_host", "")).lower()
    for cloud in CLOUDS:
        if issuer_host in cloud.login_hosts and graph_host == cloud.graph_host:
            return TenantInfo(
                tenant_id=tenant_id,
                cloud=cloud,
                region_scope=document.get("tenant_region_scope"),
                region_sub_scope=document.get("tenant_region_sub_scope"),
                document=dict(document),
            )
    raise AuthError(
        f"Tenant {tenant_id} signs in at {issuer_host} and uses Graph at {graph_host}, "
        "which matches no known cloud. Pass cloud= with a Cloud of your own."
    )


def _fetch(client: httpx.Client, cloud: Cloud, tenant: str) -> TenantInfo | None:
    """Ask one cloud's sign-in host for a tenant's discovery document.

    Args:
        client: The HTTP client.
        cloud: The cloud whose sign-in host is asked.
        tenant: Tenant id or domain name.

    Returns:
        The tenant, or ``None`` when that host does not know it.

    Raises:
        AuthError: If the host answers anything but the document or "no such tenant".
    """
    url = f"{cloud.authority_host.rstrip('/')}/{tenant}/v2.0/.well-known/openid-configuration"
    response = client.get(url)
    if response.status_code == httpx.codes.OK:
        return tenant_from_document(response.json())
    try:
        error = response.json().get("error")
    except ValueError:
        error = None
    # Entra answers 400 invalid_tenant for a name it does not hold (AADSTS90002) and for a
    # GUID it does not know (AADSTS900021).
    if response.status_code == httpx.codes.BAD_REQUEST and error == "invalid_tenant":
        return None
    raise AuthError(
        f"Discovery for {tenant} at {url} answered {response.status_code}: {response.text[:300]}"
    )


def discover_tenant(
    tenant: str, *, timeout: float = 30.0, transport: httpx.BaseTransport | None = None
) -> TenantInfo:
    """Look up any tenant by domain name or GUID, without signing in.

    Answers, for a tenant anywhere: its GUID, which Microsoft cloud it lives in, whether it
    is a GCC tenant, and its whole OpenID Connect discovery document. Only public endpoints
    are asked, so no account, credential or permission is needed, and the tenant can be
    anybody's. :class:`~azure_auth.AuthContext` runs the same lookup when it is not given a
    cloud.

    Example:
        >>> found = discover_tenant("contoso.com")  # doctest: +SKIP
        >>> found.tenant_id, found.cloud.name, found.region_sub_scope  # doctest: +SKIP
        ('00000000-0000-0000-0000-000000000000', 'Commercial', None)

    Args:
        tenant: Tenant id (GUID) or any verified domain name.
        timeout: Timeout for each request, in seconds.
        transport: Custom ``httpx`` transport, mainly for tests.

    Returns:
        The tenant.

    Raises:
        ValueError: If ``tenant`` is not a tenant id or domain name.
        TenantNotFound: If no tenant in any known cloud has that id or name.
        AmbiguousTenant: If the id or name belongs to a different tenant in each of two clouds.
        AuthError: If a sign-in host answers something unexpected, or the tenant's cloud is
            not a known one.
    """
    if not _TENANT_PATTERN.fullmatch(tenant):
        raise ValueError(f"Not a tenant id or domain name: {tenant!r}")
    with httpx.Client(timeout=timeout, transport=transport) as client:
        found = [_fetch(client, cloud, tenant) for cloud in _DISCOVERY_CLOUDS]
    tenants = list({(info.tenant_id, info.cloud.name): info for info in found if info}.values())
    if not tenants:
        raise TenantNotFound(f"No tenant {tenant!r} was found in any known cloud", tenant=tenant)
    if len(tenants) > 1:
        listed = "; ".join(f"{info.tenant_id} in {info.cloud.name}" for info in tenants)
        raise AmbiguousTenant(
            f"{tenant!r} names a different tenant in each cloud: {listed}. Pass cloud= to choose.",
            tenant=tenant,
            candidates=tenants,
        )
    return tenants[0]
