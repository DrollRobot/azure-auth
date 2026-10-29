"""The tenant a context signs in to, and the lookup that finds it.

A :class:`Tenant` is everything this package knows about one tenant: its GUID, its cloud, a
domain name when one is known, and its OpenID Connect configuration when it was looked up.

The lookup is unauthenticated: ``https://<login host>/<tenant>/v2.0/.well-known/
openid-configuration`` describes any tenant to anybody. No single sign-in host answers for
every tenant (measured 2026-09-26 and 09-29, again 2026-10-26):

* The commercial host answers for commercial and US government tenants, by GUID or by
  domain name, and for China tenants by GUID; in September it did not know a China domain
  name, by October it answered for one (``vgc.partner.onmschina.cn``).
* The US government host answers for US government and commercial tenants, not China.
* The China host answers for China tenants, and falls back to the worldwide directory for
  a name it does not hold, so it answers for commercial tenants too.

Whichever answers, the configuration describes the tenant's own cloud (the issuer is on the
tenant's sign-in host, ``msgraph_host`` is its Graph), and the cloud is read from it rather
than from the host that was asked.

One name can be a different tenant in each of two clouds, and each host then answers with
its own. A domain can be verified in a commercial tenant and in a China tenant
(``21vianet.com``), and a GUID can be both a commercial and a US government tenant
(``f8cdef31-a31e-4b4a-93e4-5f571e91255a``: the commercial host answers with the commercial
one). So all three sign-in hosts are asked, and two answers are never merged unless they
are the same tenant in the same cloud.

The hosts are asked at the same time, so a lookup takes as long as the slowest answer. A
host that cannot be reached (a network that blocks it, or a timeout) is skipped with a
warning, and the lookup answers from the hosts that did. A caller that knows a cloud is out
of the question can leave its host out, with ``clouds=``, and save even that wait.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx2

from azure_auth.auth.errors import AmbiguousTenant, AuthError, TenantNotFound
from azure_auth.clouds import CHINA, CLOUDS, COMMERCIAL, US_GOV, Cloud, get_cloud

_LOGGER = logging.getLogger(__name__)

# Tenant ids and domain names; anything else would change the URL's path.
_TENANT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*")

# Authorities that name no single tenant, so they have no GUID and nothing to look up.
MULTI_TENANT_AUTHORITIES = frozenset({"common", "organizations", "consumers"})

# The sign-in hosts asked unless the caller chooses; GCC High and DoD share US_GOV's. See the
# module docstring for why every one of them is asked.
_LOOKUP_CLOUDS: tuple[Cloud, ...] = (COMMERCIAL, US_GOV, CHINA)


def as_guid(value: str) -> str | None:
    """Return a tenant id in its one canonical spelling, or ``None`` for anything else.

    Args:
        value: A tenant id (GUID) or a domain name.

    Returns:
        The GUID, lower-case and hyphenated, or ``None`` when ``value`` is not one.
    """
    try:
        return str(uuid.UUID(value))
    except ValueError:
        return None


@dataclass
class Tenant:
    """One tenant: its GUID, its cloud, and what else is known about it.

    Build one by hand, with the GUID and the cloud, to use them as given with no request.
    :meth:`lookup` builds one from a GUID or domain name, and is what
    :class:`~azure_auth.AuthContext` runs when it is given a string.

    Attributes:
        id: The tenant's GUID. A multi-tenant authority (``common``, ``organizations``,
            ``consumers``) is the one exception, accepted only when built by hand.
        cloud: The cloud the tenant lives in.
        domain: A domain name of the tenant: the one it was looked up by, or the one found
            when a client needed it. ``None`` until either.
        oidc: The tenant's OpenID Connect configuration, from the lookup; ``None`` when the
            tenant was built by hand.
    """

    id: str
    cloud: Cloud
    domain: str | None = None
    oidc: Mapping[str, Any] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Hold the id in its canonical spelling, and refuse anything that is not one.

        Raises:
            ValueError: If ``id`` is neither a GUID nor a multi-tenant authority.
        """
        guid = as_guid(self.id)
        if guid is not None:
            self.id = guid
        elif self.id.lower() in MULTI_TENANT_AUTHORITIES:
            self.id = self.id.lower()
        else:
            raise ValueError(
                f"Tenant id {self.id!r} is not a GUID; use Tenant.lookup() for a domain name"
            )

    def __eq__(self, other: object) -> bool:
        """Tell whether two objects are the same tenant: the same id in the same cloud.

        Args:
            other: The object to compare with.

        Returns:
            ``True`` for the same tenant, whatever else either knows about it.
        """
        if not isinstance(other, Tenant):
            return NotImplemented
        return (self.id, self.cloud) == (other.id, other.cloud)

    def __hash__(self) -> int:
        """Hash the tenant by what makes it the same tenant.

        Returns:
            The hash of the id and the cloud.
        """
        return hash((self.id, self.cloud))

    def __repr__(self) -> str:
        """Describe the tenant by its id, cloud name and domain.

        Returns:
            A short description.
        """
        return f"Tenant(id={self.id!r}, cloud={self.cloud.name!r}, domain={self.domain!r})"

    def __str__(self) -> str:
        """Name the tenant for messages: its domain when known, else its id.

        Returns:
            The domain name or the id.
        """
        return self.domain or self.id

    @property
    def region_scope(self) -> str | None:
        """The tenant's region, from ``tenant_region_scope`` in its OIDC configuration.

        A continent code such as ``NA`` or ``EU`` in the commercial and China clouds,
        ``USGov`` in both US government clouds; ``None`` without a lookup.
        """
        return self.oidc.get("tenant_region_scope") if self.oidc else None

    @property
    def region_sub_scope(self) -> str | None:
        """The tenant's sub-region, from ``tenant_region_sub_scope`` in its OIDC configuration.

        ``GCC`` for a GCC tenant, ``DODCON`` for GCC High, ``DOD`` for DoD, and ``None`` for
        most others and without a lookup.
        """
        return self.oidc.get("tenant_region_sub_scope") if self.oidc else None

    @classmethod
    def from_oidc(cls, oidc: Mapping[str, Any], *, domain: str | None = None) -> Tenant:
        """Read a tenant's id and cloud out of its OpenID Connect configuration.

        The cloud is the one whose sign-in hosts include the issuer's host and whose Graph
        host is the configuration's ``msgraph_host``. Both are needed: GCC High and DoD share
        a sign-in host and differ only in Graph. The region fields are not used to decide.

        Args:
            oidc: The parsed configuration.
            domain: The domain name the tenant was looked up by, if any.

        Returns:
            The tenant.

        Raises:
            AuthError: If the issuer holds no tenant GUID, or the configuration matches no
                known cloud.
        """
        issuer = urlsplit(str(oidc.get("issuer", "")))
        tenant_id = as_guid(issuer.path.strip("/").split("/")[0])
        if tenant_id is None:
            raise AuthError(
                f"The OpenID configuration's issuer {issuer.geturl()!r} names no tenant"
            )
        issuer_host = (issuer.hostname or "").lower()
        graph_host = str(oidc.get("msgraph_host", "")).lower()
        for cloud in CLOUDS:
            if issuer_host in cloud.login_hosts and graph_host == cloud.graph_host:
                return cls(tenant_id, cloud, domain=domain, oidc=dict(oidc))
        raise AuthError(
            f"Tenant {tenant_id} signs in at {issuer_host} and uses Graph at {graph_host}, "
            "which matches no known cloud. Build the Tenant by hand with a Cloud of your own."
        )

    @classmethod
    def lookup(
        cls,
        name: str,
        cloud: Cloud | None = None,
        *,
        clouds: Iterable[Cloud | str] | None = None,
        timeout: float = 30.0,
        transport: httpx2.BaseTransport | None = None,
    ) -> Tenant:
        """Look up any tenant by GUID or domain name, without signing in.

        Answers, for a tenant anywhere: its GUID, which Microsoft cloud it lives in, whether
        it is a GCC tenant, and its whole OpenID Connect configuration. Only public endpoints
        are asked, so no account, credential or permission is needed, and the tenant can be
        anybody's.

        Every cloud's sign-in host is asked, one request each and all at once, because no
        single host knows every tenant. A host that cannot be reached, or does not answer
        within ``timeout``, is skipped with a warning (logger ``azure_auth.auth.tenant``)
        and the others decide. A cloud the tenant cannot be in is left out with ``clouds``:
        a network that blocks the China host then costs nothing instead of a timeout on
        every lookup.

        Example:
            >>> tenant = Tenant.lookup("contoso.com")  # doctest: +SKIP
            >>> tenant.id, tenant.cloud.name, tenant.region_sub_scope  # doctest: +SKIP
            ('00000000-0000-0000-0000-000000000000', 'Commercial', None)

        Args:
            name: Tenant id (GUID) or any verified domain name.
            cloud: The cloud to find the tenant in. Only needed for a name that is a
                different tenant in each of two clouds; GCC High and DoD share one directory,
                so either finds the tenant there.
            clouds: The clouds whose sign-in hosts are asked, as :class:`~azure_auth.Cloud`
                constants or names (``Commercial``, ``USGov``, ``USGovDoD``, ``China``), in
                the order to ask them. All of them by default. A tenant in a cloud left out
                is found only if another cloud's host happens to know it.
            timeout: Timeout for each request, in seconds.
            transport: Custom ``httpx2`` transport, mainly for tests.

        Returns:
            The tenant, with ``domain`` set when ``name`` is a domain name.

        Raises:
            ValueError: If ``name`` is not a tenant id or domain name, or ``clouds`` is empty
                or names a cloud that is not a known one.
            TenantNotFound: If no tenant has that id or name, in ``cloud`` when given, by
                the word of the hosts that answered.
            AmbiguousTenant: If the id or name is a different tenant in each of two clouds
                and ``cloud`` does not say which.
            AuthError: If no tenant was found and a host that might know it could not be
                reached; if a sign-in host answers something unexpected; or if the tenant's
                cloud is not a known one.
        """
        if not _TENANT_PATTERN.fullmatch(name):
            raise ValueError(f"Not a tenant id or domain name: {name!r}")
        asked = _lookup_clouds(clouds)
        domain = None if as_guid(name) else name.lower()
        found: list[Tenant] = []
        unreached: dict[Cloud, httpx2.TransportError] = {}
        with (
            httpx2.Client(timeout=timeout, transport=transport) as client,
            ThreadPoolExecutor(len(asked), thread_name_prefix="tenant-lookup") as pool,
        ):
            answers = [pool.submit(_fetch, client, known, name, domain) for known in asked]
            for known, answer in zip(asked, answers, strict=True):
                try:
                    tenant = answer.result()
                except httpx2.TransportError as error:
                    _LOGGER.warning(
                        "The %s sign-in host did not answer the lookup of %s (%s: %s); "
                        "going on without it",
                        known.name,
                        name,
                        type(error).__name__,
                        error,
                    )
                    unreached[known] = error
                    continue
                if tenant is not None:
                    found.append(tenant)
        tenants = list({(t.id, t.cloud.name): t for t in found}.values())
        if cloud is not None:
            tenants = [t for t in tenants if t.cloud.authority_host == cloud.authority_host]
            # A cloud's own host always answers for its own tenants, so when it did, the
            # other hosts have nothing to add.
            unreached = {
                c: e for c, e in unreached.items() if c.authority_host == cloud.authority_host
            }
        if not tenants:
            where = f"the {cloud.name} cloud" if cloud is not None else _describe(asked)
            message = f"No tenant {name!r} was found in {where}"
            if unreached:
                silent = "; ".join(
                    f"{c.name} ({urlsplit(c.authority_host).hostname}): {e}"
                    for c, e in unreached.items()
                )
                raise AuthError(
                    f"{message} by the sign-in hosts that answered, and the rest could not be "
                    f"reached: {silent}"
                ) from next(reversed(unreached.values()))
            raise TenantNotFound(message, name=name)
        if len(tenants) > 1:
            listed = "; ".join(f"{t.id} in {t.cloud.name}" for t in tenants)
            raise AmbiguousTenant(
                f"{name!r} names a different tenant in each cloud: {listed}. Look it up with "
                "the cloud of the one you mean.",
                name=name,
                candidates=tenants,
            )
        return tenants[0]


def _lookup_clouds(clouds: Iterable[Cloud | str] | None) -> tuple[Cloud, ...]:
    """Resolve the clouds a lookup asks to one per sign-in host, in the order given.

    Args:
        clouds: Clouds or cloud names, or ``None`` for every cloud.

    Returns:
        The clouds whose hosts are asked; of clouds sharing a host, the first named.

    Raises:
        ValueError: If ``clouds`` is empty or names an unknown cloud.
    """
    if clouds is None:
        return _LOOKUP_CLOUDS
    by_host: dict[str, Cloud] = {}
    for cloud in clouds:
        known = get_cloud(cloud)
        by_host.setdefault(known.authority_host, known)
    if not by_host:
        raise ValueError("clouds names no cloud whose sign-in host to ask")
    return tuple(by_host.values())


def _describe(asked: tuple[Cloud, ...]) -> str:
    """Name the clouds a lookup asked, for a "not found" message.

    Args:
        asked: The clouds, from :func:`_lookup_clouds`.

    Returns:
        ``any known cloud`` for the default, else the clouds by name.
    """
    if asked == _LOOKUP_CLOUDS:
        return "any known cloud"
    names = " or ".join(cloud.name for cloud in asked)
    return f"the {names} cloud" if len(asked) == 1 else f"the {names} clouds"


def _fetch(client: httpx2.Client, cloud: Cloud, name: str, domain: str | None) -> Tenant | None:
    """Ask one cloud's sign-in host for a tenant's OpenID Connect configuration.

    Args:
        client: The HTTP client.
        cloud: The cloud whose sign-in host is asked.
        name: Tenant id or domain name.
        domain: ``name`` when it is a domain name, for the tenant found.

    Returns:
        The tenant, or ``None`` when that host does not know it.

    Raises:
        AuthError: If the host answers anything but the configuration or "no such tenant".
        httpx2.TransportError: If the host cannot be reached or does not answer in time.
    """
    url = f"{cloud.authority_host.rstrip('/')}/{name}/v2.0/.well-known/openid-configuration"
    response = client.get(url)
    if response.status_code == httpx2.codes.OK:
        return Tenant.from_oidc(response.json(), domain=domain)
    try:
        error = response.json().get("error")
    except ValueError:
        error = None
    # Entra answers 400 invalid_tenant for a name it does not hold (AADSTS90002) and for a
    # GUID it does not know (AADSTS900021).
    if response.status_code == httpx2.codes.BAD_REQUEST and error == "invalid_tenant":
        return None
    raise AuthError(
        f"Lookup of {name} at {url} answered {response.status_code}: {response.text[:300]}"
    )
