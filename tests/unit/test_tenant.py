"""Unit tests for the tenant: reading its OpenID configuration, the lookup, and the object.

The configurations here are cut down from real ones fetched on 2026-09-26, one per cloud,
with the GUIDs replaced. ``tests/live/test_clouds.py`` fetches the real ones.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from azure_auth import AmbiguousTenant, AuthError, Tenant, TenantNotFound
from azure_auth.clouds import CHINA, COMMERCIAL, US_GOV, US_GOV_DOD, Cloud
from tests.http import Recorder, ok

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def fake_lookup() -> None:
    """The lookup is what is under test here, so it is left real."""


COMMERCIAL_ID = "11111111-0000-0000-0000-000000000001"
GCC_ID = "11111111-0000-0000-0000-000000000002"
GCC_HIGH_ID = "11111111-0000-0000-0000-000000000003"
DOD_ID = "11111111-0000-0000-0000-000000000004"
CHINA_ID = "11111111-0000-0000-0000-000000000005"


def oidc_config(
    tenant_id: str, login_host: str, graph_host: str, scope: str, sub_scope: str | None = None
) -> dict[str, Any]:
    """Build an OpenID configuration with the fields a real one carries for a tenant."""
    return {
        "issuer": f"https://{login_host}/{tenant_id}/v2.0",
        "token_endpoint": f"https://{login_host}/{tenant_id}/oauth2/v2.0/token",
        "tenant_region_scope": scope,
        "tenant_region_sub_scope": sub_scope,
        "cloud_instance_name": login_host.removeprefix("login."),
        "msgraph_host": graph_host,
    }


COMMERCIAL_OIDC = oidc_config(
    COMMERCIAL_ID, "login.microsoftonline.com", "graph.microsoft.com", "NA"
)
GCC_OIDC = oidc_config(GCC_ID, "login.microsoftonline.com", "graph.microsoft.com", "NA", "GCC")
GCC_HIGH_OIDC = oidc_config(
    GCC_HIGH_ID, "login.microsoftonline.us", "graph.microsoft.us", "USGov", "DODCON"
)
DOD_OIDC = oidc_config(DOD_ID, "login.microsoftonline.us", "dod-graph.microsoft.us", "USGov", "DOD")
CHINA_OIDC = oidc_config(
    CHINA_ID, "login.partner.microsoftonline.cn", "microsoftgraph.chinacloudapi.cn", "AS"
)
NOT_FOUND = {"error": "invalid_tenant", "error_description": "AADSTS90002: Tenant not found."}

# The sign-in hosts the lookup asks.
COM, US, CN = "login.microsoftonline.com", "login.microsoftonline.us", "login.chinacloudapi.cn"


def by_host(answers: dict[str, dict[str, Any] | None]) -> Recorder:
    """Answer the lookup per sign-in host: a configuration, or "no such tenant" for ``None``."""

    def handler(request: httpx.Request) -> httpx.Response:
        answer = answers[request.url.host]
        return ok(answer) if answer is not None else ok(NOT_FOUND, status=400)

    return Recorder(handler)


# ---------------------------------------------------------------------------- configurations


@pytest.mark.parametrize(
    ("oidc", "tenant_id", "cloud", "sub_scope"),
    [
        (COMMERCIAL_OIDC, COMMERCIAL_ID, COMMERCIAL, None),
        (GCC_OIDC, GCC_ID, COMMERCIAL, "GCC"),
        (GCC_HIGH_OIDC, GCC_HIGH_ID, US_GOV, "DODCON"),
        (DOD_OIDC, DOD_ID, US_GOV_DOD, "DOD"),
        (CHINA_OIDC, CHINA_ID, CHINA, None),
    ],
    ids=["commercial", "gcc", "gcc-high", "dod", "china"],
)
def test_a_configuration_names_its_tenant_and_cloud(
    oidc: dict[str, Any], tenant_id: str, cloud: Cloud, sub_scope: str | None
) -> None:
    tenant = Tenant.from_oidc(oidc)
    assert (tenant.id, tenant.cloud, tenant.region_sub_scope) == (tenant_id, cloud, sub_scope)
    assert tenant.region_scope == oidc["tenant_region_scope"]
    assert tenant.oidc == oidc


def test_the_region_fields_do_not_decide_the_cloud() -> None:
    # Only the hosts do, so a region value never seen before cannot misplace a tenant.
    oidc = {**DOD_OIDC, "tenant_region_scope": "USG", "tenant_region_sub_scope": "UNSEEN"}
    assert Tenant.from_oidc(oidc).cloud is US_GOV_DOD


def test_the_commercial_alias_host_is_recognised() -> None:
    oidc = {**COMMERCIAL_OIDC, "issuer": f"https://login.windows.net/{COMMERCIAL_ID}/v2.0"}
    assert Tenant.from_oidc(oidc).cloud is COMMERCIAL


def test_a_configuration_from_an_unknown_cloud_is_refused() -> None:
    oidc = oidc_config(COMMERCIAL_ID, "login.sovcloud-identity.fr", "graph.svc.sovcloud.fr", "EU")
    with pytest.raises(AuthError, match="matches no known cloud"):
        Tenant.from_oidc(oidc)


def test_a_configuration_whose_issuer_names_no_tenant_is_refused() -> None:
    oidc = {**COMMERCIAL_OIDC, "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"}
    with pytest.raises(AuthError, match="names no tenant"):
        Tenant.from_oidc(oidc)


# ---------------------------------------------------------------------------- lookup


def test_the_lookup_asks_every_sign_in_host_and_merges_the_same_tenant() -> None:
    # The US government and China hosts both answer for a commercial tenant too.
    recorder = by_host({COM: COMMERCIAL_OIDC, US: COMMERCIAL_OIDC, CN: COMMERCIAL_OIDC})

    tenant = Tenant.lookup("Contoso.com", transport=recorder.transport)

    assert (tenant.id, tenant.cloud, tenant.domain) == (COMMERCIAL_ID, COMMERCIAL, "contoso.com")
    assert recorder.urls() == [
        f"https://{host}/Contoso.com/v2.0/.well-known/openid-configuration"
        for host in (COM, US, CN)
    ]


def test_a_us_government_tenant_is_found() -> None:
    recorder = by_host({COM: DOD_OIDC, US: DOD_OIDC, CN: None})
    assert Tenant.lookup("army.example", transport=recorder.transport).cloud is US_GOV_DOD


def test_a_china_domain_is_found_through_the_china_host() -> None:
    recorder = by_host({COM: None, US: None, CN: CHINA_OIDC})
    assert Tenant.lookup("contoso.cn", transport=recorder.transport).cloud is CHINA


def test_a_domain_in_two_clouds_is_ambiguous() -> None:
    recorder = by_host({COM: COMMERCIAL_OIDC, US: COMMERCIAL_OIDC, CN: CHINA_OIDC})

    with pytest.raises(AmbiguousTenant) as caught:
        Tenant.lookup("both.example", transport=recorder.transport)

    assert caught.value.name == "both.example"
    assert [tenant.cloud for tenant in caught.value.candidates] == [COMMERCIAL, CHINA]
    assert COMMERCIAL_ID in str(caught.value)
    assert CHINA_ID in str(caught.value)


def test_a_guid_that_is_a_tenant_in_two_clouds_is_ambiguous() -> None:
    # Measured 2026-09-29 for f8cdef31-...: the commercial host answers with a commercial
    # tenant, the US government host with a US government tenant, under the one GUID.
    in_gcc_high = {
        **GCC_HIGH_OIDC,
        "issuer": f"https://login.microsoftonline.us/{COMMERCIAL_ID}/v2.0",
    }
    recorder = by_host({COM: COMMERCIAL_OIDC, US: in_gcc_high, CN: COMMERCIAL_OIDC})

    with pytest.raises(AmbiguousTenant, match="with the cloud of the one you mean") as caught:
        Tenant.lookup(COMMERCIAL_ID, transport=recorder.transport)

    assert [(t.id, t.cloud, t.domain) for t in caught.value.candidates] == [
        (COMMERCIAL_ID, COMMERCIAL, None),
        (COMMERCIAL_ID, US_GOV, None),
    ]


def test_an_unknown_tenant_is_not_found_anywhere() -> None:
    recorder = by_host({COM: None, US: None, CN: None})
    with pytest.raises(TenantNotFound, match="any known cloud") as caught:
        Tenant.lookup("nobody.example", transport=recorder.transport)
    assert caught.value.name == "nobody.example"


def test_an_unexpected_answer_is_an_error_not_a_miss() -> None:
    recorder = Recorder(lambda request: httpx.Response(500, text="upstream failure"))
    with pytest.raises(AuthError, match="answered 500: upstream failure"):
        Tenant.lookup("contoso.com", transport=recorder.transport)


@pytest.mark.parametrize("tenant", ["", "contoso.com/../x", "a b", "contoso.com?x=1", ".hidden"])
def test_anything_but_a_tenant_id_or_domain_is_refused_before_a_request(tenant: str) -> None:
    recorder = Recorder([])
    with pytest.raises(ValueError, match="Not a tenant id or domain name"):
        Tenant.lookup(tenant, transport=recorder.transport)
    assert recorder.requests == []


def test_naming_the_cloud_settles_a_name_that_is_a_tenant_in_two_clouds() -> None:
    recorder = by_host({COM: COMMERCIAL_OIDC, US: COMMERCIAL_OIDC, CN: CHINA_OIDC})

    china = Tenant.lookup("both.example", CHINA, transport=recorder.transport)
    commercial = Tenant.lookup("both.example", COMMERCIAL, transport=recorder.transport)

    assert (china.id, china.cloud) == (CHINA_ID, CHINA)
    assert (commercial.id, commercial.cloud) == (COMMERCIAL_ID, COMMERCIAL)


def test_gcc_high_and_dod_each_find_the_tenant_in_their_shared_directory() -> None:
    recorder = by_host({COM: DOD_OIDC, US: DOD_OIDC, CN: None})
    # The tenant is as found: the cloud named only says where to look.
    assert Tenant.lookup("army.example", US_GOV, transport=recorder.transport).cloud is US_GOV_DOD


def test_a_tenant_not_in_the_named_cloud_is_not_found() -> None:
    recorder = by_host({COM: COMMERCIAL_OIDC, US: COMMERCIAL_OIDC, CN: COMMERCIAL_OIDC})
    with pytest.raises(TenantNotFound, match="the China cloud"):
        Tenant.lookup("contoso.com", CHINA, transport=recorder.transport)


# ---------------------------------------------------------------------------- the object


def test_a_tenant_id_is_held_in_its_one_spelling() -> None:
    assert Tenant(COMMERCIAL_ID.upper(), COMMERCIAL).id == COMMERCIAL_ID
    assert Tenant("Organizations", COMMERCIAL).id == "organizations"


def test_a_domain_name_is_not_an_id() -> None:
    with pytest.raises(ValueError, match=r"use Tenant.lookup"):
        Tenant("contoso.com", COMMERCIAL)


def test_the_same_id_in_the_same_cloud_is_the_same_tenant() -> None:
    plain = Tenant(COMMERCIAL_ID, COMMERCIAL)
    known = Tenant(COMMERCIAL_ID, COMMERCIAL, domain="contoso.com", oidc=COMMERCIAL_OIDC)

    assert plain == known
    assert len({plain, known}) == 1
    assert plain != Tenant(COMMERCIAL_ID, US_GOV)


def test_a_tenant_is_named_by_its_domain_when_known() -> None:
    tenant = Tenant(COMMERCIAL_ID, COMMERCIAL)
    assert str(tenant) == COMMERCIAL_ID
    tenant.domain = "contoso.com"
    assert str(tenant) == "contoso.com"
    assert repr(tenant) == f"Tenant(id={COMMERCIAL_ID!r}, cloud='Commercial', domain='contoso.com')"


def test_a_tenant_built_by_hand_has_no_region() -> None:
    tenant = Tenant(COMMERCIAL_ID, COMMERCIAL)
    assert (tenant.oidc, tenant.region_scope, tenant.region_sub_scope) == (None, None, None)
