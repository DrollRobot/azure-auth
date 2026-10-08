"""Unit tests for the cloud table and tenant discovery.

The discovery documents here are cut down from real ones fetched on 2026-09-26, one per
cloud, with the GUIDs replaced. ``tests/live/test_clouds.py`` fetches the real ones.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from azure_auth import AmbiguousTenant, AuthError, TenantNotFound, discover_tenant
from azure_auth.auth.discovery import tenant_from_document
from azure_auth.clouds import CHINA, CLOUDS, COMMERCIAL, US_GOV, US_GOV_DOD, Cloud, get_cloud
from azure_auth.constants import (
    AZURE_POWERSHELL_CLIENT_ID,
    EXCHANGE_POWERSHELL_CLIENT_ID,
    GRAPH_CLI_CLIENT_ID,
)
from tests.http import Recorder, ok

pytestmark = pytest.mark.unit

COMMERCIAL_ID = "11111111-0000-0000-0000-000000000001"
GCC_ID = "11111111-0000-0000-0000-000000000002"
GCC_HIGH_ID = "11111111-0000-0000-0000-000000000003"
DOD_ID = "11111111-0000-0000-0000-000000000004"
CHINA_ID = "11111111-0000-0000-0000-000000000005"


def document(
    tenant_id: str, login_host: str, graph_host: str, scope: str, sub_scope: str | None = None
) -> dict[str, Any]:
    """Build a discovery document with the fields a real one carries for a tenant."""
    return {
        "issuer": f"https://{login_host}/{tenant_id}/v2.0",
        "token_endpoint": f"https://{login_host}/{tenant_id}/oauth2/v2.0/token",
        "tenant_region_scope": scope,
        "tenant_region_sub_scope": sub_scope,
        "cloud_instance_name": login_host.removeprefix("login."),
        "msgraph_host": graph_host,
    }


COMMERCIAL_DOC = document(COMMERCIAL_ID, "login.microsoftonline.com", "graph.microsoft.com", "NA")
GCC_DOC = document(GCC_ID, "login.microsoftonline.com", "graph.microsoft.com", "NA", "GCC")
GCC_HIGH_DOC = document(
    GCC_HIGH_ID, "login.microsoftonline.us", "graph.microsoft.us", "USGov", "DODCON"
)
DOD_DOC = document(DOD_ID, "login.microsoftonline.us", "dod-graph.microsoft.us", "USGov", "DOD")
CHINA_DOC = document(
    CHINA_ID, "login.partner.microsoftonline.cn", "microsoftgraph.chinacloudapi.cn", "AS"
)
NOT_FOUND = {"error": "invalid_tenant", "error_description": "AADSTS90002: Tenant not found."}

# The sign-in hosts discovery asks.
COM, US, CN = "login.microsoftonline.com", "login.microsoftonline.us", "login.chinacloudapi.cn"


def by_host(answers: dict[str, dict[str, Any] | None]) -> Recorder:
    """Answer discovery per sign-in host: a document, or "no such tenant" for ``None``."""

    def handler(request: httpx.Request) -> httpx.Response:
        answer = answers[request.url.host]
        return ok(answer) if answer is not None else ok(NOT_FOUND, status=400)

    return Recorder(handler)


# ---------------------------------------------------------------------------- the table


def test_every_cloud_is_found_by_name_in_any_case() -> None:
    assert [get_cloud(cloud.name.upper()) for cloud in CLOUDS] == list(CLOUDS)
    assert get_cloud("usgovdod") is US_GOV_DOD
    assert get_cloud(CHINA) is CHINA


def test_an_unknown_cloud_name_is_refused_with_the_known_ones() -> None:
    with pytest.raises(ValueError, match="Commercial, USGov, USGovDoD, China"):
        get_cloud("Germany")


def test_gcc_high_and_dod_share_a_sign_in_host_but_nothing_they_serve() -> None:
    assert US_GOV.authority_host == US_GOV_DOD.authority_host
    assert US_GOV.graph_host != US_GOV_DOD.graph_host
    assert US_GOV.exchange != US_GOV_DOD.exchange
    assert US_GOV.ipps_host != US_GOV_DOD.ipps_host


def test_dod_security_and_compliance_is_sent_to_l5_but_issued_for_the_bare_host() -> None:
    assert US_GOV_DOD.ipps_host == "l5.ps.compliance.protection.office365.us"
    assert US_GOV_DOD.ipps == "https://ps.compliance.protection.office365.us"


def test_every_cloud_signs_in_at_one_of_its_own_hosts() -> None:
    for cloud in CLOUDS:
        assert httpx.URL(cloud.authority_host).host in cloud.login_hosts


def test_graph_command_line_tools_is_missing_only_from_china() -> None:
    every_id = {GRAPH_CLI_CLIENT_ID, AZURE_POWERSHELL_CLIENT_ID, EXCHANGE_POWERSHELL_CLIENT_ID}
    for cloud in (COMMERCIAL, US_GOV, US_GOV_DOD):
        assert cloud.first_party_client_ids == every_id
    assert CHINA.first_party_client_ids == every_id - {GRAPH_CLI_CLIENT_ID}


# ---------------------------------------------------------------------------- documents


@pytest.mark.parametrize(
    ("doc", "tenant_id", "cloud", "sub_scope"),
    [
        (COMMERCIAL_DOC, COMMERCIAL_ID, COMMERCIAL, None),
        (GCC_DOC, GCC_ID, COMMERCIAL, "GCC"),
        (GCC_HIGH_DOC, GCC_HIGH_ID, US_GOV, "DODCON"),
        (DOD_DOC, DOD_ID, US_GOV_DOD, "DOD"),
        (CHINA_DOC, CHINA_ID, CHINA, None),
    ],
    ids=["commercial", "gcc", "gcc-high", "dod", "china"],
)
def test_a_document_names_its_tenant_and_cloud(
    doc: dict[str, Any], tenant_id: str, cloud: Cloud, sub_scope: str | None
) -> None:
    info = tenant_from_document(doc)
    assert (info.tenant_id, info.cloud, info.region_sub_scope) == (tenant_id, cloud, sub_scope)
    assert info.region_scope == doc["tenant_region_scope"]
    assert info.document == doc


def test_the_region_fields_do_not_decide_the_cloud() -> None:
    # Only the hosts do, so a region value never seen before cannot misplace a tenant.
    doc = {**DOD_DOC, "tenant_region_scope": "USG", "tenant_region_sub_scope": "UNSEEN"}
    assert tenant_from_document(doc).cloud is US_GOV_DOD


def test_the_commercial_alias_host_is_recognised() -> None:
    doc = {**COMMERCIAL_DOC, "issuer": f"https://login.windows.net/{COMMERCIAL_ID}/v2.0"}
    assert tenant_from_document(doc).cloud is COMMERCIAL


def test_a_document_from_an_unknown_cloud_is_refused() -> None:
    doc = document(COMMERCIAL_ID, "login.sovcloud-identity.fr", "graph.svc.sovcloud.fr", "EU")
    with pytest.raises(AuthError, match="matches no known cloud"):
        tenant_from_document(doc)


def test_a_document_whose_issuer_names_no_tenant_is_refused() -> None:
    doc = {**COMMERCIAL_DOC, "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"}
    with pytest.raises(AuthError, match="names no tenant"):
        tenant_from_document(doc)


# ---------------------------------------------------------------------------- discovery


def test_discovery_asks_every_sign_in_host_and_merges_the_same_tenant() -> None:
    # The US government and China hosts both answer for a commercial tenant too.
    recorder = by_host({COM: COMMERCIAL_DOC, US: COMMERCIAL_DOC, CN: COMMERCIAL_DOC})

    info = discover_tenant("contoso.com", transport=recorder.transport)

    assert (info.tenant_id, info.cloud) == (COMMERCIAL_ID, COMMERCIAL)
    assert recorder.urls() == [
        f"https://{host}/contoso.com/v2.0/.well-known/openid-configuration"
        for host in (COM, US, CN)
    ]


def test_a_us_government_tenant_is_found() -> None:
    recorder = by_host({COM: DOD_DOC, US: DOD_DOC, CN: None})
    assert discover_tenant("army.example", transport=recorder.transport).cloud is US_GOV_DOD


def test_a_china_domain_is_found_through_the_china_host() -> None:
    recorder = by_host({COM: None, US: None, CN: CHINA_DOC})
    assert discover_tenant("contoso.cn", transport=recorder.transport).cloud is CHINA


def test_a_domain_in_two_clouds_is_ambiguous() -> None:
    recorder = by_host({COM: COMMERCIAL_DOC, US: COMMERCIAL_DOC, CN: CHINA_DOC})

    with pytest.raises(AmbiguousTenant) as caught:
        discover_tenant("both.example", transport=recorder.transport)

    assert caught.value.tenant == "both.example"
    assert [info.cloud for info in caught.value.candidates] == [COMMERCIAL, CHINA]
    assert COMMERCIAL_ID in str(caught.value)
    assert CHINA_ID in str(caught.value)


def test_a_guid_that_is_a_tenant_in_two_clouds_is_ambiguous() -> None:
    # Measured 2026-09-29 for f8cdef31-...: the commercial host answers with a commercial
    # tenant, the US government host with a US government tenant, under the one GUID.
    in_gcc_high = {
        **GCC_HIGH_DOC,
        "issuer": f"https://login.microsoftonline.us/{COMMERCIAL_ID}/v2.0",
    }
    recorder = by_host({COM: COMMERCIAL_DOC, US: in_gcc_high, CN: COMMERCIAL_DOC})

    with pytest.raises(AmbiguousTenant, match="Pass the GUID of the one you mean") as caught:
        discover_tenant(COMMERCIAL_ID, transport=recorder.transport)

    assert [(i.tenant_id, i.cloud) for i in caught.value.candidates] == [
        (COMMERCIAL_ID, COMMERCIAL),
        (COMMERCIAL_ID, US_GOV),
    ]


def test_an_unknown_tenant_is_not_found_anywhere() -> None:
    recorder = by_host({COM: None, US: None, CN: None})
    with pytest.raises(TenantNotFound, match="any known cloud") as caught:
        discover_tenant("nobody.example", transport=recorder.transport)
    assert caught.value.tenant == "nobody.example"


def test_an_unexpected_answer_is_an_error_not_a_miss() -> None:
    recorder = Recorder(lambda request: httpx.Response(500, text="upstream failure"))
    with pytest.raises(AuthError, match="answered 500: upstream failure"):
        discover_tenant("contoso.com", transport=recorder.transport)


@pytest.mark.parametrize("tenant", ["", "contoso.com/../x", "a b", "contoso.com?x=1", ".hidden"])
def test_anything_but_a_tenant_id_or_domain_is_refused_before_a_request(tenant: str) -> None:
    recorder = Recorder([])
    with pytest.raises(ValueError, match="Not a tenant id or domain name"):
        discover_tenant(tenant, transport=recorder.transport)
    assert recorder.requests == []
