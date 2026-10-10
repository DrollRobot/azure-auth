"""Unit tests for the cloud table."""

from __future__ import annotations

import httpx
import pytest

from azure_auth.clouds import CHINA, CLOUDS, COMMERCIAL, US_GOV, US_GOV_DOD, get_cloud
from azure_auth.constants import (
    AZURE_POWERSHELL_CLIENT_ID,
    EXCHANGE_POWERSHELL_CLIENT_ID,
    GRAPH_CLI_CLIENT_ID,
)

pytestmark = pytest.mark.unit


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
