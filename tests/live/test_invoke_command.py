"""The Exchange and Security & Compliance clients against the real InvokeCommand endpoint."""

from __future__ import annotations

import pytest

from azure_auth import AuthContext, ExchangeClient, IppsClient
from tests.live.support import _flag, needs_user, require_cached_sign_in

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]


@needs_user
@_flag("AZURE_AUTH_TEST_EXCHANGE")
async def test_exchange_runs_a_cmdlet(user_auth: AuthContext) -> None:
    async with ExchangeClient(user_auth) as exchange:
        require_cached_sign_in(exchange)
        config = await exchange.run("Get-OrganizationConfig")
    assert config
    assert "Name" in config[0]


@needs_user
@_flag("AZURE_AUTH_TEST_IPPS")
async def test_ipps_runs_a_cmdlet_through_the_regional_host(user_auth: AuthContext) -> None:
    async with IppsClient(user_auth) as ipps:
        require_cached_sign_in(ipps)
        labels = await ipps.run("Get-Label")
        assert isinstance(labels, list)
        assert ipps.base_url.endswith("ps.compliance.protection.outlook.com")
