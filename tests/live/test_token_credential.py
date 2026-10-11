"""The context as an Azure SDK credential, called the way the SDK calls it.

``get_token`` and ``get_token_info`` had only ever run live underneath an SDK client, in the
Key Vault tests. Here they are called directly, blocking and through the asynchronous view,
and the token they hand back is used against the resource it names with a plain HTTP request,
so none of the package's own clients is in the path.
"""

from __future__ import annotations

import time

import httpx
import pytest

from azure_auth import AuthContext
from azure_auth.constants import AZURE_POWERSHELL_CLIENT_ID
from tests.live.support import USERNAME, ensure_token, live_cloud, needs_user, token_claims

pytestmark = [pytest.mark.e2e, pytest.mark.live, pytest.mark.anyio]


@needs_user
async def test_get_token_and_get_token_info_hand_the_sdk_one_usable_token(
    user_auth: AuthContext,
) -> None:
    """``get_token`` and ``get_token_info``, blocking and asynchronous, agree on a working token.

    An SDK client calls ``get_token`` with the resource's ``.default`` scope, the newer ones
    ``get_token_info``, and both pass ``enable_cae`` and may pass ``tenant_id``; the
    asynchronous SDK clients call the same two on ``auth.aio``. All four are called here with
    those arguments. A user context with no client id of its own signs in to Azure PowerShell,
    which is pre-authorised for Graph, so the token is tried against Graph itself. The cache
    answers the three calls after the first, so all four must hand back the same token.

    The token must also record that the sign-in declared continuous access evaluation
    (``xms_cc`` holding ``CP1``), which is what lets Graph send the claims challenges the
    clients answer. Its lifetime is printed: Entra issues such tokens for far longer than the
    hour or so of a plain one.
    """
    graph = live_cloud().graph
    scope = f"{graph}/.default"
    ensure_token(user_auth, [scope])

    token = user_auth.get_token(scope, enable_cae=True)
    assert token.expires_on > time.time()
    claims = token_claims(token.token)
    assert AZURE_POWERSHELL_CLIENT_ID in (claims.get("appid"), claims.get("azp"))
    assert "CP1" in claims.get("xms_cc", []), claims.get("xms_cc")
    print(f"token credential: issued for {(claims['exp'] - claims['iat']) / 60:.0f} minutes")

    async with httpx.AsyncClient() as http:
        me = await http.get(
            f"{graph}/v1.0/me",
            params={"$select": "userPrincipalName"},
            headers={"Authorization": f"Bearer {token.token}"},
        )
    assert me.status_code == 200, me.text
    assert me.json()["userPrincipalName"].lower() == USERNAME.lower()

    info = user_auth.get_token_info(
        scope, options={"tenant_id": user_auth.tenant.id, "enable_cae": True}
    )
    assert info.token_type == "Bearer"
    assert (info.token, info.expires_on) == (token.token, token.expires_on)

    aio_token = await user_auth.aio.get_token(scope, tenant_id=user_auth.tenant.id)
    aio_info = await user_auth.aio.get_token_info(scope, options={"enable_cae": True})
    assert (aio_token.token, aio_token.expires_on) == (token.token, token.expires_on)
    assert (aio_info.token, aio_info.expires_on) == (token.token, token.expires_on)
