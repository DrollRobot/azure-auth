"""Unit tests for AuthContext: flows, precedence, tenants, single-flight."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from azure_auth import (
    AccountSelectionRequired,
    AuthContext,
    AuthError,
    BrokerUnavailable,
    ConsentRequired,
    InteractionRequired,
)
from azure_auth.auth.credentials import CertStoreCredential
from azure_auth.constants import AZURE_POWERSHELL_CLIENT_ID, GRAPH_CLI_CLIENT_ID
from tests.fakes import Call, FakeMsal, Result, error_result, token_result

pytestmark = pytest.mark.unit

USER = "admin@partner.com"
ARM_SCOPE = "https://management.azure.com/.default"
ACCOUNT = {"username": USER, "home_account_id": "uid.utid"}


def user_context(**kwargs: Any) -> AuthContext:
    return AuthContext("partner-tenant", username=USER, **kwargs)


# ---------------------------------------------------------------------------- construction


def test_user_flow_requires_username() -> None:
    with pytest.raises(ValueError, match="username is required"):
        AuthContext("tenant")


def test_app_flow_rejects_username() -> None:
    with pytest.raises(ValueError, match="not used for app flows"):
        AuthContext("tenant", client_id="app", client_secret="s3cret", username=USER)


def test_only_one_credential_kind_is_accepted() -> None:
    with pytest.raises(ValueError, match="Give only one"):
        AuthContext(
            "tenant", client_id="app", client_secret="s3cret", certificate_thumbprint="AB" * 20
        )


def test_pem_pair_must_be_complete() -> None:
    with pytest.raises(ValueError, match="must be given together"):
        AuthContext("tenant", client_id="app", certificate_pem="-----BEGIN CERTIFICATE-----")


def test_broker_is_rejected_for_app_flows() -> None:
    with pytest.raises(ValueError, match="broker is only available"):
        AuthContext("tenant", client_id="app", client_secret="s3cret", broker=True)


def test_construction_makes_no_msal_application(fake_msal: FakeMsal) -> None:
    user_context().for_tenant("customer")
    assert fake_msal.apps == []


def test_repr_does_not_reveal_the_secret() -> None:
    auth = AuthContext("tenant", client_id="app", client_secret="s3cret")
    assert "s3cret" not in repr(auth)
    assert "s3cret" not in repr(auth._credential)


# ---------------------------------------------------------------------------- resolution order


def test_silent_token_is_used_without_prompting(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result("silent")

    token = user_context().get_token(ARM_SCOPE)

    assert token.token == "silent"
    assert fake_msal.methods() == ["silent"]


def test_no_cached_account_goes_interactive_with_login_hint(fake_msal: FakeMsal) -> None:
    info = user_context().acquire_token([ARM_SCOPE])

    assert info.token == "interactive"
    assert fake_msal.methods() == ["interactive"]
    assert fake_msal.calls[0].kwargs["login_hint"] == USER


def test_failed_silent_falls_through_to_interactive(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: error_result("interaction_required")

    user_context().acquire_token([ARM_SCOPE])

    assert fake_msal.methods() == ["silent", "interactive"]


def test_interactive_failure_is_raised_as_auth_error(fake_msal: FakeMsal) -> None:
    fake_msal.interactive = lambda call: error_result("access_denied", "user cancelled")

    with pytest.raises(AuthError, match="access_denied: user cancelled"):
        user_context().acquire_token([ARM_SCOPE])


# ---------------------------------------------------------------------------- consent


def _consent_error() -> Result:
    """Build the MSAL result Entra returns when an app lacks consent for the scopes."""
    return error_result("invalid_grant", "AADSTS65001", error_codes=[65001])


def test_a_failed_sign_in_is_reported_rather_than_retried(fake_msal: FakeMsal) -> None:
    # Entra shows its own consent screen, so nothing here reopens the browser. A retry with
    # prompt=consent used to live here and was removed once live testing showed it could not
    # fire; see the comment in AuthContext._acquire_for_user.
    fake_msal.interactive = lambda call: _consent_error()

    with pytest.raises(ConsentRequired) as caught:
        user_context().acquire_token(["User.Read.All"])

    assert caught.value.scopes == ("User.Read.All",)
    assert fake_msal.methods() == ["interactive"]
    assert "prompt" not in fake_msal.calls[0].kwargs


def test_a_non_consent_failure_is_not_retried(fake_msal: FakeMsal) -> None:
    fake_msal.interactive = lambda call: error_result("access_denied", "user cancelled")

    with pytest.raises(AuthError, match="access_denied"):
        user_context().acquire_token([ARM_SCOPE])

    assert fake_msal.methods() == ["interactive"]


def test_a_bare_access_denied_explains_both_things_it_can_mean(fake_msal: FakeMsal) -> None:
    # What a live tenant returns when a user who may not consent leaves "Need admin approval":
    # no AADSTS code, no description, nothing to tell it apart from pressing Cancel. Measured
    # 2026-09-20. It must not be classified as a consent failure, and it must still be useful.
    fake_msal.interactive = lambda call: error_result("access_denied")

    with pytest.raises(AuthError) as caught:
        user_context().acquire_token(["User.Read.All"])

    assert not isinstance(caught.value, ConsentRequired)
    message = str(caught.value)
    assert "User.Read.All" in message
    assert "partner-tenant" in message
    assert "cancelled" in message
    assert "Need admin approval" in message
    assert fake_msal.methods() == ["interactive"]


def test_a_sibling_reports_missing_consent_without_prompting(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: _consent_error()

    with pytest.raises(ConsentRequired):
        user_context().for_tenant("customer").acquire_token(["User.Read.All"])

    # A sibling has no browser of its own; it reports and stops.
    assert fake_msal.methods() == ["silent"]


# ---------------------------------------------------------------------------- other failures


def test_ambiguous_account_is_rejected(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT, dict(ACCOUNT)]

    with pytest.raises(AccountSelectionRequired):
        user_context().acquire_token([ARM_SCOPE])


def test_signing_in_as_someone_else_is_rejected(fake_msal: FakeMsal) -> None:
    fake_msal.interactive = lambda call: token_result(
        id_token_claims={"preferred_username": "other@partner.com"}
    )

    with pytest.raises(AuthError, match=r"Signed in as 'other@partner\.com'"):
        user_context().acquire_token([ARM_SCOPE])


def test_claims_and_force_refresh_reach_msal(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result()

    user_context().acquire_token([ARM_SCOPE], claims='{"a":1}', force_refresh=True)

    assert fake_msal.calls[0].kwargs["claims_challenge"] == '{"a":1}'
    assert fake_msal.calls[0].kwargs["force_refresh"] is True


def test_scopes_are_required(fake_msal: FakeMsal) -> None:
    with pytest.raises(ValueError, match="At least one scope"):
        user_context().acquire_token([])


# ---------------------------------------------------------------------------- login


def test_login_is_silent_when_a_token_is_cached(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result()

    user_context().login(client_id=GRAPH_CLI_CLIENT_ID, scopes=["User.Read"])

    assert fake_msal.methods() == ["silent"]
    assert fake_msal.apps[0].client_id == GRAPH_CLI_CLIENT_ID


def test_forced_login_always_prompts(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result()

    user_context().login(client_id=GRAPH_CLI_CLIENT_ID, scopes=["User.Read"], force=True)

    assert fake_msal.methods() == ["interactive"]


# ---------------------------------------------------------------------------- client id rule


def test_bare_token_request_uses_azure_powershell(fake_msal: FakeMsal) -> None:
    user_context().get_token(ARM_SCOPE)
    assert fake_msal.apps[0].client_id == AZURE_POWERSHELL_CLIENT_ID


def test_context_client_id_beats_the_default(fake_msal: FakeMsal) -> None:
    user_context(client_id="custom-app").get_token(ARM_SCOPE)
    assert fake_msal.apps[0].client_id == "custom-app"


def test_explicit_client_id_beats_the_context(fake_msal: FakeMsal) -> None:
    user_context(client_id="custom-app").acquire_token([ARM_SCOPE], client_id="per-client")
    assert fake_msal.apps[0].client_id == "per-client"


def test_app_flow_never_falls_back_to_a_first_party_id(fake_msal: FakeMsal) -> None:
    auth = AuthContext("tenant", client_secret="s3cret")
    with pytest.raises(ValueError, match="App flows need a client_id"):
        auth.get_token(ARM_SCOPE)
    assert fake_msal.apps == []


def test_one_msal_application_per_client_id(fake_msal: FakeMsal) -> None:
    auth = user_context()
    auth.acquire_token(["a"], client_id="one")
    auth.acquire_token(["b"], client_id="one")
    auth.acquire_token(["a"], client_id="two")
    assert [app.client_id for app in fake_msal.apps] == ["one", "two"]


# ---------------------------------------------------------------------------- memo


def test_fresh_token_is_reused_without_calling_msal(fake_msal: FakeMsal) -> None:
    auth = user_context()
    first = auth.acquire_token([ARM_SCOPE])
    second = auth.acquire_token([ARM_SCOPE])
    assert first is second
    assert fake_msal.methods() == ["interactive"]


def test_token_close_to_expiry_is_not_reused(fake_msal: FakeMsal) -> None:
    fake_msal.interactive = lambda call: token_result(expires_in=60)
    auth = user_context()
    auth.acquire_token([ARM_SCOPE])
    auth.acquire_token([ARM_SCOPE])
    assert fake_msal.methods() == ["interactive", "interactive"]


# ---------------------------------------------------------------------------- app flows


def test_app_flow_uses_client_credentials(fake_msal: FakeMsal) -> None:
    auth = AuthContext("tenant", client_id="app", client_secret="s3cret")

    token = auth.get_token(ARM_SCOPE)

    assert token.token == "app"
    app = fake_msal.apps[0]
    assert (app.kind, app.client_id, app.client_credential) == ("confidential", "app", "s3cret")
    assert app.authority == "https://login.microsoftonline.com/tenant"
    assert fake_msal.calls[0].scopes == [ARM_SCOPE]


def test_app_flow_force_refresh_purges_cached_tokens(fake_msal: FakeMsal) -> None:
    auth = AuthContext("tenant", client_id="app", client_secret="s3cret")
    auth.acquire_token([ARM_SCOPE], force_refresh=True)
    assert fake_msal.apps[0].removed_tokens == 1


def test_app_flow_error_is_mapped(fake_msal: FakeMsal) -> None:
    fake_msal.for_client = lambda call: error_result("invalid_client", "bad secret")
    auth = AuthContext("tenant", client_id="app", client_secret="s3cret")
    with pytest.raises(AuthError, match="invalid_client: bad secret"):
        auth.get_token(ARM_SCOPE)


def test_rejected_ps256_assertion_is_retried_as_rs256(fake_msal: FakeMsal) -> None:
    results = [error_result("invalid_client", error_codes=[700027]), token_result("rs256")]
    fake_msal.for_client = lambda call: results.pop(0)
    auth = AuthContext("tenant", client_id="app", certificate_thumbprint="AB" * 20)

    token = auth.get_token(ARM_SCOPE)

    assert token.token == "rs256"
    assert isinstance(auth._credential, CertStoreCredential)
    assert auth._credential.algorithm == "RS256"
    assert fake_msal.methods() == ["for_client", "for_client"]


# ---------------------------------------------------------------------------- tenants


def test_sibling_shares_cache_username_and_credentials() -> None:
    auth = user_context(client_id="custom-app")
    sibling = auth.for_tenant("customer")

    assert sibling is auth.for_tenant("CUSTOMER")
    assert sibling is not auth
    assert sibling._cache is auth._cache
    assert (sibling.username, sibling.client_id) == (USER, "custom-app")
    assert sibling.authority == "https://login.microsoftonline.com/customer"
    assert auth.for_tenant("partner-tenant") is auth


def test_sibling_redeems_the_shared_account_silently(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result(call.app.authority)

    token = user_context().for_tenant("customer").get_token(ARM_SCOPE)

    assert token.token == "https://login.microsoftonline.com/customer"
    assert fake_msal.calls[0].kwargs["account"] == ACCOUNT


def test_sibling_never_prompts(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: error_result("interaction_required", "MFA needed")

    with pytest.raises(InteractionRequired, match="Sibling contexts never prompt") as caught:
        user_context().for_tenant("customer").acquire_token([ARM_SCOPE])

    assert caught.value.tenant_id == "customer"
    assert fake_msal.methods() == ["silent"]


def test_sibling_without_an_account_asks_for_a_root_login(fake_msal: FakeMsal) -> None:
    with pytest.raises(InteractionRequired) as caught:
        user_context().for_tenant("customer").acquire_token([ARM_SCOPE])
    assert caught.value.tenant_id == "customer"
    assert fake_msal.methods() == []


def test_sibling_reports_missing_consent(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: error_result(
        "invalid_grant", "AADSTS65001", suberror="consent_required"
    )

    with pytest.raises(ConsentRequired) as caught:
        user_context().for_tenant("customer").acquire_token(["User.Read.All"])

    assert caught.value.tenant_id == "customer"
    assert caught.value.scopes == ("User.Read.All",)


def test_forced_login_on_a_sibling_is_refused(fake_msal: FakeMsal) -> None:
    sibling = user_context().for_tenant("customer")
    with pytest.raises(InteractionRequired):
        sibling.login(client_id="app", scopes=["a"], force=True)
    assert fake_msal.methods() == []


def test_get_token_for_another_tenant_uses_the_sibling(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result(call.app.authority)

    token = user_context().get_token(ARM_SCOPE, tenant_id="vault-tenant", enable_cae=True)

    assert token.token.endswith("/vault-tenant")


def test_get_token_info_honours_options(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result(call.app.authority)

    info = user_context().get_token_info(
        ARM_SCOPE, options={"tenant_id": "vault-tenant", "claims": "{}", "enable_cae": True}
    )

    assert info.token.endswith("/vault-tenant")
    assert info.token_type == "Bearer"
    assert fake_msal.calls[0].kwargs["claims_challenge"] == "{}"


def test_app_flow_sibling_gets_its_own_assertion_audience(fake_msal: FakeMsal) -> None:
    auth = AuthContext("home", client_id="app", certificate_thumbprint="AB" * 20)
    seen: list[str] = []

    def record(client_id: str, token_endpoint: str) -> str:
        seen.append(token_endpoint)
        return "assertion"

    assert isinstance(auth._credential, CertStoreCredential)
    auth._credential.build_assertion = record  # type: ignore[method-assign]

    auth.get_token(ARM_SCOPE)
    auth.for_tenant("customer").get_token(ARM_SCOPE)
    for app in fake_msal.apps:
        app.client_credential["client_assertion"]()

    assert seen == [
        "https://login.microsoftonline.com/home/oauth2/v2.0/token",
        "https://login.microsoftonline.com/customer/oauth2/v2.0/token",
    ]


# ---------------------------------------------------------------------------- single-flight


def test_concurrent_cold_start_prompts_once(fake_msal: FakeMsal) -> None:
    def slow_interactive(call: Call) -> Result:
        time.sleep(0.05)
        return token_result("once")

    fake_msal.interactive = slow_interactive
    auth = user_context()
    tokens: list[str] = []

    def worker() -> None:
        tokens.append(auth.acquire_token([ARM_SCOPE]).token)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert tokens == ["once"] * 12
    assert fake_msal.methods() == ["interactive"]


# ---------------------------------------------------------------------------- broker


@pytest.fixture
def broker_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("azure_auth.auth.context._broker_installed", lambda: True)


def test_broker_is_used_when_available(fake_msal: FakeMsal, broker_installed: None) -> None:
    user_context(broker=True).acquire_token([ARM_SCOPE])

    call = fake_msal.calls[0]
    assert call.app.broker is True
    assert call.kwargs["parent_window_handle"] is call.app.CONSOLE_WINDOW_HANDLE


def test_broker_failure_falls_back_to_the_browser(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    def interactive(call: Call) -> Result:
        if call.app.broker:
            raise RuntimeError("WAM exploded")
        return token_result("browser")

    fake_msal.interactive = interactive

    assert user_context(broker=True).acquire_token([ARM_SCOPE]).token == "browser"
    assert [call.app.broker for call in fake_msal.calls] == [True, False]


def test_broker_error_result_falls_back_to_the_browser(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    fake_msal.interactive = lambda call: (
        error_result("broker_error") if call.app.broker else token_result("browser")
    )
    assert user_context(broker=True).acquire_token([ARM_SCOPE]).token == "browser"


def test_user_cancelling_in_the_broker_does_not_open_a_browser(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    fake_msal.interactive = lambda call: error_result("user_cancelled")
    with pytest.raises(AuthError, match="user_cancelled"):
        user_context(broker=True).acquire_token([ARM_SCOPE])
    assert len(fake_msal.calls) == 1


def test_broker_failure_without_fallback_raises(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    def interactive(call: Call) -> Result:
        raise RuntimeError("WAM exploded")

    fake_msal.interactive = interactive
    with pytest.raises(BrokerUnavailable, match="WAM exploded"):
        user_context(broker=True, broker_fallback=False).acquire_token([ARM_SCOPE])


def test_missing_broker_package_falls_back(
    fake_msal: FakeMsal, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("azure_auth.auth.context._broker_installed", lambda: False)

    user_context(broker=True).acquire_token([ARM_SCOPE])

    assert fake_msal.calls[0].app.broker is False


def test_missing_broker_package_without_fallback_raises(
    fake_msal: FakeMsal, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("azure_auth.auth.context._broker_installed", lambda: False)
    with pytest.raises(BrokerUnavailable, match="broker"):
        user_context(broker=True, broker_fallback=False).acquire_token([ARM_SCOPE])


# ---------------------------------------------------------------------------- async view


@pytest.mark.anyio
async def test_async_view_acquires_in_a_worker_thread(fake_msal: FakeMsal) -> None:
    thread_names: list[str] = []

    def interactive(call: Call) -> Result:
        thread_names.append(threading.current_thread().name)
        return token_result("async")

    fake_msal.interactive = interactive
    auth = user_context()

    async with auth.aio as credential:
        token = await credential.get_token(ARM_SCOPE)
        info = await credential.get_token_info(ARM_SCOPE)

    assert (token.token, info.token) == ("async", "async")
    assert thread_names != [threading.main_thread().name]
    assert len(thread_names) == 1
    assert auth.aio is credential
    assert credential.sync is auth


@pytest.mark.anyio
async def test_async_view_serves_other_tenants_and_login(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result(call.app.authority)
    auth = user_context()

    await auth.aio.login(client_id="app", scopes=["a"])
    token = await auth.aio.get_token(ARM_SCOPE, tenant_id="customer")
    info = await auth.aio.for_tenant("customer").get_token_info(ARM_SCOPE)

    assert token.token.endswith("/customer")
    assert info.token == token.token
