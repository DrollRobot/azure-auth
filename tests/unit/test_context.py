"""Unit tests for AuthContext: flows, precedence, tenants, single-flight."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest
from msal import BrowserInteractionTimeoutError

from azure_auth import (
    AccountSelectionRequired,
    AmbiguousTenant,
    AuthContext,
    AuthError,
    BrokerUnavailable,
    ConsentRequired,
    InteractionRequired,
    TenantNotFound,
)
from azure_auth.auth.credentials import CertStoreCredential
from azure_auth.clouds import CHINA, COMMERCIAL, US_GOV, US_GOV_DOD, TenantInfo
from azure_auth.constants import AZURE_POWERSHELL_CLIENT_ID, GRAPH_CLI_CLIENT_ID
from tests.fakes import (
    Call,
    FakeDiscovery,
    FakeMsal,
    Result,
    error_result,
    tenant_guid,
    token_result,
)

pytestmark = pytest.mark.unit

USER = "admin@partner.com"
# The home tenant by domain name, and a customer tenant, with the GUIDs the fake lookup gives
# them: every context holds its tenant as the GUID, whatever it was given.
TENANT = "partner-tenant"
TENANT_GUID = tenant_guid(TENANT)
CUSTOMER = "customer"
CUSTOMER_GUID = tenant_guid(CUSTOMER)
ARM_SCOPE = "https://management.azure.com/.default"
ACCOUNT = {"username": USER, "home_account_id": "uid.utid"}


def user_context(**kwargs: Any) -> AuthContext:
    return AuthContext(TENANT, username=USER, **kwargs)


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


def test_browser_sign_in_is_given_a_timeout(fake_msal: FakeMsal) -> None:
    # A closed browser window would otherwise leave MSAL waiting for ever.
    user_context().acquire_token([ARM_SCOPE])

    assert fake_msal.methods() == ["interactive"]
    assert fake_msal.calls[0].kwargs["timeout"] == 120


def test_the_browser_timeout_can_be_set(fake_msal: FakeMsal) -> None:
    user_context(interactive_timeout=5).acquire_token([ARM_SCOPE])

    assert fake_msal.calls[0].kwargs["timeout"] == 5


def test_an_unanswered_browser_sign_in_is_reported_not_hung(fake_msal: FakeMsal) -> None:
    def time_out(call: Call) -> Result:
        raise BrowserInteractionTimeoutError("User did not complete the flow in time")

    fake_msal.interactive = time_out

    with pytest.raises(AuthError, match="not completed within 120 seconds") as caught:
        user_context().acquire_token([ARM_SCOPE])

    # A timeout is neither a missing sign-in nor missing consent; nothing should retry it.
    assert not isinstance(caught.value, (InteractionRequired, ConsentRequired))


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
    assert fake_msal.calls[0].kwargs["prompt"] is None


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
    # A still signed-in browser would otherwise complete the page with nobody choosing.
    assert fake_msal.calls[0].kwargs["prompt"] == "select_account"


def test_a_sign_in_that_is_not_forced_shows_no_account_picker(fake_msal: FakeMsal) -> None:
    user_context().acquire_token([ARM_SCOPE])

    assert fake_msal.methods() == ["interactive"]
    assert fake_msal.calls[0].kwargs["prompt"] is None


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
    assert app.authority == f"https://login.microsoftonline.com/{tenant_guid('tenant')}"
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


@pytest.mark.regression
def test_rejected_certificate_assertion_is_not_retried(fake_msal: FakeMsal) -> None:
    # AADSTS700027 also means "the key was not found" on the application. Retrying it as
    # RS256 logged a false reason and left the credential on RS256 for the whole process.
    fake_msal.for_client = lambda call: error_result("invalid_client", error_codes=[700027])
    auth = AuthContext("tenant", client_id="app", certificate_thumbprint="AB" * 20)

    with pytest.raises(AuthError, match="invalid_client"):
        auth.get_token(ARM_SCOPE)

    assert isinstance(auth._credential, CertStoreCredential)
    assert auth._credential.algorithm == "PS256"
    assert fake_msal.methods() == ["for_client"]


# ---------------------------------------------------------------------------- tenants


def test_sibling_shares_cache_username_and_credentials() -> None:
    auth = user_context(client_id="custom-app")
    sibling = auth.for_tenant("customer")

    assert sibling is auth.for_tenant("CUSTOMER")
    assert sibling is not auth
    assert sibling._cache is auth._cache
    assert (sibling.username, sibling.client_id) == (USER, "custom-app")
    assert sibling.authority == f"https://login.microsoftonline.com/{CUSTOMER_GUID}"
    assert auth.for_tenant("partner-tenant") is auth


def test_sibling_redeems_the_shared_account_silently(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result(call.app.authority)

    token = user_context().for_tenant("customer").get_token(ARM_SCOPE)

    assert token.token == f"https://login.microsoftonline.com/{CUSTOMER_GUID}"
    assert fake_msal.calls[0].kwargs["account"] == ACCOUNT


def test_sibling_never_prompts(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: error_result("interaction_required", "MFA needed")

    with pytest.raises(InteractionRequired, match="Sibling contexts never prompt") as caught:
        user_context().for_tenant("customer").acquire_token([ARM_SCOPE])

    assert caught.value.tenant_id == CUSTOMER_GUID
    assert fake_msal.methods() == ["silent"]


def test_sibling_without_an_account_asks_for_a_root_login(fake_msal: FakeMsal) -> None:
    with pytest.raises(InteractionRequired) as caught:
        user_context().for_tenant("customer").acquire_token([ARM_SCOPE])
    assert caught.value.tenant_id == CUSTOMER_GUID
    assert fake_msal.methods() == []


def test_sibling_reports_missing_consent(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: error_result(
        "invalid_grant", "AADSTS65001", suberror="consent_required"
    )

    with pytest.raises(ConsentRequired) as caught:
        user_context().for_tenant("customer").acquire_token(["User.Read.All"])

    assert caught.value.tenant_id == CUSTOMER_GUID
    assert caught.value.scopes == ("User.Read.All",)


def test_forced_login_on_a_sibling_is_refused(fake_msal: FakeMsal) -> None:
    sibling = user_context().for_tenant("customer")
    with pytest.raises(InteractionRequired):
        sibling.login(client_id="app", scopes=["a"], force=True)
    assert fake_msal.methods() == []


def test_get_token_for_another_tenant_uses_the_sibling(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result(call.app.authority)

    token = user_context().get_token(ARM_SCOPE, tenant_id=CUSTOMER_GUID, enable_cae=True)

    assert token.token.endswith(f"/{CUSTOMER_GUID}")


def test_get_token_info_honours_options(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result(call.app.authority)

    info = user_context().get_token_info(
        ARM_SCOPE, options={"tenant_id": CUSTOMER_GUID, "claims": "{}", "enable_cae": True}
    )

    assert info.token.endswith(f"/{CUSTOMER_GUID}")
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
        f"https://login.microsoftonline.com/{tenant_guid('home')}/oauth2/v2.0/token",
        f"https://login.microsoftonline.com/{CUSTOMER_GUID}/oauth2/v2.0/token",
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
    # What MSAL makes of a cancel: the same error as any broker failure, told apart only by
    # the status in the description.
    fake_msal.interactive = lambda call: error_result(
        "broker_error",
        "User canceled the Accounts Control Operation.. "
        "Status: Response_Status.Status_UserCanceled, Error code: 0, Tag: 528315210",
    )
    with pytest.raises(AuthError, match="Status_UserCanceled"):
        user_context(broker=True).acquire_token([ARM_SCOPE])
    assert len(fake_msal.calls) == 1


def test_a_sibling_the_broker_cannot_serve_silently_asks_for_a_sign_in(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    # What MSAL returned live when the broker held no sign-in for the application.
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: error_result(
        "broker_error",
        "(pii). Status: Response_Status.Status_InteractionRequired, Error code: 3399614476, "
        "Tag: 557973645",
    )
    with pytest.raises(InteractionRequired, match="Sibling contexts never prompt") as caught:
        user_context(broker=True).for_tenant("customer").acquire_token([ARM_SCOPE])
    assert caught.value.tenant_id == CUSTOMER_GUID
    assert fake_msal.methods() == ["silent"]


def test_a_forced_broker_sign_in_shows_the_account_picker(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result()

    user_context(broker=True).login(client_id="app", scopes=["a"], force=True)

    # Without it the broker answers silently for an account it holds, and force does nothing.
    call = fake_msal.calls[0]
    assert (call.method, call.app.broker, call.kwargs["prompt"]) == (
        "interactive",
        True,
        "select_account",
    )


def test_signing_in_as_someone_else_through_the_broker_is_rejected(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    fake_msal.interactive = lambda call: token_result(
        id_token_claims={"preferred_username": "other@partner.com"}
    )

    with pytest.raises(AuthError, match=r"Signed in as 'other@partner\.com'"):
        user_context(broker=True).acquire_token([ARM_SCOPE])
    assert [call.app.broker for call in fake_msal.calls] == [True]


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

    assert token.token.endswith(f"/{CUSTOMER_GUID}")
    assert info.token == token.token


# ---------------------------------------------------------------------------- clouds


def test_the_cloud_is_looked_up_when_the_context_is_created(
    fake_discovery: FakeDiscovery, fake_msal: FakeMsal
) -> None:
    fake_discovery.cloud = US_GOV_DOD
    auth = user_context()

    assert fake_discovery.tenants == [TENANT]
    assert auth.cloud is US_GOV_DOD
    assert "cloud='USGovDoD'" in repr(auth)
    auth.acquire_token([ARM_SCOPE])
    assert fake_msal.apps[0].authority == f"https://login.microsoftonline.us/{TENANT_GUID}"
    # Once is enough: token requests do not look again.
    assert fake_discovery.tenants == [TENANT]


def test_a_given_cloud_with_the_guid_is_taken_as_given_without_a_lookup(
    fake_discovery: FakeDiscovery, fake_msal: FakeMsal
) -> None:
    fake_discovery.cloud = US_GOV_DOD
    auth = AuthContext(TENANT_GUID.upper(), username=USER, cloud="usgov")

    auth.acquire_token([ARM_SCOPE])

    assert auth.cloud is US_GOV
    assert auth.tenant is None
    # The GUID is held in its one spelling, so no two spellings make two tenants.
    assert (auth.tenant_id, auth.tenant_name) == (TENANT_GUID, TENANT_GUID.upper())
    assert AuthContext(TENANT_GUID, username=USER, cloud=COMMERCIAL).cloud is COMMERCIAL
    assert fake_msal.apps[0].authority == f"https://login.microsoftonline.us/{TENANT_GUID}"
    assert fake_discovery.tenants == []


def test_a_given_cloud_with_a_domain_name_still_looks_the_guid_up(
    fake_discovery: FakeDiscovery, fake_msal: FakeMsal
) -> None:
    fake_discovery.cloud = US_GOV_DOD
    auth = user_context(cloud="usgov")

    auth.acquire_token([ARM_SCOPE])

    # The name is looked up for its GUID; the cloud stays as given, not as found.
    assert fake_discovery.tenants == [TENANT]
    assert (auth.tenant_id, auth.tenant_name) == (TENANT_GUID, TENANT)
    assert auth.cloud is US_GOV
    assert auth.tenant is not None
    assert auth.tenant.cloud is US_GOV_DOD
    assert fake_msal.apps[0].authority == f"https://login.microsoftonline.us/{TENANT_GUID}"


# A name verified in a commercial and a China tenant, as the lookup reports it.
COMMERCIAL_TWIN = tenant_guid("twin-commercial")
CHINA_TWIN = tenant_guid("twin-china")
TWINS = AmbiguousTenant(
    "a tenant in each cloud",
    tenant=TENANT,
    candidates=[TenantInfo(COMMERCIAL_TWIN, COMMERCIAL), TenantInfo(CHINA_TWIN, CHINA)],
)


def test_a_given_cloud_settles_a_name_that_is_a_tenant_in_two_clouds(
    fake_discovery: FakeDiscovery,
) -> None:
    fake_discovery.error = TWINS

    china = user_context(cloud=CHINA)
    commercial = user_context(cloud="Commercial")

    assert (china.tenant_id, china.tenant_name, china.cloud) == (CHINA_TWIN, TENANT, CHINA)
    assert china.tenant is TWINS.candidates[1]
    assert commercial.tenant_id == COMMERCIAL_TWIN
    with pytest.raises(AmbiguousTenant):
        user_context()
    # Neither tenant is in the US government cloud, so naming it settles nothing.
    with pytest.raises(AmbiguousTenant):
        user_context(cloud=US_GOV)


def test_a_sibling_named_by_an_ambiguous_name_takes_the_one_in_the_parents_cloud(
    fake_discovery: FakeDiscovery,
) -> None:
    auth = AuthContext(TENANT_GUID, username=USER, cloud=CHINA)
    fake_discovery.error = TWINS

    sibling = auth.for_tenant(CUSTOMER)

    assert (sibling.tenant_id, sibling.tenant_name, sibling.cloud) == (CHINA_TWIN, CUSTOMER, CHINA)


def test_a_domain_name_is_held_as_the_guid_the_lookup_found(
    fake_discovery: FakeDiscovery,
) -> None:
    fake_discovery.region_sub_scope = "GCC"
    auth = user_context()

    assert (auth.tenant_id, auth.tenant_name) == (TENANT_GUID, TENANT)
    assert auth.authority == f"https://login.microsoftonline.com/{TENANT_GUID}"
    assert auth.tenant is not None
    assert (auth.tenant.tenant_id, auth.tenant.region_sub_scope) == (TENANT_GUID, "GCC")
    assert auth.cloud is auth.tenant.cloud
    assert repr(auth) == (
        f"AuthContext(tenant_id={TENANT_GUID!r}, tenant_name={TENANT!r}, cloud='Commercial', "
        "flow='user')"
    )


def test_a_looked_up_tenant_is_taken_as_found(fake_discovery: FakeDiscovery) -> None:
    info = TenantInfo(TENANT_GUID, US_GOV, region_sub_scope="DODCON")

    auth = AuthContext(info, username=USER)
    app = AuthContext(info, client_id="app", client_secret="s3cret")

    assert auth.tenant is info
    assert app.tenant is info
    assert (auth.tenant_id, auth.tenant_name, auth.cloud) == (TENANT_GUID, TENANT_GUID, US_GOV)
    assert repr(auth) == f"AuthContext(tenant_id={TENANT_GUID!r}, cloud='USGov', flow='user')"
    assert fake_discovery.tenants == []
    with pytest.raises(ValueError, match="cloud is not used"):
        AuthContext(info, username=USER, cloud=US_GOV)


def test_the_tenant_name_is_what_messages_say_and_the_guid_what_errors_carry(
    fake_msal: FakeMsal,
) -> None:
    with pytest.raises(InteractionRequired) as caught:
        user_context().for_tenant(CUSTOMER).acquire_token([ARM_SCOPE])

    assert caught.value.tenant_id == CUSTOMER_GUID
    assert f"tenant {CUSTOMER};" in str(caught.value)
    assert CUSTOMER_GUID not in str(caught.value)


def test_a_request_for_the_contexts_own_tenant_by_guid_may_prompt(fake_msal: FakeMsal) -> None:
    # Key Vault and the other Azure SDK clients name the tenant of a request by GUID, which
    # must come back to the context itself, and so may sign the person in, not to a sibling
    # that never can. Seen with a context built from a domain name (2026-09-29).
    auth = user_context()

    token = auth.get_token(ARM_SCOPE, tenant_id=TENANT_GUID)

    assert auth.for_tenant(TENANT_GUID) is auth
    assert auth.for_tenant(TENANT.upper()) is auth
    assert token.token
    assert fake_msal.methods() == ["interactive"]


def test_an_unknown_cloud_name_is_refused(fake_discovery: FakeDiscovery) -> None:
    with pytest.raises(ValueError, match="Unknown cloud"):
        user_context(cloud="Germany")
    assert fake_discovery.tenants == []


def test_a_failed_lookup_fails_the_constructor(fake_discovery: FakeDiscovery) -> None:
    fake_discovery.error = TenantNotFound("no such tenant", tenant=TENANT)
    with pytest.raises(TenantNotFound):
        user_context()


def test_bad_arguments_are_refused_before_any_lookup(fake_discovery: FakeDiscovery) -> None:
    with pytest.raises(ValueError, match="username is required"):
        AuthContext("tenant")
    with pytest.raises(ValueError, match="username is not used"):
        AuthContext("tenant", client_id="app", client_secret="s3cret", username=USER)
    assert fake_discovery.tenants == []


@pytest.mark.parametrize("tenant", ["common", "organizations", "Consumers"])
def test_a_multi_tenant_authority_needs_its_cloud_named(
    fake_discovery: FakeDiscovery, tenant: str
) -> None:
    with pytest.raises(ValueError, match="pass cloud="):
        AuthContext(tenant, username=USER)
    assert AuthContext(tenant, username=USER, cloud=COMMERCIAL).cloud is COMMERCIAL
    assert fake_discovery.tenants == []


def test_a_sibling_shares_the_cloud_without_a_lookup(
    fake_discovery: FakeDiscovery, fake_msal: FakeMsal
) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result(call.app.authority)
    fake_discovery.cloud = US_GOV
    auth = user_context()

    token = auth.get_token(ARM_SCOPE, tenant_id=CUSTOMER_GUID)

    sibling = auth.for_tenant(CUSTOMER_GUID)
    assert (sibling.cloud, sibling.tenant, sibling.tenant_name) == (US_GOV, None, CUSTOMER_GUID)
    assert token.token == f"https://login.microsoftonline.us/{CUSTOMER_GUID}"
    assert fake_discovery.tenants == [TENANT]


def test_a_sibling_named_by_domain_is_looked_up_once_and_keeps_the_parents_cloud(
    fake_discovery: FakeDiscovery,
) -> None:
    fake_discovery.cloud = US_GOV
    auth = user_context()
    fake_discovery.cloud = CHINA

    sibling = auth.for_tenant(CUSTOMER)

    assert sibling is auth.for_tenant(CUSTOMER.upper()) is auth.for_tenant(CUSTOMER_GUID)
    assert fake_discovery.tenants == [TENANT, CUSTOMER]
    assert (sibling.tenant_id, sibling.tenant_name, sibling.cloud) == (
        CUSTOMER_GUID,
        CUSTOMER,
        US_GOV,
    )
    # What the lookup found is kept, though a customer tenant is always in the parent's cloud.
    assert sibling.tenant is not None
    assert sibling.tenant.cloud is CHINA


def test_a_sibling_first_made_by_guid_learns_its_name_later(
    fake_discovery: FakeDiscovery,
) -> None:
    auth = user_context()

    by_guid = auth.for_tenant(CUSTOMER_GUID)
    assert (by_guid.tenant, by_guid.tenant_name) == (None, CUSTOMER_GUID)

    assert auth.for_tenant(CUSTOMER) is by_guid
    assert by_guid.tenant is not None
    assert by_guid.tenant.tenant_id == CUSTOMER_GUID
    assert by_guid.tenant_name == CUSTOMER
