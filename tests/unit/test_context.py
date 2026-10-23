"""Unit tests for AuthContext: flows, precedence, tenants, single-flight."""

from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
import webbrowser
from pathlib import Path
from typing import Any

import msal_extensions
import pytest
from msal import BrowserInteractionTimeoutError, TokenCache

from azure_auth import (
    AccountSelectionRequired,
    AuthContext,
    AuthError,
    BrokerUnavailable,
    ConsentRequired,
    InteractionRequired,
    Tenant,
    TenantNotFound,
)
from azure_auth.auth.credentials import CertStoreCredential
from azure_auth.clouds import COMMERCIAL, US_GOV, US_GOV_DOD
from azure_auth.constants import AZURE_POWERSHELL_CLIENT_ID, GRAPH_CLI_CLIENT_ID
from tests.fakes import (
    Call,
    FakeLookup,
    FakeMsal,
    FakeReceiver,
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
    user_context().get_tenant_context("customer")
    assert fake_msal.apps == []


def test_repr_does_not_reveal_the_secret() -> None:
    auth = AuthContext("tenant", client_id="app", client_secret="s3cret")
    assert "s3cret" not in repr(auth)
    assert "s3cret" not in repr(auth._app_credential)


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
    user_context(browser_timeout=5).acquire_token([ARM_SCOPE])

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


def test_a_customer_reports_missing_consent_without_prompting(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: _consent_error()

    with pytest.raises(ConsentRequired):
        user_context().get_tenant_context("customer").acquire_token(["User.Read.All"])

    # A context from get_tenant_context() has no browser of its own; it reports and stops.
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

    user_context().login(client_id=GRAPH_CLI_CLIENT_ID, scopes=["User.Read"], pick_account=True)

    assert fake_msal.methods() == ["interactive"]
    # A still signed-in browser would otherwise complete the page with nobody choosing.
    assert fake_msal.calls[0].kwargs["prompt"] == "select_account"


def test_reauthenticating_always_asks_for_the_password_again(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result()

    user_context().login(client_id=GRAPH_CLI_CLIENT_ID, scopes=["User.Read"], reauthenticate=True)

    assert fake_msal.methods() == ["interactive"]
    # A still signed-in browser would otherwise finish the page with the old sign-in's time.
    assert fake_msal.calls[0].kwargs["prompt"] == "login"


def test_pick_account_and_reauthenticate_cannot_both_be_set(fake_msal: FakeMsal) -> None:
    with pytest.raises(ValueError, match="cannot both be set"):
        user_context().login(client_id="app", scopes=["a"], pick_account=True, reauthenticate=True)

    assert fake_msal.calls == []


def test_a_customer_context_never_prompts_even_to_reauthenticate(fake_msal: FakeMsal) -> None:
    customer = user_context().get_tenant_context("customer")

    with pytest.raises(InteractionRequired):
        customer.login(client_id="app", scopes=["a"], reauthenticate=True)

    assert "interactive" not in fake_msal.methods()


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


def test_every_application_declares_continuous_access_evaluation(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    user_context().acquire_token([ARM_SCOPE])
    user_context(broker=True).acquire_token([ARM_SCOPE])
    AuthContext("tenant", client_id="app", client_secret="s3cret").acquire_token([ARM_SCOPE])

    kinds = [(app.kind, app.broker) for app in fake_msal.apps]
    assert kinds == [("public", False), ("public", True), ("confidential", False)]
    assert [app.capabilities for app in fake_msal.apps] == [["CP1"]] * 3


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

    assert isinstance(auth._app_credential, CertStoreCredential)
    assert auth._app_credential.algorithm == "PS256"
    assert fake_msal.methods() == ["for_client"]


# ---------------------------------------------------------------------------- tenants


def test_get_tenant_shares_cache_username_and_credentials() -> None:
    home = user_context(client_id="custom-app")
    customer = home.get_tenant_context("customer")

    assert customer is home.get_tenant_context("CUSTOMER")
    assert customer is not home
    assert customer._cache is home._cache
    assert (customer.username, customer.client_id) == (USER, "custom-app")
    assert customer.authority == f"https://login.microsoftonline.com/{CUSTOMER_GUID}"
    assert home.get_tenant_context("partner-tenant") is home


def test_a_directly_built_context_is_its_own_home() -> None:
    auth = user_context()

    assert auth.home is auth
    assert auth.aio.home is auth.aio


def test_get_tenant_points_home_at_the_original_context() -> None:
    home = user_context()
    customer = home.get_tenant_context("customer")

    assert customer.home is home
    assert customer.aio.home is home.aio
    assert home.aio.get_tenant_context("customer") is customer.aio


def test_a_context_from_a_customer_context_keeps_the_original_home() -> None:
    home = user_context()

    other = home.get_tenant_context("customer").get_tenant_context("other-customer")

    assert other.home is home


def test_get_tenant_redeems_the_shared_account_silently(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result(call.app.authority)

    token = user_context().get_tenant_context("customer").get_token(ARM_SCOPE)

    assert token.token == f"https://login.microsoftonline.com/{CUSTOMER_GUID}"
    assert fake_msal.calls[0].kwargs["account"] == ACCOUNT


def test_a_customer_hands_msal_the_account_as_its_home_tenant_entry_describes_it(
    fake_msal: FakeMsal, monkeypatch: pytest.MonkeyPatch
) -> None:
    # MSAL describes an account by its entry saved last, which through the broker can be a
    # customer tenant's, under a placeholder username (tests/integration/test_account_lookup.py).
    home = {
        "home_account_id": "uid.utid",
        "environment": "login.microsoftonline.com",
        "realm": "utid",
        "local_account_id": "uid",
        "username": USER,
        "account_source": "broker",
        "authority_type": "MSSTS",
    }
    cache = TokenCache()
    cache.modify(TokenCache.CredentialType.ACCOUNT, home, home)
    monkeypatch.setattr("azure_auth.auth.context.build_cache", lambda *args: cache)
    fake_msal.accounts = [
        home
        | {
            "realm": CUSTOMER_GUID,
            "local_account_id": f"uid.utid.{CUSTOMER_GUID}",
            "username": "user_uid@partner.com",
        }
    ]
    fake_msal.silent = lambda call: token_result()

    user_context().get_tenant_context("customer").acquire_token([ARM_SCOPE])

    assert fake_msal.calls[0].kwargs["account"] == home


def test_get_tenant_never_prompts(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: error_result("interaction_required", "MFA needed")

    with pytest.raises(
        InteractionRequired, match=r"from get_tenant_context\(\) never prompt"
    ) as caught:
        user_context().get_tenant_context("customer").acquire_token([ARM_SCOPE])

    assert "client of the home context (auth.home)" in str(caught.value)
    assert caught.value.tenant_id == CUSTOMER_GUID
    assert fake_msal.methods() == ["silent"]


def test_get_tenant_without_an_account_asks_for_a_home_login(fake_msal: FakeMsal) -> None:
    with pytest.raises(InteractionRequired) as caught:
        user_context().get_tenant_context("customer").acquire_token([ARM_SCOPE])
    assert caught.value.tenant_id == CUSTOMER_GUID
    assert "client of the home context (auth.home)" in str(caught.value)
    assert fake_msal.methods() == []


def test_a_customer_reports_missing_consent(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: error_result(
        "invalid_grant", "AADSTS65001", suberror="consent_required"
    )

    with pytest.raises(ConsentRequired) as caught:
        user_context().get_tenant_context("customer").acquire_token(["User.Read.All"])

    assert caught.value.tenant_id == CUSTOMER_GUID
    assert caught.value.scopes == ("User.Read.All",)


def test_forced_login_on_a_get_tenant_context_is_refused(fake_msal: FakeMsal) -> None:
    customer = user_context().get_tenant_context("customer")
    with pytest.raises(InteractionRequired):
        customer.login(client_id="app", scopes=["a"], pick_account=True)
    assert fake_msal.methods() == []


def test_get_token_for_another_tenant_uses_get_tenant_context(fake_msal: FakeMsal) -> None:
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


def test_app_flow_get_tenant_gets_its_own_assertion_audience(fake_msal: FakeMsal) -> None:
    auth = AuthContext("home", client_id="app", certificate_thumbprint="AB" * 20)
    seen: list[str] = []

    def record(client_id: str, token_endpoint: str) -> str:
        seen.append(token_endpoint)
        return "assertion"

    assert isinstance(auth._app_credential, CertStoreCredential)
    auth._app_credential.build_assertion = record  # type: ignore[method-assign]

    auth.get_token(ARM_SCOPE)
    auth.get_tenant_context("customer").get_token(ARM_SCOPE)
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


def test_a_customer_the_broker_cannot_serve_silently_asks_for_a_sign_in(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    # What MSAL returned live when the broker held no sign-in for the application.
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: error_result(
        "broker_error",
        "(pii). Status: Response_Status.Status_InteractionRequired, Error code: 3399614476, "
        "Tag: 557973645",
    )
    with pytest.raises(
        InteractionRequired, match=r"from get_tenant_context\(\) never prompt"
    ) as caught:
        user_context(broker=True).get_tenant_context("customer").acquire_token([ARM_SCOPE])
    assert caught.value.tenant_id == CUSTOMER_GUID
    assert fake_msal.methods() == ["silent"]
    # The advice is added to the broker's answer, which stays in the fields.
    assert caught.value.error == "broker_error"


def test_broker_applications_turn_on_the_brokers_pii_logging(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    fake_msal.interactive = lambda call: (
        error_result("broker_error") if call.app.broker else token_result("browser")
    )

    user_context(broker=True).acquire_token([ARM_SCOPE])

    # Without it the broker hides Entra's reason for every failure.
    assert [(app.broker, app.pii_log) for app in fake_msal.apps] == [(True, True), (False, False)]


# A broker failure in the shape MSAL gives it with PII logging on (measured 2026-10-17 for
# AADSTS65001), here for Conditional Access, and a browser failure Entra gave a code for.
ENTRA_REFUSALS = [
    pytest.param(
        True,
        error_result(
            "broker_error",
            "SubError: message_only V2Error: invalid_grant AADSTS53003: Access has been blocked "
            "by Conditional Access policies. Status: Response_Status.Status_InteractionRequired, "
            "Error code: 3399614476, Tag: 557973645",
        ),
        "AADSTS53003: Access has been blocked by Conditional Access policies "
        "(broker: Status_InteractionRequired, SubError: message_only)",
        {53003},
        id="broker",
    ),
    pytest.param(
        False,
        error_result(
            "invalid_grant", "AADSTS50105: The user is not assigned.", error_codes=[50105]
        ),
        "invalid_grant: AADSTS50105: The user is not assigned.",
        {50105},
        id="browser",
    ),
]


@pytest.mark.parametrize(("broker", "result", "message", "codes"), ENTRA_REFUSALS)
def test_a_customer_entra_refused_for_a_reason_gives_only_the_reason(
    fake_msal: FakeMsal,
    broker_installed: None,
    broker: bool,
    result: Result,
    message: str,
    codes: set[int],
) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: result

    with pytest.raises(InteractionRequired) as caught:
        user_context(broker=broker).get_tenant_context("customer").acquire_token([ARM_SCOPE])

    # A home sign-in would not change Entra's answer, so the message does not suggest one.
    assert str(caught.value) == message
    assert caught.value.tenant_id == CUSTOMER_GUID
    # The caller can tell one reason from another without reading the message.
    assert caught.value.error_codes == codes


def test_a_customer_missing_consent_through_the_broker_is_consent_required(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: error_result(
        "broker_error",
        "SubError: consent_required V2Error: invalid_grant AADSTS65001: The user or "
        "administrator has not consented to use the application. "
        "Status: Response_Status.Status_InteractionRequired, Error code: 3399614476, "
        "Tag: 557973645",
    )

    with pytest.raises(ConsentRequired, match=r"^AADSTS65001: ") as caught:
        user_context(broker=True).get_tenant_context("customer").acquire_token(["User.Read.All"])

    assert caught.value.tenant_id == CUSTOMER_GUID
    assert "login()" not in str(caught.value)


def test_a_forced_broker_sign_in_shows_the_account_picker(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result()

    user_context(broker=True).login(client_id="app", scopes=["a"], pick_account=True)

    # Without it the broker answers silently for an account it holds, and force does nothing.
    call = fake_msal.calls[0]
    assert (call.method, call.app.broker, call.kwargs["prompt"]) == (
        "interactive",
        True,
        "select_account",
    )


def test_reauthenticating_with_the_broker_signs_in_in_the_browser(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result()

    user_context(broker=True).login(client_id="app", scopes=["a"], reauthenticate=True)

    # The broker cannot be told to ask again, and would answer for the account it holds.
    assert [(c.method, c.app.broker, c.kwargs["prompt"]) for c in fake_msal.calls] == [
        ("interactive", False, "login")
    ]


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
    info = await auth.aio.get_tenant_context("customer").get_token_info(ARM_SCOPE)

    assert token.token.endswith(f"/{CUSTOMER_GUID}")
    assert info.token == token.token


# ---------------------------------------------------------------------------- the tenant


def test_a_string_is_looked_up_when_the_context_is_created(
    fake_lookup: FakeLookup, fake_msal: FakeMsal
) -> None:
    fake_lookup.cloud = US_GOV_DOD
    fake_lookup.region_sub_scope = "DOD"
    auth = user_context()

    assert fake_lookup.calls == [(TENANT, None)]
    assert (auth.tenant.id, auth.tenant.cloud, auth.tenant.domain) == (
        TENANT_GUID,
        US_GOV_DOD,
        TENANT,
    )
    assert auth.tenant.region_sub_scope == "DOD"
    assert repr(auth) == (
        f"AuthContext(tenant=Tenant(id={TENANT_GUID!r}, cloud='USGovDoD', domain={TENANT!r}), "
        "flow='user')"
    )
    auth.acquire_token([ARM_SCOPE])
    assert fake_msal.apps[0].authority == f"https://login.microsoftonline.us/{TENANT_GUID}"
    # Once is enough: token requests do not look again.
    assert fake_lookup.names == [TENANT]


def test_a_tenant_built_by_hand_is_used_as_given(
    fake_lookup: FakeLookup, fake_msal: FakeMsal
) -> None:
    tenant = Tenant(TENANT_GUID.upper(), US_GOV)

    auth = AuthContext(tenant, username=USER)
    app = AuthContext(tenant, client_id="app", client_secret="s3cret")
    auth.acquire_token([ARM_SCOPE])

    assert auth.tenant is tenant
    assert app.tenant is tenant
    # The GUID is held in its one spelling, so no two spellings make two tenants.
    assert tenant.id == TENANT_GUID
    assert (tenant.domain, tenant.oidc, tenant.region_scope) == (None, None, None)
    assert fake_msal.apps[0].authority == f"https://login.microsoftonline.us/{TENANT_GUID}"
    assert fake_lookup.calls == []


def test_messages_name_the_tenant_by_domain_and_errors_carry_the_guid(
    fake_msal: FakeMsal,
) -> None:
    with pytest.raises(InteractionRequired) as caught:
        user_context().get_tenant_context(CUSTOMER).acquire_token([ARM_SCOPE])

    assert caught.value.tenant_id == CUSTOMER_GUID
    assert f"tenant {CUSTOMER};" in str(caught.value)
    assert CUSTOMER_GUID not in str(caught.value)


def test_a_request_for_the_contexts_own_tenant_by_guid_may_prompt(fake_msal: FakeMsal) -> None:
    # Key Vault and the other Azure SDK clients name the tenant of a request by GUID, which
    # must come back to the context itself, and so may sign the person in, not to a context
    # from get_tenant_context() that never can. Seen with a context built from a domain name
    # (2026-09-29).
    auth = user_context()

    token = auth.get_token(ARM_SCOPE, tenant_id=TENANT_GUID)

    assert auth.get_tenant_context(TENANT_GUID) is auth
    assert auth.get_tenant_context(TENANT.upper()) is auth
    assert token.token
    assert fake_msal.methods() == ["interactive"]


def test_a_failed_lookup_fails_the_constructor(fake_lookup: FakeLookup) -> None:
    fake_lookup.error = TenantNotFound("no such tenant", name=TENANT)
    with pytest.raises(TenantNotFound):
        user_context()


def test_bad_arguments_are_refused_before_any_lookup(fake_lookup: FakeLookup) -> None:
    with pytest.raises(ValueError, match="username is required"):
        AuthContext("tenant")
    with pytest.raises(ValueError, match="username is not used"):
        AuthContext("tenant", client_id="app", client_secret="s3cret", username=USER)
    assert fake_lookup.calls == []


@pytest.mark.parametrize("authority", ["common", "organizations", "Consumers"])
def test_a_multi_tenant_authority_is_built_by_hand(fake_lookup: FakeLookup, authority: str) -> None:
    with pytest.raises(ValueError, match="pass Tenant"):
        AuthContext(authority, username=USER)

    auth = AuthContext(Tenant(authority, COMMERCIAL), username=USER)

    assert auth.tenant.id == authority.lower()
    assert fake_lookup.calls == []


def test_get_tenant_by_guid_shares_the_cloud_without_a_lookup(
    fake_lookup: FakeLookup, fake_msal: FakeMsal
) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result(call.app.authority)
    fake_lookup.cloud = US_GOV
    auth = user_context()

    token = auth.get_token(ARM_SCOPE, tenant_id=CUSTOMER_GUID)

    customer = auth.get_tenant_context(CUSTOMER_GUID)
    assert customer.tenant == Tenant(CUSTOMER_GUID, US_GOV)
    assert (customer.tenant.domain, customer.tenant.oidc) == (None, None)
    assert token.token == f"https://login.microsoftonline.us/{CUSTOMER_GUID}"
    assert fake_lookup.names == [TENANT]


def test_a_customer_named_by_domain_is_looked_up_once_in_the_home_cloud(
    fake_lookup: FakeLookup,
) -> None:
    fake_lookup.cloud = US_GOV
    auth = user_context()

    customer = auth.get_tenant_context(CUSTOMER)

    assert (
        customer
        is auth.get_tenant_context(CUSTOMER.upper())
        is auth.get_tenant_context(CUSTOMER_GUID)
    )
    # A customer tenant is in its partner's cloud, so it is looked for only there.
    assert fake_lookup.calls == [(TENANT, None), (CUSTOMER, US_GOV)]
    assert (customer.tenant.id, customer.tenant.cloud, customer.tenant.domain) == (
        CUSTOMER_GUID,
        US_GOV,
        CUSTOMER,
    )


def test_a_customer_first_made_by_guid_learns_its_domain_later(fake_lookup: FakeLookup) -> None:
    auth = user_context()

    by_guid = auth.get_tenant_context(CUSTOMER_GUID)
    assert by_guid.tenant.domain is None

    assert auth.get_tenant_context(CUSTOMER) is by_guid
    assert by_guid.tenant.domain == CUSTOMER
    assert by_guid.tenant.oidc is not None


# ---------------------------------------------------------------------------- chosen browser


@pytest.fixture
def fake_receiver(monkeypatch: pytest.MonkeyPatch) -> FakeReceiver:
    """Answer browser sign-ins in the chosen browser without opening one."""
    fake = FakeReceiver()
    monkeypatch.setattr("azure_auth.auth.context.AuthCodeReceiver", fake)
    return fake


def _unique_program() -> str:
    """A program nobody else registered, so each test sees its own registration."""
    return rf"C:\Browsers\{uuid.uuid4().hex}.exe"


def _registered(receiver: FakeReceiver) -> webbrowser.BackgroundBrowser:
    """The browser registered under the name the sign-in gave MSAL."""
    browser = webbrowser.get(receiver.requests[0]["browser_name"])
    assert isinstance(browser, webbrowser.BackgroundBrowser)
    return browser


def test_without_a_browser_the_default_browser_signs_in(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver
) -> None:
    user_context().acquire_token([ARM_SCOPE])

    assert fake_msal.methods() == ["interactive"]
    assert fake_receiver.requests == []


def test_a_chosen_browser_signs_in_through_the_auth_code_flow(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver
) -> None:
    info = user_context(browser="msedge").acquire_token([ARM_SCOPE])

    assert info.token == "interactive"
    assert fake_msal.methods() == ["initiate_auth_code_flow", "auth_code_flow"]
    initiate, redeem = fake_msal.calls
    assert initiate.app.broker is False
    assert initiate.scopes == [ARM_SCOPE]
    assert initiate.kwargs == {
        "redirect_uri": "http://localhost:51234",
        "prompt": None,
        "login_hint": USER,
        "claims_challenge": None,
        "response_mode": "form_post",
    }
    assert fake_receiver.ports == [0]
    assert fake_receiver.requests == [
        {
            "auth_uri": "https://login.example/authorize",
            "state": "the-state",
            "timeout": 120,
            "browser_name": fake_receiver.requests[0]["browser_name"],
        }
    ]
    assert fake_receiver.closed
    assert redeem.scopes == [ARM_SCOPE]
    assert redeem.kwargs["auth_code_flow"]["state"] == "the-state"
    assert redeem.kwargs["auth_response"] == {"code": "the-code", "state": "the-state"}


def test_a_chosen_browser_is_registered_with_the_address_as_its_last_argument(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver
) -> None:
    user_context(browser="msedge").acquire_token([ARM_SCOPE])

    browser = _registered(fake_receiver)
    assert (browser.name, browser.args) == ("msedge", ["%s"])
    assert "%s" not in fake_receiver.requests[0]["browser_name"]


def test_a_chosen_browser_may_be_given_arguments(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver
) -> None:
    program = _unique_program()
    user_context(browser=[program, "--profile-directory=Profile 2"]).acquire_token([ARM_SCOPE])

    browser = _registered(fake_receiver)
    assert (browser.name, browser.args) == (program, ["--profile-directory=Profile 2", "%s"])


def test_a_chosen_browser_may_be_given_as_a_path(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver
) -> None:
    program = Path(_unique_program())
    user_context(browser=program).acquire_token([ARM_SCOPE])

    assert _registered(fake_receiver).name == str(program)


def test_a_chosen_browser_is_registered_once(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every registration lengthens webbrowser's try order, so repeated sign-ins must not add
    # one each.
    registered: list[str] = []
    monkeypatch.setattr(webbrowser, "register", lambda name, *args: registered.append(name))
    auth = user_context(browser=_unique_program())

    auth.login(client_id="app", scopes=[ARM_SCOPE], pick_account=True)
    auth.login(client_id="app", scopes=[ARM_SCOPE], pick_account=True)

    assert len(fake_receiver.requests) == 2
    assert registered == [fake_receiver.requests[0]["browser_name"]]


def test_a_chosen_browser_is_given_the_claims_and_the_forced_prompt(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver
) -> None:
    auth = user_context(browser="msedge", browser_timeout=5)

    auth.acquire_token([ARM_SCOPE], claims='{"access_token": {}}')
    auth.login(client_id="app", scopes=[ARM_SCOPE], pick_account=True)

    claimed, forced = (call for call in fake_msal.calls if call.method == "initiate_auth_code_flow")
    assert claimed.kwargs["claims_challenge"] == '{"access_token": {}}'
    assert forced.kwargs["prompt"] == "select_account"
    assert [request["timeout"] for request in fake_receiver.requests] == [5, 5]


def test_a_chosen_browser_is_told_to_ask_for_the_password_again(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver
) -> None:
    user_context(browser="msedge").login(client_id="app", scopes=[ARM_SCOPE], reauthenticate=True)

    (flow,) = (call for call in fake_msal.calls if call.method == "initiate_auth_code_flow")
    assert flow.kwargs["prompt"] == "login"


def test_an_unanswered_sign_in_in_a_chosen_browser_is_reported_not_hung(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver
) -> None:
    fake_receiver.response = None

    with pytest.raises(AuthError, match="not completed within 120 seconds") as caught:
        user_context(browser="msedge").acquire_token([ARM_SCOPE])

    assert not isinstance(caught.value, (InteractionRequired, ConsentRequired))
    assert fake_msal.methods() == ["initiate_auth_code_flow"]


def test_a_failed_sign_in_in_a_chosen_browser_is_raised_as_auth_error(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver
) -> None:
    fake_msal.interactive = lambda call: error_result("access_denied", "user cancelled")

    with pytest.raises(AuthError, match="access_denied: user cancelled"):
        user_context(browser="msedge").acquire_token([ARM_SCOPE])


def test_somebody_else_signing_in_in_a_chosen_browser_is_refused(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver
) -> None:
    fake_msal.interactive = lambda call: token_result(
        id_token_claims={"preferred_username": "someone@else.com"}
    )

    with pytest.raises(AuthError, match=r"Signed in as 'someone@else\.com'"):
        user_context(browser="msedge").acquire_token([ARM_SCOPE])


def test_a_broker_falling_back_uses_the_chosen_browser(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver, broker_installed: None
) -> None:
    fake_msal.interactive = lambda call: (
        error_result("broker_error") if call.app.broker else token_result("browser")
    )

    token = user_context(broker=True, browser="msedge").acquire_token([ARM_SCOPE])

    assert token.token == "browser"
    assert fake_msal.methods() == ["interactive", "initiate_auth_code_flow", "auth_code_flow"]


def test_a_customer_keeps_the_chosen_browser() -> None:
    auth = user_context(browser=["msedge", "--inprivate"])

    assert auth.get_tenant_context(CUSTOMER)._browser == ("msedge", "--inprivate")


def test_browser_is_rejected_for_app_flows() -> None:
    with pytest.raises(ValueError, match="browser is only available"):
        AuthContext("tenant", client_id="app", client_secret="s3cret", browser="msedge")


@pytest.mark.parametrize("browser", ["", [], [""]])
def test_browser_must_name_a_program(browser: str | list[str]) -> None:
    with pytest.raises(ValueError, match="browser must name a program"):
        user_context(browser=browser)


# ---------------------------------------------------------------------------- before the browser


def test_before_browser_opens_is_called_right_before_the_default_browser(
    fake_msal: FakeMsal,
) -> None:
    events: list[str] = []

    def interactive(call: Call) -> Result:
        events.append("window")
        return token_result()

    fake_msal.interactive = interactive

    user_context(before_browser_opens=lambda: events.append("before")).acquire_token([ARM_SCOPE])

    assert events == ["before", "window"]


def test_before_browser_opens_is_called_right_before_a_chosen_browser(
    fake_msal: FakeMsal, fake_receiver: FakeReceiver
) -> None:
    # The chosen browser opens when the receiver is asked for the answer.
    requests_seen: list[int] = []

    def before() -> None:
        requests_seen.append(len(fake_receiver.requests))

    user_context(browser="msedge", before_browser_opens=before).acquire_token([ARM_SCOPE])

    assert requests_seen == [0]
    assert len(fake_receiver.requests) == 1


def test_before_browser_opens_is_called_for_every_window(fake_msal: FakeMsal) -> None:
    calls: list[None] = []
    auth = user_context(before_browser_opens=lambda: calls.append(None))

    auth.login(client_id="app", scopes=[ARM_SCOPE], pick_account=True)
    auth.login(client_id="app", scopes=[ARM_SCOPE], pick_account=True)

    assert (len(calls), fake_msal.methods()) == (2, ["interactive", "interactive"])


def test_before_browser_opens_is_not_called_when_the_cache_answers(fake_msal: FakeMsal) -> None:
    fake_msal.accounts = [ACCOUNT]
    fake_msal.silent = lambda call: token_result("silent")
    calls: list[None] = []

    user_context(before_browser_opens=lambda: calls.append(None)).acquire_token([ARM_SCOPE])

    assert (calls, fake_msal.methods()) == ([], ["silent"])


def test_before_browser_opens_is_not_called_when_the_broker_answers(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    calls: list[None] = []

    user_context(broker=True, before_browser_opens=lambda: calls.append(None)).acquire_token(
        [ARM_SCOPE]
    )

    assert calls == []
    assert [call.app.broker for call in fake_msal.calls] == [True]


def test_before_browser_opens_is_called_when_the_broker_falls_back_to_the_browser(
    fake_msal: FakeMsal, broker_installed: None
) -> None:
    events: list[str] = []

    def interactive(call: Call) -> Result:
        events.append("broker" if call.app.broker else "browser")
        return error_result("broker_error") if call.app.broker else token_result()

    fake_msal.interactive = interactive

    user_context(broker=True, before_browser_opens=lambda: events.append("before")).acquire_token(
        [ARM_SCOPE]
    )

    assert events == ["broker", "before", "browser"]


def test_an_error_before_the_browser_opens_fails_the_sign_in_without_a_window(
    fake_msal: FakeMsal,
) -> None:
    def fail() -> None:
        raise RuntimeError("could not get ready")

    with pytest.raises(RuntimeError, match="could not get ready"):
        user_context(before_browser_opens=fail).acquire_token([ARM_SCOPE])

    assert fake_msal.methods() == []


def test_a_customer_keeps_before_browser_opens() -> None:
    def before() -> None:
        pass

    auth = user_context(before_browser_opens=before)

    assert auth.get_tenant_context(CUSTOMER)._before_browser_opens is before


def test_before_browser_opens_is_rejected_for_app_flows() -> None:
    with pytest.raises(ValueError, match="before_browser_opens is only available"):
        AuthContext(
            "tenant", client_id="app", client_secret="s3cret", before_browser_opens=lambda: None
        )


# ---------------------------------------------------------------------------- the disk cache


# msal-extensions ships no types, so mypy sees its class as Any.
class _PlainFile(msal_extensions.FilePersistence):  # type: ignore[misc]
    """A plain file standing in for the encrypted one."""

    is_encrypted = True


@pytest.fixture
def cache_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Make disk caches plain files, in a process with no disk cache open yet.

    Returns:
        The file for a context's ``cache_path``.
    """
    monkeypatch.setattr("msal_extensions.build_encrypted_persistence", _PlainFile)
    monkeypatch.setattr("azure_auth.auth.cache._disk_caches", {})
    return tmp_path / "cache.bin"


def _store(auth: AuthContext, token: str) -> None:
    """Record a token in a context's cache, as MSAL does after a token response."""
    auth._cache.add(
        {
            "client_id": "app",
            "scope": ["https://graph.microsoft.com/.default"],
            "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            "response": {"access_token": token, "expires_in": 3600, "token_type": "Bearer"},
        }
    )


def _written(path: Path) -> list[str]:
    """Read the access tokens a plain cache file holds; none for no file."""
    if not path.exists():
        return []
    state = json.loads(path.read_text(encoding="utf-8"))
    return [entry["secret"] for entry in state.get("AccessToken", {}).values()]


def test_flush_cache_writes_the_disk_cache(cache_file: Path) -> None:
    auth = user_context(cache="disk", cache_path=cache_file)
    _store(auth, "kept")
    assert _written(cache_file) == []

    auth.flush_cache()

    assert _written(cache_file) == ["kept"]


def test_a_tenant_context_flushes_the_cache_it_shares(cache_file: Path) -> None:
    auth = user_context(cache="disk", cache_path=cache_file)
    _store(auth, "kept")

    auth.get_tenant_context(CUSTOMER).flush_cache()

    assert _written(cache_file) == ["kept"]


def test_flush_cache_has_nothing_to_do_for_the_memory_cache() -> None:
    auth = user_context(cache="memory")
    _store(auth, "kept")

    auth.flush_cache()

    found = auth._cache.search(TokenCache.CredentialType.ACCESS_TOKEN)
    assert [entry["secret"] for entry in found] == ["kept"]


def test_closing_the_async_context_flushes_the_cache(cache_file: Path) -> None:
    auth = user_context(cache="disk", cache_path=cache_file)
    _store(auth, "kept")

    asyncio.run(auth.aio.close())

    assert _written(cache_file) == ["kept"]
