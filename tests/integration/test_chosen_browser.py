"""A sign-in in a chosen browser, through the real MSAL, ``webbrowser`` and a launched program.

``AuthContext(browser=...)`` runs MSAL's browser sign-in itself, with MSAL's
``AuthCodeReceiver``, which ``msal`` does not export. These tests prove the wiring against
the installed msal: the browser registered with ``webbrowser`` is the one launched, with its
arguments and the sign-in address last; the receiver accepts the ``form_post`` answer and
checks its state; and the code is redeemed at the token endpoint. An msal upgrade that
changes the receiver fails here.

The browser is ``fake_browser.py``, run by this Python. Entra is :class:`FakeEntra`, which
answers the discovery document and the code redemption.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import msal
import pytest

from azure_auth import AuthContext, AuthError, Tenant
from azure_auth.clouds import COMMERCIAL
from tests.integration import fake_browser

pytestmark = [
    pytest.mark.integration,
    # webbrowser launches a browser and lets go of it, because a browser outlives the launch.
    # Python warns when it lets go of a process that is still running, as the fake browser
    # can be.
    pytest.mark.filterwarnings(r"ignore:subprocess \d+ is still running:ResourceWarning"),
]

LOGIN = "https://login.microsoftonline.com"
TENANT = "11111111-1111-1111-1111-111111111111"
USER = "admin@partner.com"
SCOPE = "https://management.azure.com/.default"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
# A safety net only: each sign-in ends when the fake browser answers. Starting it can take
# several seconds on a busy machine (measured up to 3.4 on Windows).
SIGN_IN_TIMEOUT_SECONDS = 60


class FakeEntra:
    """Entra ID's discovery document and token endpoint; any other request fails the test."""

    def __init__(self) -> None:
        """Start with no token requests."""
        self.token_requests: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> Any:
        """Answer the discovery documents: the tenant's, and the instance aliases."""
        body: dict[str, Any]
        if url == f"{LOGIN}/{TENANT}/v2.0/.well-known/openid-configuration":
            body = {
                "authorization_endpoint": f"{LOGIN}/{TENANT}/oauth2/v2.0/authorize",
                "token_endpoint": f"{LOGIN}/{TENANT}/oauth2/v2.0/token",
                "issuer": f"{LOGIN}/{TENANT}/v2.0",
            }
        elif url == f"{LOGIN}/common/discovery/instance":
            # Looking for cached accounts asks which hosts are aliases of the sign-in host.
            host = "login.microsoftonline.com"
            body = {"metadata": [{"preferred_network": host, "aliases": [host]}]}
        else:
            raise AssertionError(f"unexpected request: GET {url}")
        return SimpleNamespace(status_code=200, text=json.dumps(body), headers={})

    def post(self, url: str, data: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """Redeem an authorization code."""
        if url != f"{LOGIN}/{TENANT}/oauth2/v2.0/token":
            raise AssertionError(f"unexpected request: POST {url}")
        self.token_requests.append(dict(data or {}))
        body = {"access_token": "chosen-browser-token", "token_type": "Bearer", "expires_in": 3600}
        return SimpleNamespace(status_code=200, text=json.dumps(body), headers={})

    def close(self) -> None:
        """Nothing to close."""


@pytest.fixture
def entra(monkeypatch: pytest.MonkeyPatch) -> FakeEntra:
    """Send every MSAL application's requests to one :class:`FakeEntra`."""
    entra = FakeEntra()

    class MsalOver:
        def __getattr__(self, name: str) -> Any:
            return getattr(msal, name)

        def PublicClientApplication(self, *args: Any, **kwargs: Any) -> Any:
            return msal.PublicClientApplication(*args, http_client=entra, **kwargs)

    monkeypatch.setattr("azure_auth.auth.context.msal", MsalOver())
    return entra


def test_the_chosen_browser_answers_the_sign_in(entra: FakeEntra, tmp_path: Path) -> None:
    record = tmp_path / "record.json"
    browser = [sys.executable, "-I", fake_browser.__file__, "--record", str(record)]
    auth = AuthContext(
        Tenant(TENANT, COMMERCIAL),
        username=USER,
        browser=browser,
        browser_timeout=SIGN_IN_TIMEOUT_SECONDS,
    )

    token = auth.acquire_token([SCOPE], client_id=CLIENT_ID)

    assert token.token == "chosen-browser-token"
    # The registered program was launched with its own arguments and the address last.
    argv = json.loads(record.read_text(encoding="utf-8"))["argv"]
    assert argv[:2] == ["--record", str(record)]
    address = urlsplit(argv[2])
    query = parse_qs(address.query)
    assert address.path == f"/{TENANT}/oauth2/v2.0/authorize"
    assert query["response_mode"] == ["form_post"]
    assert query["login_hint"] == [USER]
    assert query["client_id"] == [CLIENT_ID]
    # The code the browser posted back was redeemed, at the address it was issued for.
    (redeemed,) = entra.token_requests
    assert redeemed["grant_type"] == "authorization_code"
    assert redeemed["code"] == fake_browser.CODE
    assert redeemed["redirect_uri"] == query["redirect_uri"][0]
    assert redeemed["code_verifier"]


def test_an_answer_with_the_wrong_state_is_refused(entra: FakeEntra, tmp_path: Path) -> None:
    # A forged answer to the listener must not be redeemed. The receiver refuses it and keeps
    # waiting; the person's decline that follows, with the right state, then ends the sign-in.
    # Ending it that way, not by a timeout, keeps the test independent of how long the fake
    # browser takes to start.
    record = tmp_path / "record.json"
    browser = [sys.executable, "-I", fake_browser.__file__, "--record", str(record)]
    auth = AuthContext(
        Tenant(TENANT, COMMERCIAL),
        username=USER,
        browser=[*browser, "--wrong-state"],
        browser_timeout=SIGN_IN_TIMEOUT_SECONDS,
    )

    with pytest.raises(AuthError, match="access_denied"):
        auth.acquire_token([SCOPE], client_id=CLIENT_ID)

    assert json.loads(record.read_text(encoding="utf-8"))["forged_status"] == 400
    assert entra.token_requests == []
