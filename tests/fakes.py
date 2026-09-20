"""A scriptable stand-in for the ``msal`` module.

Unit tests replace ``azure_auth.auth.context.msal`` with a :class:`FakeMsal` so that no
network call, browser or broker is ever involved. Behaviour is scripted per test through the
callables on the fake; every MSAL call is recorded in ``calls``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

Result = dict[str, Any]


def token_result(token: str = "token", expires_in: int = 3600, **extra: Any) -> Result:
    """Build a successful MSAL-style result."""
    return {"access_token": token, "expires_in": expires_in, "token_type": "Bearer", **extra}


def error_result(error: str, description: str = "", **extra: Any) -> Result:
    """Build a failed MSAL-style result."""
    return {"error": error, "error_description": description, **extra}


@dataclass
class Call:
    """One recorded call into a fake MSAL application."""

    method: str
    app: FakeApp
    scopes: list[str]
    kwargs: dict[str, Any]


@dataclass
class FakeMsal:
    """Replacement for the ``msal`` module with scriptable behaviour."""

    accounts: list[dict[str, Any]] = field(default_factory=list)
    silent: Callable[[Call], Result | None] = lambda call: None
    interactive: Callable[[Call], Result] = lambda call: token_result("interactive")
    for_client: Callable[[Call], Result] = lambda call: token_result("app")
    apps: list[FakeApp] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)

    def TokenCache(self) -> object:
        """Return a unique object standing in for a token cache."""
        return object()

    def PublicClientApplication(self, client_id: str, **kwargs: Any) -> FakeApp:
        """Create a fake public client application."""
        return self._new_app("public", client_id, kwargs)

    def ConfidentialClientApplication(self, client_id: str, **kwargs: Any) -> FakeApp:
        """Create a fake confidential client application."""
        return self._new_app("confidential", client_id, kwargs)

    def _new_app(self, kind: str, client_id: str, kwargs: dict[str, Any]) -> FakeApp:
        app = FakeApp(self, kind, client_id, kwargs)
        self.apps.append(app)
        return app

    def methods(self) -> list[str]:
        """Return the names of the recorded calls, in order."""
        return [call.method for call in self.calls]


class FakeApp:
    """Replacement for an MSAL client application."""

    CONSOLE_WINDOW_HANDLE = object()

    def __init__(self, module: FakeMsal, kind: str, client_id: str, kwargs: dict[str, Any]) -> None:
        """Record how the application was constructed."""
        self.module = module
        self.kind = kind
        self.client_id = client_id
        self.authority: str = kwargs["authority"]
        self.token_cache: object = kwargs["token_cache"]
        self.client_credential: Any = kwargs.get("client_credential")
        self.broker: bool = bool(kwargs.get("enable_broker_on_windows"))
        self.removed_tokens = 0

    def _record(self, method: str, scopes: list[str], kwargs: dict[str, Any]) -> Call:
        call = Call(method, self, list(scopes), kwargs)
        self.module.calls.append(call)
        return call

    def get_accounts(self, username: str | None = None) -> list[dict[str, Any]]:
        """Return the scripted accounts that match ``username``."""
        return [
            account
            for account in self.module.accounts
            if username is None or account["username"].lower() == username.lower()
        ]

    def acquire_token_silent_with_error(
        self, scopes: list[str], account: dict[str, Any], **kwargs: Any
    ) -> Result | None:
        """Run the scripted silent behaviour."""
        return self.module.silent(self._record("silent", scopes, {"account": account, **kwargs}))

    def acquire_token_interactive(self, scopes: list[str], **kwargs: Any) -> Result:
        """Run the scripted interactive behaviour."""
        return self.module.interactive(self._record("interactive", scopes, kwargs))

    def acquire_token_for_client(self, scopes: list[str], **kwargs: Any) -> Result:
        """Run the scripted client credentials behaviour."""
        return self.module.for_client(self._record("for_client", scopes, kwargs))

    def remove_tokens_for_client(self) -> None:
        """Count cache purges."""
        self.removed_tokens += 1
