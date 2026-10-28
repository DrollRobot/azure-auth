"""Scriptable stand-ins for the ``msal`` module and for the tenant lookup.

Unit tests replace ``azure_auth.auth.context.msal`` with a :class:`FakeMsal` so that no
network call, browser or broker is ever involved. Behaviour is scripted per test through the
callables on the fake; every MSAL call is recorded in ``calls``.

A context given a string looks its tenant up when it is created. Every unit test replaces
that lookup with a :class:`FakeLookup`, which finds every tenant in ``cloud`` and records
each lookup.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from azure_auth import Tenant
from azure_auth.auth.tenant import as_guid
from azure_auth.clouds import COMMERCIAL, Cloud

Result = dict[str, Any]

# MSAL's ``token_source`` for a token Entra issued in that request.
IDP = "identity_provider"


def token_result(token: str = "token", expires_in: int = 3600, **extra: Any) -> Result:
    """Build a successful MSAL-style result.

    MSAL says where a token came from in ``token_source``: pass it to script a silent
    request that Entra answered through the refresh token (``"identity_provider"``). The
    fake application fills it in otherwise, as MSAL would: a silent request from the
    cache, a sign-in from Entra.
    """
    return {"access_token": token, "expires_in": expires_in, "token_type": "Bearer", **extra}


def _from(result: Result | None, source: str) -> Result | None:
    """Fill in ``token_source`` on a successful result that does not say, as MSAL does."""
    if result and "access_token" in result:
        return {"token_source": source, **result}
    return result


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
        self.pii_log: bool = bool(kwargs.get("enable_pii_log"))
        self.capabilities: list[str] = list(kwargs.get("client_capabilities") or [])
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
        """Run the scripted silent behaviour; its token comes from the cache unless scripted."""
        call = self._record("silent", scopes, {"account": account, **kwargs})
        return _from(self.module.silent(call), "cache")

    def acquire_token_interactive(self, scopes: list[str], **kwargs: Any) -> Result:
        """Run the scripted interactive behaviour; its token comes from Entra."""
        result = _from(self.module.interactive(self._record("interactive", scopes, kwargs)), IDP)
        assert result is not None
        return result

    def initiate_auth_code_flow(self, scopes: list[str], **kwargs: Any) -> dict[str, Any]:
        """Record the start of an auth code flow and return a flow for it."""
        self._record("initiate_auth_code_flow", scopes, kwargs)
        return {"auth_uri": "https://login.example/authorize", "state": "the-state"}

    def acquire_token_by_auth_code_flow(
        self, auth_code_flow: dict[str, Any], auth_response: dict[str, Any], **kwargs: Any
    ) -> Result:
        """Run the scripted interactive behaviour for the code a browser sign-in returned."""
        call = self._record(
            "auth_code_flow",
            kwargs.pop("scopes", []),
            {"auth_code_flow": auth_code_flow, "auth_response": auth_response, **kwargs},
        )
        result = _from(self.module.interactive(call), IDP)
        assert result is not None
        return result

    def acquire_token_for_client(self, scopes: list[str], **kwargs: Any) -> Result:
        """Run the scripted client credentials behaviour; its token is cached unless scripted."""
        call = self._record("for_client", scopes, kwargs)
        result = _from(self.module.for_client(call), "cache")
        assert result is not None
        return result

    def remove_tokens_for_client(self) -> None:
        """Count cache purges."""
        self.removed_tokens += 1


@dataclass
class FakeReceiver:
    """Replacement for MSAL's ``AuthCodeReceiver``: answers a browser sign-in without a browser.

    Install it in place of the class; each construction returns this one object.
    """

    response: dict[str, Any] | None = field(
        default_factory=lambda: {"code": "the-code", "state": "the-state"}
    )
    port: int = 51234
    ports: list[int] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    closed: bool = False

    def __call__(self, port: int) -> FakeReceiver:
        """Stand in for constructing a receiver on ``port``."""
        self.ports.append(port)
        return self

    def __enter__(self) -> FakeReceiver:
        """Enter the ``with`` block."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Record that the receiver was closed."""
        self.closed = True

    def get_port(self) -> int:
        """Return the port the receiver listens on."""
        return self.port

    def get_auth_response(self, **kwargs: Any) -> dict[str, Any] | None:
        """Record the request and return the scripted answer; ``None`` is a timeout."""
        self.requests.append(kwargs)
        return self.response


def tenant_guid(tenant: str) -> str:
    """The GUID the fake lookup answers for a tenant: a GUID is its own, a name gets a stable one.

    Args:
        tenant: Tenant id (GUID) or domain name, as a test passes it to ``AuthContext``.

    Returns:
        The GUID in its canonical spelling.
    """
    try:
        return str(uuid.UUID(tenant))
    except ValueError:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, tenant.lower()))


@dataclass
class FakeLookup:
    """Replacement for :meth:`azure_auth.Tenant.lookup`."""

    cloud: Cloud = COMMERCIAL
    region_sub_scope: str | None = None
    error: Exception | None = None
    calls: list[tuple[str, Cloud | None]] = field(default_factory=list)
    clouds_asked: list[tuple[Cloud, ...] | None] = field(default_factory=list)

    def __call__(
        self,
        name: str,
        cloud: Cloud | None = None,
        *,
        clouds: tuple[Cloud, ...] | None = None,
    ) -> Tenant:
        """Record the lookup and find the tenant in ``cloud``, or raise ``error``."""
        self.calls.append((name, cloud))
        self.clouds_asked.append(clouds)
        if self.error is not None:
            raise self.error
        oidc = {"tenant_region_sub_scope": self.region_sub_scope}
        domain = None if as_guid(name) else name.lower()
        return Tenant(tenant_guid(name), self.cloud, domain=domain, oidc=oidc)

    @property
    def names(self) -> list[str]:
        """The names looked up, in order."""
        return [name for name, _cloud in self.calls]
