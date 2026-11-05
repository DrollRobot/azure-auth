"""Fixtures for every unit test."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
import requests

from azure_auth import Tenant
from azure_auth.auth import managed_identity as managed_identity_module
from tests.fakes import FakeLookup
from tests.identity import (
    CONTAINER_APPS_ENDPOINT,
    HOST_VARIABLES,
    IDENTITY_HEADER,
    FakeEndpoint,
    FakeEntra,
    MsalOver,
    app_service_answer,
    imds_answer,
)


@pytest.fixture(autouse=True)
def fake_lookup(monkeypatch: pytest.MonkeyPatch) -> FakeLookup:
    """Keep ``AuthContext`` from looking its tenant up on the network when it is created.

    Every tenant is found in the commercial cloud unless a test sets another.
    """
    fake = FakeLookup()
    monkeypatch.setattr(Tenant, "lookup", fake)
    return fake


@pytest.fixture
def endpoint(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeEndpoint]:
    """The host's identity endpoint, answering App Service style, off any real host.

    No host variable is set, so msal takes this for a virtual machine until a test sets one.
    """
    for name in HOST_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    fake = FakeEndpoint(app_service_answer)
    sessions: list[requests.Session] = []

    def http_client() -> requests.Session:
        session = managed_identity_module.IdentitySession()
        session.mount("http://", fake)
        session.mount("https://", fake)
        sessions.append(session)
        return session

    monkeypatch.setattr(managed_identity_module, "http_client", http_client)
    yield fake
    for session in sessions:
        session.close()


@pytest.fixture
def container_apps(monkeypatch: pytest.MonkeyPatch, endpoint: FakeEndpoint) -> FakeEndpoint:
    """A Container Apps job: the App Service-style variables are set."""
    monkeypatch.setenv("IDENTITY_ENDPOINT", CONTAINER_APPS_ENDPOINT)
    monkeypatch.setenv("IDENTITY_HEADER", IDENTITY_HEADER)
    return endpoint


@pytest.fixture
def vm(endpoint: FakeEndpoint) -> FakeEndpoint:
    """A virtual machine: no host variable, the instance metadata endpoint answers."""
    endpoint.answer = imds_answer
    return endpoint


@pytest.fixture
def entra(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeEntra]:
    """Entra ID, where the context's msal applications send their requests."""
    fake = FakeEntra()
    with requests.Session() as session:
        session.mount("https://", fake)
        session.mount("http://", fake)
        monkeypatch.setattr("azure_auth.auth.context.msal", MsalOver(session))
        yield fake
