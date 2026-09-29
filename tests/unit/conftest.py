"""Fixtures for every unit test."""

from __future__ import annotations

import pytest

from tests.fakes import FakeDiscovery


@pytest.fixture(autouse=True)
def fake_discovery(monkeypatch: pytest.MonkeyPatch) -> FakeDiscovery:
    """Keep ``AuthContext`` from looking its tenant up on the network when it is created.

    Every tenant is found in the commercial cloud unless a test sets another.
    """
    fake = FakeDiscovery()
    monkeypatch.setattr("azure_auth.auth.context.discover_tenant", fake)
    return fake
