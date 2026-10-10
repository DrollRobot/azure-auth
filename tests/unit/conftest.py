"""Fixtures for every unit test."""

from __future__ import annotations

import pytest

from azure_auth import Tenant
from tests.fakes import FakeLookup


@pytest.fixture(autouse=True)
def fake_lookup(monkeypatch: pytest.MonkeyPatch) -> FakeLookup:
    """Keep ``AuthContext`` from looking its tenant up on the network when it is created.

    Every tenant is found in the commercial cloud unless a test sets another.
    """
    fake = FakeLookup()
    monkeypatch.setattr(Tenant, "lookup", fake)
    return fake
