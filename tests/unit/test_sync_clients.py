"""The blocking clients must offer what the asynchronous clients offer.

Behaviour is covered by ``tests/unit/sync``, which is generated from the tests of the
asynchronous clients.
"""

from __future__ import annotations

import inspect

import pytest

from azure_auth import clients, sync

pytestmark = pytest.mark.unit


def test_mirror_has_the_same_public_surface() -> None:
    assert set(sync.__all__) <= set(clients.__all__)
    for name in sync.__all__:
        blocking, asynchronous = getattr(sync, name), getattr(clients, name)
        public = {member for member in dir(asynchronous) if not member.startswith("_")}
        renamed = {"close" if member == "aclose" else member for member in public}
        assert renamed <= set(dir(blocking)), name
        assert not any(
            inspect.iscoroutinefunction(getattr(blocking, member)) for member in dir(blocking)
        )
