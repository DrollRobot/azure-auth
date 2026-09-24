"""Live end-to-end tests against a real tenant.

Nothing here runs unless the environment names a tenant; ``support.py`` lists the variables.

Every live run starts from the consent baseline: the Graph application holds at least
``BASELINE_SCOPES`` in the tenant (see ``support.py``). The ``consent_baseline`` fixture makes
that so before the first test that uses the shared sign-in, and the one test that revokes
consent brings the tenant back in its teardown. So no test depends on another having run,
and no order of tests can leave the tenant unusable for the next run.

``consent_baseline`` is not marked ``interactive``, although it can prompt. It has to run for
every live run, and marking it would make it optional. It is silent when the cache and the
tenant are already fine, which is the normal case, and prompts once when they are not; so a
``-m "not interactive"`` run can open one sign-in at the start if the tenant was disturbed.

Tests marked ``interactive`` will prompt: a forced browser sign-in for each first-party client
id, and the consent test, which signs in a second user. Every other user-flow test only *uses*
the signed-in account and cannot open a prompt: it takes its token from the encrypted disk
cache, which outlives the run, and skips when there is none. So do the prompts once, walk
away, and run the rest unattended for as long as the refresh token lasts::

    uv run --env-file .env pytest tests/live -s -m interactive --run-destructive-remote --no-cov
    uv run --env-file .env pytest tests/live -s -m "not interactive" --no-cov  # unattended

The ``interactive`` tests are collected first, so every prompt comes in one stretch at the
start. That is a convenience for the person at the desktop; nothing depends on it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from azure_auth import AuthContext
from azure_auth.auth.cache import default_cache_path
from tests.live.support import TENANT, USERNAME, cached_user_auth, ensure_consent_baseline


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Put the ``interactive`` tests first, so the prompts come in one stretch.

    A stable sort: within each group the collection order stands.
    """
    items.sort(key=lambda item: 0 if "interactive" in item.keywords else 1)


@pytest.fixture(scope="session")
def _live_cache_path() -> Path:
    """The encrypted disk cache the sign-ins fill and the live tests read.

    It outlives the run, so one sign-in serves the live tests of later, unattended runs until
    the refresh token lapses. It sits beside the package's default cache, in the per-user
    cache directory, but in a file of its own, so test tokens and real ones never mix.
    """
    return default_cache_path().with_name("live_tests_token_cache.bin")


@pytest.fixture(scope="session")
def consent_baseline(_live_cache_path: Path) -> None:
    """Bring the tenant to the consent baseline once, before any test uses the sign-in.

    Not marked ``interactive``, although it can prompt; the module docstring says why.
    """
    if not (TENANT and USERNAME):
        pytest.skip("set AZURE_AUTH_TEST_TENANT_ID and AZURE_AUTH_TEST_USERNAME")
    ensure_consent_baseline(_live_cache_path, force=False)


@pytest.fixture(scope="module")
def cache_path(_live_cache_path: Path, consent_baseline: None) -> Path:
    """The shared disk cache, with the tenant at the consent baseline.

    Every test that uses the shared sign-in takes this, so each starts at baseline without
    asking for it.
    """
    return _live_cache_path


@pytest.fixture
def user_auth(cache_path: Path) -> AuthContext:
    return cached_user_auth(cache_path)
