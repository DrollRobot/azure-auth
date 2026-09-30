"""Live end-to-end tests against a real tenant.

Nothing here runs unless the environment names a tenant; ``support.py`` lists the variables.

Every live test starts from the consent baseline: the Graph application is granted exactly
``BASELINE_SCOPES`` in the tenant, no more and no fewer (see ``support.py``). A tenant whose
users may not use the Graph application (``AZURE_AUTH_TEST_GRAPH`` unset) has no baseline to
keep; its Graph tests skip, and nothing else depends on the baseline.
:func:`~tests.live.support.restore_baseline` puts it there -- reading what is granted, adding
what is missing, taking out what is beyond -- at the start of every live run, and again after
every test that can change consent: every ``interactive`` test, since a consent screen can be
accepted, and every ``destructive_remote`` one. It runs whether the test passed or failed. So
no test depends on another having run, none has to arrange its own consent, and no order of
tests can leave the tenant unusable for the next run.

Restoring the baseline is not marked ``interactive``, although it can prompt. It has to run
for every live run, and marking it would make it optional. It is silent when the tenant is
already at the baseline, which is the normal case, and prompts once when a baseline scope is
missing; so a ``-m "not interactive"`` run can open one sign-in at the start if the tenant was
disturbed. Taking scopes out needs no prompt, but it changes the tenant, so it is only done to
a tenant marked disposable; on any other the run fails and says what is beyond the baseline.

Tests marked ``interactive`` cannot pass without a person: a forced sign-in, which shows the
account picker, for each first-party client id and through the broker, and the consent test,
which signs in a second user. Every other user-flow test needs nobody. Most only *use* the
signed-in account: they take their token from the encrypted disk cache, which outlives the
run, and skip when there is none. So do the prompts once, walk away, and run the rest
unattended for as long as the refresh token lasts::

    uv run --env-file .env pytest tests/live -s -m interactive --run-destructive-remote --no-cov
    uv run --env-file .env pytest tests/live -s -m "not interactive" --no-cov  # unattended

The ``interactive`` tests are collected first, so every prompt comes in one stretch at the
start. That is a convenience for the person at the desktop; nothing depends on it.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from azure_auth import AuthContext
from azure_auth.auth.cache import default_cache_path
from tests.live.support import GRAPH, TENANT, USERNAME, cached_user_auth, restore_baseline


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


@pytest.fixture(scope="session", autouse=True)
def consent_baseline(_live_cache_path: Path, request: pytest.FixtureRequest) -> None:
    """Restore the exact consent baseline once, before the first live test runs.

    Not marked ``interactive``, although it can prompt; the module docstring says why. Does
    nothing when no tenant is configured, so the live tests that need no account still run,
    or when the tenant's users may not use the Graph application.
    """
    if TENANT and USERNAME and GRAPH:
        restore_baseline(
            _live_cache_path,
            may_remove=lambda: bool(request.getfixturevalue("_remote_disposable_confirmed")),
        )


@pytest.fixture(autouse=True)
def _baseline_after_state_changes(
    request: pytest.FixtureRequest, _live_cache_path: Path
) -> Iterator[None]:
    """Restore the exact consent baseline after a test that can change consent, pass or fail.

    Those are the ``interactive`` tests, since a consent screen can be accepted, and the
    ``destructive_remote`` ones. Whether the tenant may have scopes taken out is settled
    before the test, while fixtures can still be asked for.
    """
    node = request.node
    changes_state = node.get_closest_marker("interactive") or node.get_closest_marker(
        "destructive_remote"
    )
    if not (changes_state and TENANT and USERNAME and GRAPH):
        yield
        return
    disposable = bool(request.getfixturevalue("_remote_disposable_confirmed"))
    yield
    restore_baseline(_live_cache_path, may_remove=lambda: disposable)


@pytest.fixture(scope="module")
def cache_path(_live_cache_path: Path) -> Path:
    """The shared disk cache the sign-ins fill; the tenant is at the consent baseline.

    Skips the test when no tenant is configured.
    """
    if not (TENANT and USERNAME):
        pytest.skip("set AZURE_AUTH_TEST_TENANT_ID and AZURE_AUTH_TEST_USERNAME")
    return _live_cache_path


@pytest.fixture
def user_auth(cache_path: Path) -> AuthContext:
    return cached_user_auth(cache_path)
