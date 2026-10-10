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

The test application is part of the baseline too: it holds no certificate a test uploaded.
The same restore takes off every one it finds.

Restoring the baseline is not marked ``interactive``, although it can prompt. It has to run
for every live run, and marking it would make it optional. It is silent when the tenant is
already at the baseline, which is the normal case, and prompts once when a baseline scope is
missing. Taking scopes out needs no prompt, but it changes the tenant, so it is only done to
a tenant marked disposable; on any other the run fails and says what is beyond the baseline.

Tests marked ``interactive`` cannot pass without a person: a forced sign-in, which shows the
account picker, for each first-party client id and through the broker, and the consent test,
which signs in a second user. Every other user-flow test takes its token from the encrypted
disk cache, which outlives the run, and signs in when there is none
(:func:`~tests.live.support.ensure_sign_in`)::

    uv run --env-file .env pytest tests/live -s --run-destructive-remote --no-cov

The ``interactive`` tests are collected first, so every prompt comes in one stretch at the
start, and the ``cached_credential`` tests last, when the cache is full.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from azure_auth import AuthContext
from azure_auth.auth.cache import default_cache_path
from tests.live.support import (
    KEEPS_CERTIFICATES,
    KEEPS_CONSENT,
    TENANT,
    USERNAME,
    live_user_auth,
    restore_baseline,
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Put the ``interactive`` tests first, and the ``cached_credential`` tests last.

    The prompts come in one stretch, and the tests of signing in from the cache find it full.
    A stable sort: within each group the collection order stands.
    """

    def group(item: pytest.Item) -> int:
        if "interactive" in item.keywords:
            return 0
        return 2 if "cached_credential" in item.keywords else 1

    items.sort(key=group)


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
    """Restore the exact baseline once, before the first live test runs.

    Not marked ``interactive``, although it can prompt; the module docstring says why. Does
    nothing when there is no baseline to keep: no tenant, or neither an administrator who may
    use the Graph application nor a test application.
    """
    if KEEPS_CONSENT or KEEPS_CERTIFICATES:
        restore_baseline(
            _live_cache_path,
            may_remove=lambda: bool(request.getfixturevalue("_remote_disposable_confirmed")),
        )


@pytest.fixture(autouse=True)
def _baseline_after_state_changes(
    request: pytest.FixtureRequest, _live_cache_path: Path
) -> Iterator[None]:
    """Restore the exact baseline after a test that can change it, pass or fail.

    Those are the ``interactive`` tests, since a consent screen can be accepted, and the
    ``destructive_remote`` ones. Whether the tenant may have things taken out is settled
    before the test, while fixtures can still be asked for.
    """
    node = request.node
    changes_state = node.get_closest_marker("interactive") or node.get_closest_marker(
        "destructive_remote"
    )
    if not (changes_state and (KEEPS_CONSENT or KEEPS_CERTIFICATES)):
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
    return live_user_auth(cache_path)
