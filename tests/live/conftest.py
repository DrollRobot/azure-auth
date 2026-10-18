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
start, and the ``cached_credential`` tests last, when the cache is full. The interactive
test that revokes the account's sessions comes first of all, so the forced sign-ins after it
refill the caches it empties.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from azure_auth import AuthContext
from azure_auth.auth.cache import default_cache_path
from tests import cache_reminder
from tests.live.support import (
    BROKER_CACHE_NAME,
    KEEPS_CERTIFICATES,
    KEEPS_CONSENT,
    TENANT,
    USERNAME,
    cancel_alarm,
    live_user_auth,
    restore_baseline,
)

# The interactive test that revokes the account's sessions, which kills every sign-in the
# caches hold. It runs before the other interactive tests, whose forced sign-ins refill them.
REVOKES_SESSIONS = "test_token_revocation.py"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Put the ``interactive`` tests first, and the ``cached_credential`` tests last.

    The prompts come in one stretch, and the tests of signing in from the cache find it full.
    The session revocation (``REVOKES_SESSIONS``) leads the ``interactive`` tests. A stable
    sort: within each group the collection order stands.
    """

    def group(item: pytest.Item) -> int:
        if "interactive" in item.keywords:
            return 0 if item.path.name == REVOKES_SESSIONS else 1
        return 3 if "cached_credential" in item.keywords else 2

    items.sort(key=group)


def live_cache_file() -> Path:
    """Return the encrypted disk cache the sign-ins fill and the live tests read.

    It outlives the run, so one sign-in serves the live tests of later, unattended runs until
    the refresh token lapses. It sits beside the package's default cache, in the per-user
    cache directory, but in a file of its own, so test tokens and real ones never mix.

    Returns:
        The cache file's path; the first sign-in creates it.
    """
    return default_cache_path().with_name("live_tests_token_cache.bin")


@pytest.fixture(scope="session")
def _live_cache_path() -> Path:
    """The live tests' disk cache (:func:`live_cache_file`), with its reminder in place.

    A credential store nobody sees is a credential store nobody deletes. So before the first
    test touches the cache, when ``AZURE_AUTH_TEST_CACHE_REMINDER_PATH`` names a folder, a
    reminder pointing at the cache's folder is put there (``tests/cache_reminder.py``). The
    end-of-run summary names the cache files either way (:func:`pytest_terminal_summary`).
    """
    path = live_cache_file()
    folder = cache_reminder.configured_folder()
    if folder is not None:
        cache_reminder.place_reminder(path, folder)
    return path


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter, exitstatus: int, config: pytest.Config
) -> None:
    """Say where the token caches are, at the end of every run, whatever its outcome.

    Lists the live tests' cache files that exist after the run, the browser's and the
    broker's, with their size and age, and the reminder when one is configured. It is written
    by the terminal reporter, so output capturing does not hide it.
    """
    cache = live_cache_file()
    files = [path for path in (cache, cache.with_name(BROKER_CACHE_NAME)) if path.exists()]
    if not files:
        return
    terminalreporter.section("token caches on disk", sep="=")
    for path in files:
        stat = path.stat()
        modified = datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="minutes")
        terminalreporter.line(f"{path}  ({stat.st_size} bytes, modified {modified})")
    terminalreporter.line(
        "Encrypted, but they hold the live tests' sign-in, refresh token included."
        " Delete them when testing ends."
    )
    folder = cache_reminder.configured_folder()
    if folder is None:
        terminalreporter.line(
            f"No reminder on your desk: set {cache_reminder.ENV_VAR} to a folder you look at."
        )
    else:
        terminalreporter.line(f"Reminder: {cache_reminder.reminder_path(folder)}")


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


@pytest.fixture(autouse=True)
def _alarm_ends_with_the_sign_in(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Stop a forced sign-in's alarm once the sign-in returns, and after every test.

    ``walkthrough`` prints its steps at once and sets the alarm for later, so a person who
    has already answered the window must not be called. ``AuthContext._interactive`` is where
    every sign-in window opens and returns: the broker's, the default browser's and a chosen
    browser's.
    """
    interactive = AuthContext._interactive

    def answered(self: AuthContext, *args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return interactive(self, *args, **kwargs)
        finally:
            cancel_alarm()

    monkeypatch.setattr(AuthContext, "_interactive", answered)
    yield
    cancel_alarm()


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
