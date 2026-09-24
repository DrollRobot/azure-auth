"""Live end-to-end tests against a real tenant.

Nothing here runs unless the environment names a tenant; ``support.py`` lists the variables.

Only tests of interactive sign-in itself are marked ``interactive``: a forced browser sign-in
for each first-party client id, and the consent test. They need a human at this desktop, and
they leave their tokens in an encrypted disk cache that outlives the run.

Every other user-flow test only *uses* a signed-in account, so it is ``live`` but not
``interactive``. It cannot open a prompt: it takes its token from that cache, and skips when
there is none. So do the prompts once, walk away, and run the rest unattended for as long as
the refresh token lasts::

    uv run --env-file .env pytest tests/live -s -m interactive --run-destructive-remote --no-cov
    uv run --env-file .env pytest tests/live -s -m "not interactive" --no-cov  # unattended

The ``interactive`` tests are ordered so that every prompt comes in one stretch and the tenant
ends up consented. The consent test runs first (``test_consent.py`` collects before
``test_sign_in.py``), because its fixture revokes the Graph application's grants and puts
nothing back. The Graph sign-in that follows does, through the consent screen the missing
grants provoke. Run the consent test after that sign-in instead and the grants stay revoked:
the tests that read cached tokens carry on, but the two refresh tests fail, because a refresh
needs Entra to issue a new token and the consent for it is gone, and the ``.default`` test
skips for the same reason.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from azure_auth import AuthContext
from azure_auth.auth.cache import default_cache_path
from tests.live.support import cached_user_auth


@pytest.fixture(scope="module")
def cache_path() -> Path:
    """The encrypted disk cache the interactive tests fill and the live tests read.

    It outlives the run, so one interactive sign-in serves the live tests of later,
    unattended runs until the refresh token lapses. It sits beside the package's default
    cache, in the per-user cache directory, but in a file of its own, so test tokens and
    real ones never mix.
    """
    return default_cache_path().with_name("live_tests_token_cache.bin")


@pytest.fixture
def user_auth(cache_path: Path) -> AuthContext:
    return cached_user_auth(cache_path)
