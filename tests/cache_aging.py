"""Make cached access tokens look expired, so a refresh can be tested without waiting.

A refresh only happens once an access token has expired, which against a live tenant means
waiting out most of an hour. These helpers age the cached entries instead. MSAL discards an
access token whose ``expires_on`` has passed -- ``TokenCache.search`` deletes it on the way
past -- and redeems the refresh token stored beside it, which is the path under test.

The shortcut is only worth having if it models the real thing. So
``tests/integration/test_disk_cache.py`` checks that an aged entry really does vanish from a
search while its refresh token stays, and ``tests/live/test_cache.py`` carries a ``slow``
test that waits out a real token lifetime and asserts the same outcome as the fast one.
"""

from __future__ import annotations

import time
from typing import Any

import msal

_ACCESS_TOKEN = msal.TokenCache.CredentialType.ACCESS_TOKEN


def access_tokens(cache: Any) -> list[dict[str, Any]]:
    """Return every access token in a cache, expired ones included.

    Args:
        cache: An ``msal.TokenCache``, or a subclass such as the encrypted disk cache.

    Returns:
        The cached access token entries.
    """
    # now=0 stops search from deleting expired entries as it walks past them, which would
    # otherwise hide exactly the entries a caller is trying to inspect.
    return list(cache.search(_ACCESS_TOKEN, now=0))


def expire_access_tokens(cache: Any, *, seconds_ago: int = 60) -> int:
    """Move the expiry of every cached access token into the past.

    Refresh tokens, accounts and ID tokens are left alone, so the cache ends up exactly as
    it would after the access tokens ran out on their own. A disk cache writes the change
    straight back to its file, so another context opening that file sees it.

    Args:
        cache: An ``msal.TokenCache``, or a subclass such as the encrypted disk cache.
        seconds_ago: How far in the past the new expiry lies.

    Returns:
        How many access tokens were aged. Zero means there was nothing to refresh, which a
        test should treat as a failed precondition rather than a pass.
    """
    past = str(int(time.time()) - seconds_ago)
    entries = access_tokens(cache)
    for entry in entries:
        # Extended expiry too: MSAL may fall back to an access token inside its extended
        # lifetime when the token endpoint is unreachable, which would mask a broken refresh.
        cache.modify(_ACCESS_TOKEN, entry, {"expires_on": past, "extended_expires_on": past})
    return len(entries)
