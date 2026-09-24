"""Unit tests for the pure helpers in ``tests/live/support.py``.

``ensure_consent_baseline`` itself signs in to Entra and is exercised by every live run. What
is tested here is the check it makes on the token that comes back: that a token missing a
baseline scope is caught, and that a token carrying more than the baseline is not, because
the baseline is a floor.
"""

from __future__ import annotations

import base64
import json

import pytest

from tests.live.support import missing_scopes, token_scopes

pytestmark = [pytest.mark.unit]


def jwt_with(scp: str | None) -> str:
    """Build an unsigned JWT whose payload carries the given ``scp`` claim, or none.

    Args:
        scp: The space-separated scopes, or ``None`` for a payload without the claim.

    Returns:
        A three-segment token. The segments are unpadded, as Entra's are.
    """

    def segment(claims: dict[str, str]) -> str:
        raw = json.dumps(claims).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    payload = {} if scp is None else {"scp": scp}
    return f"{segment({'alg': 'none'})}.{segment(payload)}.signature"


def test_token_scopes_reads_the_scp_claim() -> None:
    token = jwt_with("User.Read Application.Read.All")
    assert token_scopes(token) == {"User.Read", "Application.Read.All"}


def test_token_scopes_is_empty_without_the_claim() -> None:
    assert token_scopes(jwt_with(None)) == set()


def test_missing_scopes_names_what_the_token_lacks() -> None:
    token = jwt_with("User.Read")
    assert missing_scopes(token, ["User.Read", "AuditLog.Read.All"]) == {"AuditLog.Read.All"}


def test_missing_scopes_is_empty_when_the_token_carries_more_than_required() -> None:
    # The baseline is a floor: extra scopes are not a discrepancy.
    token = jwt_with("User.Read AuditLog.Read.All Mail.Read")
    assert missing_scopes(token, ["User.Read"]) == set()
