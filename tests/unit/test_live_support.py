"""Unit tests for the pure helpers in ``tests/live/support.py``.

``restore_baseline`` itself signs in to Entra and edits grants, and is exercised by every live
run. What is tested here are the checks it makes: that a token missing a baseline scope is
caught, and that the tenant-wide grant is what has to carry the baseline. Scopes beyond the
baseline are found in the grants, not the token, so the token check does not report them.
"""

from __future__ import annotations

import base64
import json

import pytest

from tests.http import fake_jwt
from tests.live.support import (
    BASELINE_SCOPES,
    _holds_baseline,
    missing_scopes,
    token_claims,
    token_scopes,
    token_user,
)

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
    # Only what is missing is reported; what is beyond the baseline is read from the grants.
    token = jwt_with("User.Read AuditLog.Read.All Mail.Read")
    assert missing_scopes(token, ["User.Read"]) == set()


def test_token_claims_reads_the_payload() -> None:
    assert token_claims(fake_jwt(tid="t", scp="a b")) == {"tid": "t", "scp": "a b"}


def test_token_user_takes_the_v2_claim_first_and_the_v1_claims_after() -> None:
    assert token_user(fake_jwt(preferred_username="a@x.com", upn="b@x.com")) == "a@x.com"
    assert token_user(fake_jwt(upn="b@x.com")) == "b@x.com"
    assert token_user(fake_jwt(unique_name="c@x.com")) == "c@x.com"
    assert token_user(fake_jwt(sub="nobody")) is None


def test_the_baseline_has_to_be_in_a_tenant_wide_grant() -> None:
    scopes = " ".join(BASELINE_SCOPES)
    assert _holds_baseline([{"consentType": "AllPrincipals", "scope": f"{scopes} Extra"}])
    # A per-user grant covers only its user, not the non-administrator or anyone else.
    assert not _holds_baseline([{"consentType": "Principal", "scope": scopes}])
    assert not _holds_baseline(
        [{"consentType": "AllPrincipals", "scope": " ".join(BASELINE_SCOPES[1:])}]
    )
    assert not _holds_baseline([])
