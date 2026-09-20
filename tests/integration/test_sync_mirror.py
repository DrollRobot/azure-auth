"""The generated blocking clients must match what the generator produces today."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.functional]

_ROOT = Path(__file__).resolve().parents[2]


def test_sync_mirror_is_up_to_date() -> None:
    result = subprocess.run(  # noqa: S603 (fixed argv list, no shell)
        [sys.executable, str(_ROOT / "scripts" / "generate_sync.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
        cwd=_ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr
