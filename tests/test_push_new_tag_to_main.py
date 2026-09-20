"""Unit tests for the command line of scripts/push_new_tag_to_main.py.

The scripts folder is not a package, so the module is imported by adding the
folder to sys.path, mirroring how the scripts import their shared _cli module.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from push_new_tag_to_main import parse_args

pytestmark = pytest.mark.unit

# --- parse_args ----------------------------------------------------------------------


def test_parse_args_defaults_to_remote_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without --no-remote the release flow talks to origin."""
    monkeypatch.setattr(sys, "argv", ["push_new_tag_to_main.py", "patch"])
    args = parse_args()
    assert args.bump == "patch"
    assert args.no_remote is False


def test_parse_args_accepts_no_remote_with_a_bump(monkeypatch: pytest.MonkeyPatch) -> None:
    """--no-remote is independent of how the version is chosen."""
    monkeypatch.setattr(sys, "argv", ["push_new_tag_to_main.py", "minor", "--no-remote"])
    args = parse_args()
    assert args.bump == "minor"
    assert args.no_remote is True


def test_parse_args_accepts_no_remote_with_no_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """--no-remote combines with --no-version for a purely local merge."""
    monkeypatch.setattr(sys, "argv", ["push_new_tag_to_main.py", "--no-version", "--no-remote"])
    args = parse_args()
    assert args.no_version is True
    assert args.no_remote is True


def test_parse_args_rejects_no_version_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    """--no-remote alone is not a version selection; the script still needs one."""
    monkeypatch.setattr(sys, "argv", ["push_new_tag_to_main.py", "--no-remote"])
    with pytest.raises(SystemExit):
        parse_args()


def test_parse_args_rejects_two_version_selections(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bump level and --version are mutually exclusive."""
    monkeypatch.setattr(sys, "argv", ["push_new_tag_to_main.py", "patch", "--version", "1.2.3"])
    with pytest.raises(SystemExit):
        parse_args()


def test_parse_args_rejects_malformed_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """--version must look like X.Y.Z."""
    monkeypatch.setattr(sys, "argv", ["push_new_tag_to_main.py", "--version", "v2"])
    with pytest.raises(SystemExit):
        parse_args()
