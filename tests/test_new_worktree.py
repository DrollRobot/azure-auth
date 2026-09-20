"""Unit tests for the pure helpers in scripts/new_worktree.py.

The scripts folder is not a package, so the module is imported by adding the
folder to sys.path, mirroring how the scripts import their shared _cli module.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from new_worktree import find_source_workspace, parse_args, slug_arg

pytestmark = pytest.mark.unit

# --- parse_args ----------------------------------------------------------------------


def test_parse_args_defaults_to_remote_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without --no-remote the worktree forks from origin/<base>."""
    monkeypatch.setattr(sys, "argv", ["new_worktree.py", "issue-42"])
    args = parse_args()
    assert args.slug == "issue-42"
    assert args.base == "develop"
    assert args.no_remote is False


def test_parse_args_accepts_no_remote_with_a_base(monkeypatch: pytest.MonkeyPatch) -> None:
    """--no-remote forks from the local base branch given positionally."""
    monkeypatch.setattr(sys, "argv", ["new_worktree.py", "issue-42", "trunk", "--no-remote"])
    args = parse_args()
    assert args.base == "trunk"
    assert args.no_remote is True


def test_parse_args_no_remote_is_independent_of_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two skip flags do not imply one another."""
    monkeypatch.setattr(sys, "argv", ["new_worktree.py", "issue-42", "--no-remote"])
    args = parse_args()
    assert args.no_remote is True
    assert args.no_bootstrap is False


def test_parse_args_rejects_a_bad_slug(monkeypatch: pytest.MonkeyPatch) -> None:
    """Slug validation still applies with the new flag present."""
    monkeypatch.setattr(sys, "argv", ["new_worktree.py", "bad slug", "--no-remote"])
    with pytest.raises(SystemExit):
        parse_args()


# --- slug_arg ------------------------------------------------------------------------


def test_slug_arg_accepts_plain_slug() -> None:
    """A simple slug passes through unchanged."""
    assert slug_arg("issue-42") == "issue-42"


def test_slug_arg_accepts_internal_slash() -> None:
    """Slashes are allowed inside the slug (e.g. fix/login)."""
    assert slug_arg("fix/login") == "fix/login"


@pytest.mark.parametrize("bad", ["a b", "..", "a..b", "/lead", "trail/", "a//b"])
def test_slug_arg_rejects_bad_slugs(bad: str) -> None:
    """Characters and shapes that would break a branch or path name are refused."""
    with pytest.raises(argparse.ArgumentTypeError):
        slug_arg(bad)


# --- find_source_workspace -----------------------------------------------------------


def test_find_source_workspace_prefers_the_first_directory(tmp_path: Path) -> None:
    """Search order decides: the worktree's own workspace wins over the repo's."""
    first = tmp_path / "wt"
    second = tmp_path / "repo"
    first.mkdir()
    second.mkdir()
    (first / "a.code-workspace").write_text("{}", encoding="utf-8")
    (second / "b.code-workspace").write_text("{}", encoding="utf-8")
    assert find_source_workspace([first, second], "target.code-workspace") == (
        first / "a.code-workspace"
    )


def test_find_source_workspace_skips_the_target_file(tmp_path: Path) -> None:
    """The file being generated is never used as its own template."""
    (tmp_path / "target.code-workspace").write_text("{}", encoding="utf-8")
    assert find_source_workspace([tmp_path], "target.code-workspace") is None


def test_find_source_workspace_none_when_empty(tmp_path: Path) -> None:
    """No workspace anywhere means the caller generates a minimal one."""
    assert find_source_workspace([tmp_path], "target.code-workspace") is None
