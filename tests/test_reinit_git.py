"""Unit and integration tests for scripts/template_setup/reinit_git.py.

The template_setup folder is not a package, so the module is imported by
adding the folder to sys.path, mirroring how the setup scripts import their
shared _common module.

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/reinit_git.py and deletes it along with the rest of
the scaffolding, so it never lingers in a project started from the template.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

import reinit_git

_GIT = shutil.which("git")

# The temp repos these tests commit in must not inherit the developer's
# global/system git config: e.g. a global commit.gpgsign=true fails outright
# in a repo where no signing key resolves.
_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}


def _git(args: list[str], cwd: Path) -> None:
    """Run a git command in *cwd*, failing the test on a non-zero exit."""
    assert _GIT is not None, "git must be on PATH to run this test"
    subprocess.run(  # noqa: S603  (git path resolved via shutil.which)
        [_GIT, *args], cwd=cwd, check=True, capture_output=True, text=True, env=_ENV
    )


def _git_output(args: list[str], cwd: Path) -> str:
    """Run a read-only git command in *cwd* and return its stripped stdout."""
    assert _GIT is not None, "git must be on PATH to run this test"
    result = subprocess.run(  # noqa: S603  (git path resolved via shutil.which)
        [_GIT, *args], cwd=cwd, check=True, capture_output=True, text=True, env=_ENV
    )
    return result.stdout.strip()


def _init_repo_with_one_commit(root: Path) -> tuple[str, str]:
    """Initialize a git repo with a single commit.

    Returns:
        ``(commit_hash, branch_name)`` of the initial commit.
    """
    _git(["init"], root)
    _git(["config", "user.email", "test@example.com"], root)
    _git(["config", "user.name", "Test"], root)
    (root / "file.txt").write_text("content\n", encoding="utf-8")
    _git(["add", "-A"], root)
    _git(["commit", "-m", "Initial commit"], root)
    commit = _git_output(["rev-parse", "HEAD"], root)
    branch = _git_output(["rev-parse", "--abbrev-ref", "HEAD"], root)
    return commit, branch


@pytest.mark.integration
@pytest.mark.functional
def test_is_pristine_template_clone_matches_root_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single-commit repo whose root matches the fingerprint is pristine."""
    commit, _branch = _init_repo_with_one_commit(tmp_path)
    monkeypatch.setattr(reinit_git, "_TEMPLATE_ROOT_COMMIT", commit)
    assert reinit_git._is_pristine_template_clone(tmp_path) is True


@pytest.mark.integration
@pytest.mark.functional
def test_is_pristine_template_clone_hash_mismatch(tmp_path: Path) -> None:
    """A repo whose root commit doesn't match the fingerprint is not pristine."""
    _init_repo_with_one_commit(tmp_path)
    assert reinit_git._is_pristine_template_clone(tmp_path) is False


@pytest.mark.integration
@pytest.mark.functional
def test_is_pristine_template_clone_two_root_commits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """More than one root commit (e.g. an unrelated-history merge) is not pristine."""
    commit, branch = _init_repo_with_one_commit(tmp_path)
    monkeypatch.setattr(reinit_git, "_TEMPLATE_ROOT_COMMIT", commit)

    _git(["checkout", "--orphan", "second-root"], tmp_path)
    _git(["commit", "--allow-empty", "-m", "second root"], tmp_path)
    _git(["checkout", branch], tmp_path)
    _git(["merge", "second-root", "--allow-unrelated-histories", "-m", "merge"], tmp_path)

    assert reinit_git._is_pristine_template_clone(tmp_path) is False


@pytest.mark.unit
def test_is_pristine_template_clone_git_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No git on PATH is treated as not-pristine, not as an error."""
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert reinit_git._is_pristine_template_clone(tmp_path) is False


@pytest.mark.integration
@pytest.mark.functional
def test_run_dry_run_changes_nothing(tmp_path: Path) -> None:
    """A dry run prints the plan but deletes nothing and never re-initializes git."""
    _init_repo_with_one_commit(tmp_path)
    git_dir = tmp_path / ".git"

    assert reinit_git.run(tmp_path, assume_yes=True, dry_run=True) == 0

    assert git_dir.is_dir()
    # The original history is still reachable -- a real reinit would have
    # replaced it with a single fresh, historyless commit.
    log = _git_output(["log", "--oneline"], tmp_path)
    assert "Initial commit" in log
