"""Unit tests for scripts/template_setup/remove_remote_disposable_scripts.py.

The template_setup folder is not a package, so the module is imported by
adding the folder to sys.path, mirroring how the setup scripts import their
shared _common module.

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/remove_remote_disposable_scripts.py and deletes it
along with the rest of the scaffolding, so it never lingers in a project
started from the template.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

import remove_remote_disposable_scripts


def _make_project(root: Path, *relpaths: str) -> list[Path]:
    """Create the named files under ``root`` and return their paths."""
    paths: list[Path] = []
    for relpath in relpaths:
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("stub\n", encoding="utf-8")
        paths.append(path)
    return paths


@pytest.mark.unit
def test_plan_deletions_lists_only_existing_files(tmp_path: Path) -> None:
    """Files that are already gone are not planned for deletion."""
    _make_project(tmp_path, "scripts/mark_remote_disposable.py")

    deletions = remove_remote_disposable_scripts.plan_deletions(tmp_path)
    assert [path.name for path in deletions] == ["mark_remote_disposable.py"]


@pytest.mark.unit
def test_plan_deletions_covers_both_halves_and_the_orphaned_test(tmp_path: Path) -> None:
    """The write half, the read half, and the read half's unit test are all planned."""
    _make_project(
        tmp_path,
        "scripts/mark_remote_disposable.py",
        "tests/verify_remote_disposable.py",
        "tests/test_verify_remote_disposable.py",
    )

    deletions = remove_remote_disposable_scripts.plan_deletions(tmp_path)
    assert [str(path.relative_to(tmp_path).as_posix()) for path in deletions] == [
        "scripts/mark_remote_disposable.py",
        "tests/verify_remote_disposable.py",
        "tests/test_verify_remote_disposable.py",
    ]


@pytest.mark.integration
@pytest.mark.functional
def test_run_returns_zero_when_nothing_matches(tmp_path: Path) -> None:
    """A project that never had the scripts is a no-op success."""
    assert remove_remote_disposable_scripts.run(tmp_path, assume_yes=True) == 0


@pytest.mark.integration
@pytest.mark.functional
def test_run_dry_run_deletes_nothing(tmp_path: Path) -> None:
    """A dry run leaves every file in place."""
    paths = _make_project(
        tmp_path, "scripts/mark_remote_disposable.py", "tests/verify_remote_disposable.py"
    )

    assert remove_remote_disposable_scripts.run(tmp_path, assume_yes=True, dry_run=True) == 0
    assert all(path.exists() for path in paths)


@pytest.mark.integration
@pytest.mark.functional
def test_run_deletes_every_planned_file(tmp_path: Path) -> None:
    """A real run deletes both halves and the orphaned unit test."""
    paths = _make_project(
        tmp_path,
        "scripts/mark_remote_disposable.py",
        "tests/verify_remote_disposable.py",
        "tests/test_verify_remote_disposable.py",
    )

    assert remove_remote_disposable_scripts.run(tmp_path, assume_yes=True) == 0
    assert not any(path.exists() for path in paths)


@pytest.mark.integration
@pytest.mark.functional
def test_run_leaves_unrelated_files_alone(tmp_path: Path) -> None:
    """Only the feature's own files are touched."""
    _make_project(tmp_path, "scripts/mark_remote_disposable.py")
    (kept,) = _make_project(tmp_path, "tests/conftest.py")

    assert remove_remote_disposable_scripts.run(tmp_path, assume_yes=True) == 0
    assert kept.exists()
