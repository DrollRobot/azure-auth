"""Unit tests for scripts/template_setup/remove_contributing_guide.py.

The template_setup folder is not a package, so the module is imported by
adding the folder to sys.path, mirroring how the setup scripts import their
shared _common module.

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/remove_contributing_guide.py and deletes it along with
the rest of the scaffolding, so it never lingers in a project started from the
template.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

import remove_contributing_guide
import remove_mkdocs


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
def test_plan_deletions_is_empty_when_the_file_is_gone(tmp_path: Path) -> None:
    """A project that already removed CONTRIBUTING.md plans nothing."""
    assert remove_contributing_guide.plan_deletions(tmp_path) == []


@pytest.mark.unit
def test_plan_deletions_finds_the_contributor_guide(tmp_path: Path) -> None:
    """The guide is planned for deletion when it exists."""
    _make_project(tmp_path, "CONTRIBUTING.md")

    deletions = remove_contributing_guide.plan_deletions(tmp_path)
    assert [path.name for path in deletions] == ["CONTRIBUTING.md"]


@pytest.mark.integration
@pytest.mark.functional
def test_run_returns_zero_when_nothing_matches(tmp_path: Path) -> None:
    """A project that never had the file is a no-op success."""
    assert remove_contributing_guide.run(tmp_path, assume_yes=True) == 0


@pytest.mark.integration
@pytest.mark.functional
def test_run_dry_run_deletes_nothing(tmp_path: Path) -> None:
    """A dry run leaves the file in place."""
    (path,) = _make_project(tmp_path, "CONTRIBUTING.md")

    assert remove_contributing_guide.run(tmp_path, assume_yes=True, dry_run=True) == 0
    assert path.exists()


@pytest.mark.integration
@pytest.mark.functional
def test_run_deletes_the_contributor_guide(tmp_path: Path) -> None:
    """A real run deletes CONTRIBUTING.md."""
    (path,) = _make_project(tmp_path, "CONTRIBUTING.md")

    assert remove_contributing_guide.run(tmp_path, assume_yes=True) == 0
    assert not path.exists()


@pytest.mark.integration
@pytest.mark.functional
def test_run_leaves_unrelated_files_alone(tmp_path: Path) -> None:
    """Only the feature's own file is touched."""
    _make_project(tmp_path, "CONTRIBUTING.md")
    (kept,) = _make_project(tmp_path, "SECURITY.md")

    assert remove_contributing_guide.run(tmp_path, assume_yes=True) == 0
    assert kept.exists()


@pytest.mark.integration
@pytest.mark.functional
def test_remove_mkdocs_tolerates_the_deleted_guide(tmp_path: Path) -> None:
    """Dropping both features in either order is safe: mkdocs skips the missing file."""
    _make_project(tmp_path, "CONTRIBUTING.md")

    assert remove_contributing_guide.run(tmp_path, assume_yes=True) == 0
    assert [path for path, _new, _removed in remove_mkdocs.plan_edits(tmp_path)] == []
