"""Unit tests for scripts/template_setup/reset_changelog.py.

The template_setup folder is not a package, so the module is imported by adding
the folder to sys.path, mirroring how the setup scripts import their shared
_common module (and how test_set_python_version.py imports set_python_version).

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/reset_changelog.py and deletes it along with the rest of
the scaffolding, so it never lingers in a project started from the template.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

import reset_changelog

pytestmark = [pytest.mark.integration, pytest.mark.functional]

SKELETON = "# Changelog\n\n## [Unreleased]\n"
OLD_HISTORY = "# Changelog\n\n## [9.9.9] - 2000-01-01\n"


def _write(root: Path, name: str, text: str) -> None:
    (root / name).write_text(text, encoding="utf-8")


def test_run_replaces_history_with_skeleton(tmp_path: Path) -> None:
    """The template's history is replaced by the skeleton and the .FIXME removed."""
    _write(tmp_path, "CHANGELOG.md", OLD_HISTORY)
    _write(tmp_path, "CHANGELOG.md.FIXME", SKELETON)

    assert reset_changelog.run(tmp_path, assume_yes=True) == 0
    assert (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8") == SKELETON
    assert not (tmp_path / "CHANGELOG.md.FIXME").exists()


def test_run_works_without_existing_changelog(tmp_path: Path) -> None:
    """A missing CHANGELOG.md is fine; the skeleton is still written into place."""
    _write(tmp_path, "CHANGELOG.md.FIXME", SKELETON)

    assert reset_changelog.run(tmp_path, assume_yes=True) == 0
    assert (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8") == SKELETON
    assert not (tmp_path / "CHANGELOG.md.FIXME").exists()


def test_run_aborts_when_skeleton_missing(tmp_path: Path) -> None:
    """With no .FIXME skeleton there is nothing to do; CHANGELOG.md is left alone."""
    _write(tmp_path, "CHANGELOG.md", OLD_HISTORY)

    assert reset_changelog.run(tmp_path, assume_yes=True) == 1
    assert (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8") == OLD_HISTORY


def test_dry_run_changes_nothing(tmp_path: Path) -> None:
    """A dry run reports the plan but leaves both files untouched."""
    _write(tmp_path, "CHANGELOG.md", OLD_HISTORY)
    _write(tmp_path, "CHANGELOG.md.FIXME", SKELETON)

    assert reset_changelog.run(tmp_path, assume_yes=True, dry_run=True) == 0
    assert (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8") == OLD_HISTORY
    assert (tmp_path / "CHANGELOG.md.FIXME").read_text(encoding="utf-8") == SKELETON
