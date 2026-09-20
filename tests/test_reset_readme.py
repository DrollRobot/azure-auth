"""Unit tests for scripts/template_setup/reset_readme.py.

The template_setup folder is not a package, so the module is imported by adding
the folder to sys.path, mirroring how the setup scripts import their shared
_common module (and how test_reset_changelog.py imports reset_changelog).

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/reset_readme.py and deletes it along with the rest of
the scaffolding, so it never lingers in a project started from the template.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

import reset_readme

pytestmark = [pytest.mark.integration, pytest.mark.functional]

SKELETON = "# azure-auth\n\n<!-- FIXME: what this package does -->\n"
TEMPLATE_README = "# azure-auth\n\n## Making a new repo from this template\n"


def _write(root: Path, name: str, text: str) -> None:
    (root / name).write_text(text, encoding="utf-8")


def test_run_replaces_template_readme_with_skeleton(tmp_path: Path) -> None:
    """The template's own README is replaced by the skeleton and the .FIXME removed."""
    _write(tmp_path, "README.md", TEMPLATE_README)
    _write(tmp_path, "README.md.FIXME", SKELETON)

    assert reset_readme.run(tmp_path, assume_yes=True) == 0
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == SKELETON
    assert not (tmp_path / "README.md.FIXME").exists()


def test_run_works_without_existing_readme(tmp_path: Path) -> None:
    """A missing README.md is fine; the skeleton is still written into place."""
    _write(tmp_path, "README.md.FIXME", SKELETON)

    assert reset_readme.run(tmp_path, assume_yes=True) == 0
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == SKELETON
    assert not (tmp_path / "README.md.FIXME").exists()


def test_run_aborts_when_skeleton_missing(tmp_path: Path) -> None:
    """With no .FIXME skeleton there is nothing to do; README.md is left alone.

    This is the idempotency guard: a second run must not touch a README the
    project has already rewritten.
    """
    project_readme = "# my-project\n\nAlready rewritten by hand.\n"
    _write(tmp_path, "README.md", project_readme)

    assert reset_readme.run(tmp_path, assume_yes=True) == 1
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == project_readme


def test_dry_run_changes_nothing(tmp_path: Path) -> None:
    """A dry run reports the plan but leaves both files untouched."""
    _write(tmp_path, "README.md", TEMPLATE_README)
    _write(tmp_path, "README.md.FIXME", SKELETON)

    assert reset_readme.run(tmp_path, assume_yes=True, dry_run=True) == 0
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == TEMPLATE_README
    assert (tmp_path / "README.md.FIXME").read_text(encoding="utf-8") == SKELETON
