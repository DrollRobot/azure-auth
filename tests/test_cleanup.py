"""Unit tests for the pure helpers in scripts/template_setup/cleanup.py.

The template_setup folder is not a package, so the module is imported by
adding the folder to sys.path, mirroring how the setup scripts import their
shared _common module.

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/cleanup.py and deletes it along with the rest of the
scaffolding, so it never lingers in a project started from the template.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

from cleanup import dev_script_tests, strip_template_config

pytestmark = pytest.mark.unit

# A pyproject.toml slice holding both template-only lines cleanup removes,
# surrounded by neighbors that must survive untouched.
PYPROJECT = (
    "addopts = [\n"
    '    "--cov=azure_auth",\n'
    '    "--cov=scripts",\n'
    '    "--cov-report=term-missing",\n'
    "]\n"
    "\n"
    "[tool.mypy]\n"
    'files = ["src", "tests", "scripts"]\n'
    'mypy_path = ["scripts", "scripts/template_setup"]\n'
)


def touch(root: Path, relative: str) -> Path:
    """Create an empty file (and its parents) under ``root``."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    return path


def test_test_matching_dev_script_is_selected(tmp_path: Path) -> None:
    """A test named after a script in scripts/ is selected for deletion."""
    touch(tmp_path, "scripts/remove_worktree.py")
    test_file = touch(tmp_path, "tests/test_remove_worktree.py")
    assert dev_script_tests(tmp_path) == [test_file]


def test_test_matching_setup_script_is_selected(tmp_path: Path) -> None:
    """A test named after a script in scripts/template_setup/ is selected too."""
    touch(tmp_path, "scripts/template_setup/cleanup.py")
    test_file = touch(tmp_path, "tests/test_cleanup.py")
    assert dev_script_tests(tmp_path) == [test_file]


def test_project_tests_are_kept(tmp_path: Path) -> None:
    """A test with no matching script is the project's own and is not selected."""
    touch(tmp_path, "scripts/remove_worktree.py")
    touch(tmp_path, "tests/test_unwanted_strings.py")
    assert dev_script_tests(tmp_path) == []


def test_scripts_themselves_are_never_selected(tmp_path: Path) -> None:
    """Only files under tests/ are selected; the scripts stay."""
    touch(tmp_path, "scripts/remove_worktree.py")
    touch(tmp_path, "tests/test_remove_worktree.py")
    selected = dev_script_tests(tmp_path)
    assert all(path.parent == tmp_path / "tests" for path in selected)


def test_results_are_sorted(tmp_path: Path) -> None:
    """Multiple matches come back in sorted order for stable output."""
    touch(tmp_path, "scripts/remove_worktree.py")
    touch(tmp_path, "scripts/complete_worktree.py")
    second = touch(tmp_path, "tests/test_remove_worktree.py")
    first = touch(tmp_path, "tests/test_complete_worktree.py")
    assert dev_script_tests(tmp_path) == [first, second]


def test_missing_tests_folder_yields_nothing(tmp_path: Path) -> None:
    """A project without a tests/ folder has nothing to select."""
    touch(tmp_path, "scripts/remove_worktree.py")
    assert dev_script_tests(tmp_path) == []


def test_strip_removes_scripts_coverage_line() -> None:
    """The --cov=scripts line vanishes without leaving a blank line behind."""
    result = strip_template_config(PYPROJECT)
    assert "--cov=scripts" not in result
    assert '    "--cov=azure_auth",\n    "--cov-report=term-missing",\n' in result


def test_strip_narrows_mypy_path() -> None:
    """The template_setup entry is dropped; scripts stays on the search path."""
    result = strip_template_config(PYPROJECT)
    assert 'mypy_path = ["scripts"]\n' in result
    assert "template_setup" not in result


def test_strip_narrows_mypy_files_to_the_project() -> None:
    """The template's own scripts drop out of mypy's files."""
    result = strip_template_config(PYPROJECT)
    assert 'files = ["src", "tests"]\n' in result


def test_strip_keeps_unrelated_lines() -> None:
    """Neighboring config lines survive the edit byte-for-byte."""
    result = strip_template_config(PYPROJECT)
    assert "[tool.mypy]\n" in result
    assert '    "--cov=azure_auth",\n' in result


def test_strip_rejects_drifted_pyproject() -> None:
    """A missing snippet aborts loudly instead of silently skipping the edit."""
    drifted = PYPROJECT.replace('    "--cov=scripts",\n', "")
    with pytest.raises(ValueError, match="drifted"):
        strip_template_config(drifted)
