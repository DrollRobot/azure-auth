"""Unit tests for scripts/template_setup/set_version.py.

The template_setup folder is not a package, so the module is imported by adding
the folder to sys.path, mirroring how the setup scripts import their shared
_common module (and how test_set_python_version.py imports set_python_version).

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/set_version.py and deletes it along with the rest of the
scaffolding, so it never lingers in a project started from the template.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

import set_version

# A pyproject.toml slice that includes the two trap lines also containing the
# word "version": ruff's target-version and mypy's python_version.
PYPROJECT = (
    "[project]\n"
    'name = "demo"\n'
    'version = "1.4.0"\n'
    'requires-python = ">=3.14"\n'
    "\n"
    "[tool.ruff]\n"
    'target-version = "py314"\n'
    "\n"
    "[tool.mypy]\n"
    'python_version = "3.14"\n'
)


@pytest.mark.unit
def test_validate_accepts_valid() -> None:
    """A MAJOR.MINOR.PATCH version (with optional suffix) is returned cleaned."""
    assert set_version.validate("0.1.0") == "0.1.0"
    assert set_version.validate("1.0.0rc1") == "1.0.0rc1"
    assert set_version.validate("  2.3.4  ") == "2.3.4"


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["1", "1.0", "abc", "", "py314"])
def test_validate_rejects_invalid(bad: str) -> None:
    """Anything that is not MAJOR.MINOR.PATCH raises ValueError."""
    with pytest.raises(ValueError, match="not a valid version"):
        set_version.validate(bad)


@pytest.mark.unit
def test_set_version_touches_only_project_version() -> None:
    """Only the [project] version line changes; the trap lines are untouched."""
    result = set_version.set_version(PYPROJECT, "0.1.0")
    assert 'version = "0.1.0"' in result
    assert '"1.4.0"' not in result
    # The look-alike fields must survive unchanged.
    assert 'target-version = "py314"' in result
    assert 'python_version = "3.14"' in result


@pytest.mark.integration
@pytest.mark.functional
def test_run_updates_pyproject(tmp_path: Path) -> None:
    """Running the step rewrites the version in pyproject.toml."""
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    assert set_version.run(tmp_path, "0.1.0", assume_yes=True) == 0

    pyproject = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "0.1.0"' in pyproject
    assert 'target-version = "py314"' in pyproject


@pytest.mark.integration
@pytest.mark.functional
def test_run_is_idempotent(tmp_path: Path) -> None:
    """Re-running with the version already in place reports nothing to change."""
    path = tmp_path / "pyproject.toml"
    path.write_text(PYPROJECT, encoding="utf-8")
    set_version.run(tmp_path, "0.1.0", assume_yes=True)
    after_first = path.read_text(encoding="utf-8")

    assert set_version.run(tmp_path, "0.1.0", assume_yes=True) == 0
    assert path.read_text(encoding="utf-8") == after_first


@pytest.mark.integration
@pytest.mark.functional
def test_dry_run_changes_nothing(tmp_path: Path) -> None:
    """A dry run reports the plan but leaves pyproject.toml untouched."""
    path = tmp_path / "pyproject.toml"
    path.write_text(PYPROJECT, encoding="utf-8")
    assert set_version.run(tmp_path, "0.1.0", assume_yes=True, dry_run=True) == 0
    assert path.read_text(encoding="utf-8") == PYPROJECT


@pytest.mark.integration
@pytest.mark.functional
def test_run_rejects_invalid_version(tmp_path: Path) -> None:
    """An invalid version raises before pyproject.toml is read or written."""
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    with pytest.raises(ValueError, match="not a valid version"):
        set_version.run(tmp_path, "nope", assume_yes=True)
