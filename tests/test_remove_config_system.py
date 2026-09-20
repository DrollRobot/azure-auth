"""Unit tests for scripts/template_setup/remove_config_system.py.

The template_setup folder is not a package, so the module is imported by
adding the folder to sys.path, mirroring how the setup scripts import their
shared _common module.

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/remove_config_system.py and deletes it along with the
rest of the scaffolding, so it never lingers in a project started from the
template.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

import remove_config_system

_PACKAGE_FILES = (
    "src/my_project/config/__init__.py",
    "src/my_project/config/schema.py",
    "src/my_project/config/keyring_backend.py",
)
_TEST_FILES = (
    "tests/_config_test_object.py",
    "tests/test_config_cli.py",
    "tests/test_config_secrets.py",
)


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
def test_plan_deletions_is_empty_when_the_package_is_gone(tmp_path: Path) -> None:
    """A project that already removed the config system plans nothing."""
    assert remove_config_system.plan_deletions(tmp_path) == []


@pytest.mark.unit
def test_plan_deletions_finds_the_package_dir_and_tests(tmp_path: Path) -> None:
    """The package directory and every config test are planned together."""
    _make_project(tmp_path, *_PACKAGE_FILES, *_TEST_FILES)

    deletions = remove_config_system.plan_deletions(tmp_path)
    names = [path.name for path in deletions]
    assert names == [
        "config",
        "test_config_cli.py",
        "test_config_secrets.py",
        "_config_test_object.py",
    ]
    assert deletions[0].is_dir()


@pytest.mark.integration
@pytest.mark.functional
def test_run_returns_zero_when_nothing_matches(tmp_path: Path) -> None:
    """A project that never had the config system is a no-op success."""
    assert remove_config_system.run(tmp_path, assume_yes=True) == 0


@pytest.mark.integration
@pytest.mark.functional
def test_run_dry_run_deletes_nothing(tmp_path: Path) -> None:
    """--dry-run reports the plan and leaves every path in place."""
    paths = _make_project(tmp_path, *_PACKAGE_FILES, *_TEST_FILES)

    assert remove_config_system.run(tmp_path, assume_yes=True, dry_run=True) == 0
    assert all(path.exists() for path in paths)


@pytest.mark.integration
@pytest.mark.functional
def test_run_deletes_the_package_and_tests_but_keeps_the_rest(tmp_path: Path) -> None:
    """A real run deletes the whole package directory (backends included) and
    every config test, leaving the rest of the project alone."""
    paths = _make_project(tmp_path, *_PACKAGE_FILES, *_TEST_FILES)
    keep = _make_project(tmp_path, "src/my_project/main.py", "tests/conftest.py")

    assert remove_config_system.run(tmp_path, assume_yes=True) == 0
    assert not (tmp_path / "src/my_project/config").exists()
    assert all(not path.exists() for path in paths)
    assert all(path.exists() for path in keep)
