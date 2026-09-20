"""Unit tests for scripts/template_setup/remove_keyvault.py.

The template_setup folder is not a package, so the module is imported by
adding the folder to sys.path, mirroring how the setup scripts import their
shared _common module.

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/remove_keyvault.py and deletes it along with the rest
of the scaffolding, so it never lingers in a project started from the
template.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

import remove_keyvault

_BACKEND = "src/my_project/config/keyvault_backend.py"
_TESTS = "tests/test_keyvault_backend.py"


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
def test_plan_deletions_is_empty_when_the_backend_is_gone(tmp_path: Path) -> None:
    """A project that already removed the backend plans nothing."""
    assert remove_keyvault.plan_deletions(tmp_path) == []


@pytest.mark.unit
def test_plan_deletions_finds_the_backend_and_its_tests(tmp_path: Path) -> None:
    """Backend and test module are planned wherever the package lives under src/."""
    _make_project(tmp_path, _BACKEND, _TESTS)

    deletions = remove_keyvault.plan_deletions(tmp_path)
    assert [path.name for path in deletions] == [
        "keyvault_backend.py",
        "test_keyvault_backend.py",
    ]


@pytest.mark.unit
@pytest.mark.regression
def test_plan_deletions_keeps_the_dispatcher_tests(tmp_path: Path) -> None:
    """secrets.py survives the removal, so its tests must survive it too."""
    _make_project(tmp_path, _BACKEND, "tests/test_config_secrets.py")

    deletions = remove_keyvault.plan_deletions(tmp_path)
    assert [path.name for path in deletions] == ["keyvault_backend.py"]


@pytest.mark.unit
def test_plan_deletions_ignores_other_backends(tmp_path: Path) -> None:
    """The keyring backend is never planned by the Key Vault removal."""
    _make_project(tmp_path, _BACKEND, "src/my_project/config/keyring_backend.py")

    deletions = remove_keyvault.plan_deletions(tmp_path)
    assert [path.name for path in deletions] == ["keyvault_backend.py"]


@pytest.mark.integration
@pytest.mark.functional
def test_run_returns_zero_when_nothing_matches(tmp_path: Path) -> None:
    """A project that never had the backend is a no-op success."""
    assert remove_keyvault.run(tmp_path, assume_yes=True) == 0


@pytest.mark.integration
@pytest.mark.functional
def test_run_dry_run_deletes_nothing(tmp_path: Path) -> None:
    """--dry-run reports the plan and leaves every file in place."""
    paths = _make_project(tmp_path, _BACKEND, _TESTS)

    assert remove_keyvault.run(tmp_path, assume_yes=True, dry_run=True) == 0
    assert all(path.exists() for path in paths)


@pytest.mark.integration
@pytest.mark.functional
def test_run_deletes_the_backend_and_its_tests(tmp_path: Path) -> None:
    """A real run deletes both files and nothing else."""
    backend, tests = _make_project(tmp_path, _BACKEND, _TESTS)
    (keep,) = _make_project(tmp_path, "src/my_project/config/secrets.py")

    assert remove_keyvault.run(tmp_path, assume_yes=True) == 0
    assert not backend.exists()
    assert not tests.exists()
    assert keep.exists()
