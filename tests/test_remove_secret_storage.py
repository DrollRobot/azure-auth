"""Unit tests for scripts/template_setup/remove_secret_storage.py.

The template_setup folder is not a package, so the module is imported by
adding the folder to sys.path, mirroring how the setup scripts import their
shared _common module.

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/remove_secret_storage.py and deletes it along with the
rest of the scaffolding, so it never lingers in a project started from the
template.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

import remove_secret_storage

_DISPATCHER = "src/my_project/config/secrets.py"
_KEYRING = "src/my_project/config/keyring_backend.py"
_KEYVAULT = "src/my_project/config/keyvault_backend.py"
_TESTS = [
    "tests/test_config_secrets.py",
    "tests/test_keyring_backend.py",
    "tests/test_keyvault_backend.py",
]


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
def test_plan_deletions_is_empty_when_the_machinery_is_gone(tmp_path: Path) -> None:
    """A project that already removed the machinery plans nothing."""
    assert remove_secret_storage.plan_deletions(tmp_path) == []


@pytest.mark.unit
def test_plan_deletions_finds_dispatcher_backends_and_tests(tmp_path: Path) -> None:
    """Dispatcher, every backend, and their tests are planned together."""
    _make_project(tmp_path, _DISPATCHER, _KEYRING, _KEYVAULT, *_TESTS)

    deletions = remove_secret_storage.plan_deletions(tmp_path)
    assert [path.name for path in deletions] == [
        "secrets.py",
        "keyring_backend.py",
        "keyvault_backend.py",
        "test_config_secrets.py",
        "test_keyring_backend.py",
        "test_keyvault_backend.py",
    ]


@pytest.mark.unit
def test_plan_deletions_catches_project_added_backends(tmp_path: Path) -> None:
    """A backend added downstream matches the *_backend.py glob and goes too."""
    _make_project(tmp_path, _DISPATCHER, "src/my_project/config/custom_backend.py")

    deletions = remove_secret_storage.plan_deletions(tmp_path)
    assert [path.name for path in deletions] == ["secrets.py", "custom_backend.py"]


@pytest.mark.unit
def test_plan_deletions_keeps_the_rest_of_the_config_package(tmp_path: Path) -> None:
    """The core config modules and their tests are never planned."""
    _make_project(
        tmp_path,
        _DISPATCHER,
        "src/my_project/config/resolve.py",
        "src/my_project/config/file.py",
        "tests/test_config_resolve.py",
    )

    deletions = remove_secret_storage.plan_deletions(tmp_path)
    assert [path.name for path in deletions] == ["secrets.py"]


@pytest.mark.integration
@pytest.mark.functional
def test_run_returns_zero_when_nothing_matches(tmp_path: Path) -> None:
    """A project that never had the machinery is a no-op success."""
    assert remove_secret_storage.run(tmp_path, assume_yes=True) == 0


@pytest.mark.integration
@pytest.mark.functional
def test_run_dry_run_deletes_nothing(tmp_path: Path) -> None:
    """--dry-run reports the plan and leaves every file in place."""
    paths = _make_project(tmp_path, _DISPATCHER, _KEYRING, *_TESTS)

    assert remove_secret_storage.run(tmp_path, assume_yes=True, dry_run=True) == 0
    assert all(path.exists() for path in paths)


@pytest.mark.integration
@pytest.mark.functional
def test_run_deletes_the_machinery_and_nothing_else(tmp_path: Path) -> None:
    """A real run deletes the machinery files and leaves the core modules."""
    doomed = _make_project(tmp_path, _DISPATCHER, _KEYRING, _KEYVAULT, *_TESTS)
    (keep,) = _make_project(tmp_path, "src/my_project/config/resolve.py")

    assert remove_secret_storage.run(tmp_path, assume_yes=True) == 0
    assert not any(path.exists() for path in doomed)
    assert keep.exists()
