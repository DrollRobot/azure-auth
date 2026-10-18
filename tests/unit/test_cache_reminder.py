"""Unit tests for the reminder the live tests leave about their token cache on disk."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests import cache_reminder

pytestmark = [pytest.mark.unit]

needs_symlinks = pytest.mark.skipif(
    os.name == "nt", reason="creating a symbolic link on Windows needs a privilege"
)


def test_the_windows_reminder_is_a_url_file_opening_the_cache_folder(tmp_path: Path) -> None:
    cache_file = tmp_path / "cache" / "live_tests_token_cache.bin"
    folder = tmp_path / "desktop"

    link = cache_reminder.place_reminder(cache_file, folder, windows=True)

    assert link == folder / "AZURE-AUTH_MSAL_CACHE_DELETEME.url"
    text = link.read_text(encoding="utf-8")
    assert text.startswith("[InternetShortcut]\n")
    assert f"URL={cache_file.parent.resolve().as_uri()}/" in text


@needs_symlinks
def test_the_posix_reminder_is_a_symlink_to_the_cache_folder(tmp_path: Path) -> None:
    cache_file = tmp_path / "cache" / "live_tests_token_cache.bin"
    cache_file.parent.mkdir()
    folder = tmp_path / "desktop"

    link = cache_reminder.place_reminder(cache_file, folder, windows=False)

    assert link == folder / "AZURE-AUTH_MSAL_CACHE_DELETEME"
    assert link.is_symlink()
    assert link.resolve() == cache_file.parent.resolve()


def test_the_folder_is_created_when_missing(tmp_path: Path) -> None:
    folder = tmp_path / "not" / "yet" / "there"
    link = cache_reminder.place_reminder(tmp_path / "c.bin", folder, windows=True)
    assert link.parent == folder
    assert link.is_file()


def test_an_existing_reminder_is_replaced(tmp_path: Path) -> None:
    folder = tmp_path / "desktop"
    old_cache = tmp_path / "old" / "c.bin"
    new_cache = tmp_path / "new" / "c.bin"
    cache_reminder.place_reminder(old_cache, folder, windows=True)

    link = cache_reminder.place_reminder(new_cache, folder, windows=True)

    text = link.read_text(encoding="utf-8")
    assert new_cache.parent.resolve().as_uri() in text
    assert old_cache.parent.resolve().as_uri() not in text


def test_a_directory_with_the_reminders_name_is_left_alone(tmp_path: Path) -> None:
    folder = tmp_path / "desktop"
    in_the_way = cache_reminder.reminder_path(folder, windows=True)
    in_the_way.mkdir(parents=True)
    (in_the_way / "somebodys-file.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError, match="not replacing"):
        cache_reminder.place_reminder(tmp_path / "c.bin", folder, windows=True)

    assert (in_the_way / "somebodys-file.txt").read_text(encoding="utf-8") == "keep"


def test_the_reminder_path_differs_by_platform(tmp_path: Path) -> None:
    assert cache_reminder.reminder_path(tmp_path, windows=True).name.endswith(".url")
    assert cache_reminder.reminder_path(tmp_path, windows=False).name == (
        "AZURE-AUTH_MSAL_CACHE_DELETEME"
    )


def test_the_configured_folder_comes_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(cache_reminder.ENV_VAR, raising=False)
    assert cache_reminder.configured_folder() is None

    monkeypatch.setenv(cache_reminder.ENV_VAR, "   ")
    assert cache_reminder.configured_folder() is None

    monkeypatch.setenv(cache_reminder.ENV_VAR, str(tmp_path))
    assert cache_reminder.configured_folder() == tmp_path
