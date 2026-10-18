"""Leave a visible reminder, where a person will see it, that a token cache sits on disk.

The live tests keep their sign-in in an encrypted cache file that outlives the run, so later
runs need nobody at the desktop. That file holds a refresh token, and it is easy to forget in
a cache directory nobody opens. When ``AZURE_AUTH_TEST_CACHE_REMINDER_PATH`` names a folder,
every live run puts ``AZURE-AUTH_MSAL_CACHE_DELETEME`` there, pointing at the folder that
holds the cache: on Windows an Internet Shortcut (a ``.url`` text file Explorer opens as the
folder), elsewhere a symbolic link. Either holds nothing but a path, so the reminder may sit
in a synced folder such as a Desktop. The cache itself never should.

This is test tooling, not part of the package; nothing collects it.
"""

from __future__ import annotations

import os
from pathlib import Path

REMINDER_NAME = "AZURE-AUTH_MSAL_CACHE_DELETEME"
ENV_VAR = "AZURE_AUTH_TEST_CACHE_REMINDER_PATH"


def configured_folder() -> Path | None:
    """Return the folder ``AZURE_AUTH_TEST_CACHE_REMINDER_PATH`` names, or ``None``.

    Returns:
        The folder, with ``~`` expanded, or ``None`` when the variable is unset or blank.
    """
    value = os.environ.get(ENV_VAR, "").strip()
    return Path(value).expanduser() if value else None


def reminder_path(folder: Path, *, windows: bool = os.name == "nt") -> Path:
    """Return where the reminder goes in ``folder``.

    Args:
        folder: The folder the reminder is placed in.
        windows: Name a ``.url`` file, as on Windows, instead of a symbolic link.

    Returns:
        The reminder's path.
    """
    return folder / (f"{REMINDER_NAME}.url" if windows else REMINDER_NAME)


def place_reminder(cache_file: Path, folder: Path, *, windows: bool = os.name == "nt") -> Path:
    """Put the reminder in ``folder``, pointing at the folder that holds ``cache_file``.

    An existing reminder is replaced, so it always points at the current cache. A real
    directory under the reminder's name is left alone and reported, since removing it could
    take someone's files.

    Args:
        cache_file: The token cache file; it need not exist yet.
        folder: Where the reminder goes; created when missing.
        windows: Write a ``.url`` file, as on Windows, instead of a symbolic link.

    Returns:
        The reminder's path.

    Raises:
        FileExistsError: If a directory, not a reminder, has the reminder's name.
    """
    target = cache_file.resolve().parent
    folder.mkdir(parents=True, exist_ok=True)
    link = reminder_path(folder, windows=windows)
    if link.is_dir() and not link.is_symlink():
        raise FileExistsError(f"{link} is a directory, not a reminder; not replacing it")
    if link.is_symlink() or link.exists():
        link.unlink()
    if windows:
        link.write_text(f"[InternetShortcut]\nURL={target.as_uri()}/\n", encoding="utf-8")
    else:
        link.symlink_to(target, target_is_directory=True)
    return link
