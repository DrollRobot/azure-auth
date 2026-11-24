"""The launcher the unanswered sign-in test starts its browser with, and its clean-up.

``tests/live/headless_browser.py`` is run by this Python with a stand-in browser: this Python
again, which starts a helper process of its own, as a browser does, and then waits.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.live import headless_browser

pytestmark = [pytest.mark.integration]

# The stand-in browser. It records its helper's process id the way the launcher records its
# own, written whole and then renamed, and outlives any test that does not close it.
STAND_IN = """
import pathlib, subprocess, sys, time
helper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
partial = pathlib.Path(sys.argv[1] + ".partial")
partial.write_text(str(helper.pid), encoding="ascii")
partial.replace(sys.argv[1])
time.sleep(120)
"""
# Long enough for a busy machine to start two Python processes, or to end them.
WAIT_SECONDS = 30


def alive(pid: int) -> bool:
    """Tell whether a process is still running.

    Args:
        pid: The process id.

    Returns:
        ``True`` while the process runs.
    """
    if sys.platform == "win32":
        tasklist = shutil.which("tasklist")
        assert tasklist is not None
        listing = subprocess.run(  # noqa: S603 (tasklist path from shutil.which, fixed arguments)
            [tasklist, "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return f'"{pid}"' in listing
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def ended(pid: int) -> bool:
    """Wait for a process to end.

    Args:
        pid: The process id.

    Returns:
        ``True`` once it has ended; ``False`` if it still runs after ``WAIT_SECONDS``.
    """
    deadline = time.monotonic() + WAIT_SECONDS
    while alive(pid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)
    return True


def test_close_ends_the_recorded_browser_and_the_processes_it_started(tmp_path: Path) -> None:
    pid_file = tmp_path / "browser.pid"
    helper_file = tmp_path / "helper.pid"
    subprocess.run(  # noqa: S603 (fixed interpreter and arguments)
        [
            sys.executable,
            "-I",
            headless_browser.__file__,
            "--pid-file",
            str(pid_file),
            sys.executable,
            "-c",
            STAND_IN,
            str(helper_file),
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        ],
        check=True,
        timeout=WAIT_SECONDS,
    )
    # The launcher has exited, so its file is already there.
    browser = headless_browser.read_pid(pid_file, wait_seconds=0)
    assert browser is not None
    try:
        helper = headless_browser.read_pid(helper_file, wait_seconds=WAIT_SECONDS)
        assert helper is not None
        assert alive(browser)
        assert alive(helper)

        headless_browser.close(browser)

        assert ended(browser)
        assert ended(helper)
    finally:
        headless_browser.close(browser)


def test_a_browser_that_was_never_started_has_no_process_id(tmp_path: Path) -> None:
    assert headless_browser.read_pid(tmp_path / "browser.pid", wait_seconds=0) is None


def test_closing_a_browser_that_has_already_exited_is_not_an_error(tmp_path: Path) -> None:
    pid_file = tmp_path / "browser.pid"
    subprocess.run(  # noqa: S603 (fixed interpreter and arguments)
        [
            sys.executable,
            "-I",
            headless_browser.__file__,
            "--pid-file",
            str(pid_file),
            sys.executable,
            "-c",
            "pass",
        ],
        check=True,
        timeout=WAIT_SECONDS,
    )
    browser = headless_browser.read_pid(pid_file, wait_seconds=0)
    assert browser is not None
    assert ended(browser)

    headless_browser.close(browser)
