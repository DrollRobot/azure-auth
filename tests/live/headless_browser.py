"""Start a browser for a test, and close it again afterwards.

Run as ``python headless_browser.py --pid-file <file> <program> [arguments...] <address>``,
as ``webbrowser`` runs a registered browser. It starts ``<program>`` with its arguments and
the address, writes the browser's process id to ``<file>``, and exits, leaving the browser
running. ``webbrowser`` keeps no handle on what it starts, so the file is how the test finds
the browser again: :func:`read_pid` reads it, and :func:`close` ends the browser and every
process it started.

The browser is started in a session of its own off Windows, so that its process group holds
everything it starts. On Windows its helper processes are its children, and ``taskkill /T``
ends them with it.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

# How often read_pid looks for the file.
POLL_SECONDS = 0.1


def main(argv: list[str]) -> None:
    """Start the browser and record its process id.

    Args:
        argv: The arguments after the script name: ``--pid-file <file>``, then the program,
            its arguments and the address.
    """
    pid_file = Path(argv[1])
    browser = subprocess.Popen(  # noqa: S603 (the test's own argv list, no shell)
        argv[2:], start_new_session=True
    )
    # Written whole and then renamed, so that a reader never sees part of the number.
    partial = pid_file.with_name(f"{pid_file.name}.partial")
    partial.write_text(str(browser.pid), encoding="ascii")
    partial.replace(pid_file)


def read_pid(pid_file: Path, wait_seconds: float) -> int | None:
    """Return the process id the launcher recorded, waiting for it to be written.

    Args:
        pid_file: The file given to the launcher as ``--pid-file``.
        wait_seconds: How long to wait for the file to appear.

    Returns:
        The browser's process id, or ``None`` when the browser was never started.
    """
    deadline = time.monotonic() + wait_seconds
    while not pid_file.exists():
        if time.monotonic() >= deadline:
            return None
        time.sleep(POLL_SECONDS)
    return int(pid_file.read_text(encoding="ascii"))


def close(pid: int) -> None:
    """End the browser and every process it started.

    A browser that has already exited is not an error.

    Args:
        pid: The browser's process id, from :func:`read_pid`.
    """
    if sys.platform == "win32":
        taskkill = shutil.which("taskkill")
        if taskkill is None:
            raise RuntimeError("taskkill was not found, so the browser cannot be closed")
        subprocess.run(  # noqa: S603 (taskkill path from shutil.which, fixed arguments)
            [taskkill, "/PID", str(pid), "/T", "/F"], capture_output=True, check=False
        )
    else:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pid, signal.SIGKILL)


if __name__ == "__main__":
    main(sys.argv[1:])
