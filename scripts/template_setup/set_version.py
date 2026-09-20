"""Set the project's release version in ``pyproject.toml``.

A fresh clone carries the template's own release version (whatever it was tagged
at). A brand-new project has not released anything yet, so it should start from a
clean ``0.1.0``. This rewrites the ``version`` field under ``[project]`` and
nothing else -- the ``target-version`` (ruff) and ``python_version`` (mypy)
fields, which also contain the word "version", are left untouched.

It deliberately does **not** touch ``uv.lock``; that is generated. The version
also is not stored anywhere else (the package reads it from its installed
metadata), so this one field is the whole job.

The default version lives in :data:`DEFAULT_VERSION` below; edit that one line to
change what a fresh clone resets to, or pass a version on the command line.

Usage:
    uv run scripts/template_setup/set_version.py
    uv run scripts/template_setup/set_version.py 1.0.0
    uv run scripts/template_setup/set_version.py 1.0.0 --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import _common

# The version a fresh clone resets to. A new project has no releases yet, so it
# starts below 1.0.0 per Semantic Versioning's initial-development guidance.
DEFAULT_VERSION = "0.1.0"

# Accepts MAJOR.MINOR.PATCH with an optional pre-release/build suffix
# (e.g. "0.1.0", "1.0.0rc1", "2.0.0-beta.1"), matching what push_new_tag_to_main
# is willing to tag.
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+")

# The project version line in pyproject.toml. Anchored at the start of a line so
# it never matches ``target-version`` (ruff) or ``python_version`` (mypy), which
# also contain the word "version".
_VERSION_LINE_RE = re.compile(r'(?m)^(version\s*=\s*")[^"]*(")')


def validate(version: str) -> str:
    """Return ``version`` stripped of surrounding whitespace, or raise.

    Args:
        version: User-supplied version string.

    Returns:
        The cleaned version.

    Raises:
        ValueError: If ``version`` does not start with ``MAJOR.MINOR.PATCH``.
    """
    cleaned = version.strip()
    if not _VERSION_RE.match(cleaned):
        raise ValueError(f"'{version}' is not a valid version. Use MAJOR.MINOR.PATCH, e.g. 0.1.0.")
    return cleaned


def set_version(text: str, version: str) -> str:
    """Rewrite the ``[project]`` version field in pyproject.toml contents.

    Args:
        text: Full ``pyproject.toml`` contents.
        version: Already-validated version to set.

    Returns:
        The contents with the project version replaced. Only the first
        ``^version = "..."`` line is touched.
    """
    return _VERSION_LINE_RE.sub(rf"\g<1>{version}\g<2>", text, count=1)


def run(root: Path, version: str, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Set the project's release version in ``pyproject.toml``.

    Args:
        root: Project root directory.
        version: Version to set (``MAJOR.MINOR.PATCH`` with an optional suffix).
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success, 1 if aborted).

    Raises:
        ValueError: If ``version`` is not a valid version string.
    """
    version = validate(version)

    _common.section("Set project version")
    _common.info("Version", version)

    path = root / "pyproject.toml"
    text = _common.read_text(path)
    if text is None:
        print("  Could not read pyproject.toml; nothing to change.")
        return 1

    new_text = set_version(text, version)
    if new_text == text:
        match = _VERSION_LINE_RE.search(text)
        if match is None:
            print("  No 'version = \"...\"' line found in pyproject.toml; nothing to change.")
            return 1
        print(f"\n  Already at version {version}; nothing to change.")
        return 0

    old_line = _VERSION_LINE_RE.search(text)
    new_line = _VERSION_LINE_RE.search(new_text)
    if old_line and new_line:
        print("\n  pyproject.toml")
        print(f"    {old_line.group().strip()}  ->  {new_line.group().strip()}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Apply version change?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    _common.write_text(path, new_text)
    print(f"\n  Set version to {version}.")
    print("  Reminder: run 'uv sync' to update uv.lock with the new version.")
    return 0


def main() -> None:
    """Parse arguments and run the version reset."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "version",
        nargs="?",
        default=DEFAULT_VERSION,
        help=f"version to set (default: {DEFAULT_VERSION}).",
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would change without writing."
    )
    args = parser.parse_args()

    root = _common.find_root()
    try:
        exit_code = run(root, args.version, assume_yes=args.yes, dry_run=args.dry_run)
    except ValueError as error:
        sys.exit(f"ERROR: {error}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
