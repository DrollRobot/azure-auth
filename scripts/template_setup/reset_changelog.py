"""Replace the template's changelog with a clean, empty one for the new project.

A fresh clone carries ``CHANGELOG.md`` -- the *template's* own release history,
which is meaningless in your project -- alongside ``CHANGELOG.md.FIXME``, a blank
Keep a Changelog skeleton. This step drops the template's history and puts the
skeleton in its place: it writes ``CHANGELOG.md.FIXME``'s contents to
``CHANGELOG.md`` and deletes the ``.FIXME`` file.

It runs after the rename and GitHub-user steps in the guided flow, so the
project name and username placeholders in the skeleton's links are already
rewritten by the time it becomes ``CHANGELOG.md``.

Usage:
    uv run scripts/template_setup/reset_changelog.py
    uv run scripts/template_setup/reset_changelog.py --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import _common

# The committed skeleton and the file it becomes.
TEMPLATE_NAME = "CHANGELOG.md.FIXME"
TARGET_NAME = "CHANGELOG.md"


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Reset ``CHANGELOG.md`` to the blank ``CHANGELOG.md.FIXME`` skeleton.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success, 1 if aborted or the skeleton is gone).
    """
    _common.section("Reset changelog")

    template = root / TEMPLATE_NAME
    target = root / TARGET_NAME

    if not template.exists():
        print(f"  No {TEMPLATE_NAME} found (already reset?).")
        return 1

    if target.exists():
        print(f"  Replace: {TARGET_NAME} (the template's release history)")
    print(f"  Rename:  {TEMPLATE_NAME} -> {TARGET_NAME}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Reset the changelog?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    text = _common.read_text(template) or ""
    _common.write_text(target, text)
    template.unlink()

    print(f"\n  Wrote a fresh {TARGET_NAME}.")
    return 0


def main() -> None:
    """Parse arguments and run the changelog reset."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would change without writing."
    )
    args = parser.parse_args()

    root = _common.find_root()
    sys.exit(run(root, assume_yes=args.yes, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
