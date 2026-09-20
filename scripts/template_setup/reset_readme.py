"""Replace the template's README with a blank one for the new project.

A fresh clone carries ``README.md`` -- the *template's* own README, which
documents the template itself (its tool choices and the how-to-start-a-project
instructions) and is meaningless in your project -- alongside
``README.md.FIXME``, a skeleton project README whose sections are marked with
FIXMEs. This step drops the template's README and puts the skeleton in its
place: it writes ``README.md.FIXME``'s contents to ``README.md`` and deletes
the ``.FIXME`` file.

It runs early in the guided flow, before the rename, GitHub-user and
Python-version steps, so the skeleton is already ``README.md`` by the time
those steps rewrite the project name, username and version badge in it
(``set_python_version.py`` edits ``README.md`` by name, so a skeleton still
sitting at ``README.md.FIXME`` would keep the template's badge).

Usage:
    uv run scripts/template_setup/reset_readme.py
    uv run scripts/template_setup/reset_readme.py --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import _common

# The committed skeleton and the file it becomes.
TEMPLATE_NAME = "README.md.FIXME"
TARGET_NAME = "README.md"


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Reset ``README.md`` to the ``README.md.FIXME`` skeleton.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success, 1 if aborted or the skeleton is gone).
    """
    _common.section("Reset README")

    template = root / TEMPLATE_NAME
    target = root / TARGET_NAME

    if not template.exists():
        print(f"  No {TEMPLATE_NAME} found (already reset?).")
        return 1

    if target.exists():
        print(f"  Replace: {TARGET_NAME} (the template's own README)")
    print(f"  Rename:  {TEMPLATE_NAME} -> {TARGET_NAME}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Reset the README?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    text = _common.read_text(template) or ""
    _common.write_text(target, text)
    template.unlink()

    print(f"\n  Wrote a fresh {TARGET_NAME}; fill in its FIXMEs.")
    return 0


def main() -> None:
    """Parse arguments and run the README reset."""
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
