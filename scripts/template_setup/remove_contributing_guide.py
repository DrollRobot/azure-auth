"""Remove the contributor guide.

``CONTRIBUTING.md`` is recognized by GitHub and linked in the sidebar of every
new issue and pull request. A project that will never take outside
contributions -- a solo or internal one -- ships it as an unread stub, so this
deletes it.

Nothing else is touched: no other template file links to ``CONTRIBUTING.md``.
Note that the file also carries the dev-environment setup, the project
conventions, and the PR checklist; ``AGENTS.TESTING.md`` (which it defers to
for the actual check commands) stays either way, but anything else worth
keeping should be moved before this runs.

Ordering with ``remove_mkdocs.py`` does not matter: that script edits
``CONTRIBUTING.md`` only when it is still there, and skips it silently
otherwise.

Usage:
    uv run scripts/template_setup/remove_contributing_guide.py
    uv run scripts/template_setup/remove_contributing_guide.py --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import _common

# Files deleted wholesale (relative to the project root).
_DELETE = ["CONTRIBUTING.md"]


def plan_deletions(root: Path) -> list[Path]:
    """Return the contributor-guide files that exist and should be deleted.

    Args:
        root: Project root directory.

    Returns:
        Existing paths from :data:`_DELETE`, in declaration order.
    """
    return [root / relpath for relpath in _DELETE if (root / relpath).exists()]


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Delete the contributor guide.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success or when nothing matched, 1 if aborted).
    """
    _common.section("Remove the contributor guide")

    deletions = plan_deletions(root)
    if not deletions:
        print("\n  No CONTRIBUTING.md found; nothing to remove.")
        return 0

    print(f"\n  Files to delete ({len(deletions)}):")
    for path in deletions:
        print(f"    {path.relative_to(root)}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Remove the contributor guide?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    for path in deletions:
        path.unlink()
        print(f"  Deleted {path.relative_to(root)}")

    print(f"\n  Removed the contributor guide: {len(deletions)} path(s) deleted.")
    print("  Reminder: its dev-environment setup and PR checklist go with it;")
    print("  AGENTS.TESTING.md still documents the check and test commands.")
    return 0


def main() -> None:
    """Parse arguments and run the contributor-guide removal."""
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
