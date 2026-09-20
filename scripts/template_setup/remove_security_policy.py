"""Remove the security policy file.

``SECURITY.md`` is GitHub's private vulnerability-disclosure page: it appears
on the repository's Security tab and is linked whenever someone opens an issue
that looks like a vulnerability report. A project with no disclosure process
to document -- an internal tool, a private repo, a scratch project -- ships it
as an unread stub, so this deletes it.

Nothing else is touched: no other template file links to ``SECURITY.md``, and
GitHub simply stops offering the "Report a vulnerability" flow once the file
is gone.

Usage:
    uv run scripts/template_setup/remove_security_policy.py
    uv run scripts/template_setup/remove_security_policy.py --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import _common

# Files deleted wholesale (relative to the project root).
_DELETE = ["SECURITY.md"]


def plan_deletions(root: Path) -> list[Path]:
    """Return the security-policy files that exist and should be deleted.

    Args:
        root: Project root directory.

    Returns:
        Existing paths from :data:`_DELETE`, in declaration order.
    """
    return [root / relpath for relpath in _DELETE if (root / relpath).exists()]


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Delete the security policy file.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success or when nothing matched, 1 if aborted).
    """
    _common.section("Remove the security policy")

    deletions = plan_deletions(root)
    if not deletions:
        print("\n  No SECURITY.md found; nothing to remove.")
        return 0

    print(f"\n  Files to delete ({len(deletions)}):")
    for path in deletions:
        print(f"    {path.relative_to(root)}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Remove the security policy?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    for path in deletions:
        path.unlink()
        print(f"  Deleted {path.relative_to(root)}")

    print(f"\n  Removed the security policy: {len(deletions)} path(s) deleted.")
    print("  Reminder: GitHub's Security tab will no longer link a reporting")
    print("  process, so make sure another channel is documented if this repo")
    print("  is public.")
    return 0


def main() -> None:
    """Parse arguments and run the security-policy removal."""
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
