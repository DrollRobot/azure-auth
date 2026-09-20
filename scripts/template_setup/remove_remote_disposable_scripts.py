"""Remove the remote-disposability script pair.

``scripts/mark_remote_disposable.py`` (write half) and
``tests/verify_remote_disposable.py`` (read half) exist only to gate
``@pytest.mark.destructive_remote`` tests -- see AGENTS.TESTING.md. A project
with no remote-destructive tests has no use for them, so this deletes both,
plus ``tests/test_verify_remote_disposable.py``, whose module-level import of
the read half would fail at collection once that file is gone (``cleanup.py``
does not match it: its rule only pairs ``tests/test_<name>.py`` with a
``scripts/`` or ``scripts/template_setup/`` script, and the read half lives
in ``tests/``).

Nothing else is touched. ``tests/conftest.py``'s ``destructive_remote`` gate,
the marker in ``pyproject.toml``, and the AGENTS.TESTING.md section all stay:
the gate already fails closed when the read half is missing, so a project
that later grows a ``destructive_remote`` test still refuses to run it until
the pair is restored and implemented.

Usage:
    uv run scripts/template_setup/remove_remote_disposable_scripts.py
    uv run scripts/template_setup/remove_remote_disposable_scripts.py --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import _common

# Files deleted wholesale (relative to the project root).
_DELETE = [
    "scripts/mark_remote_disposable.py",
    "tests/verify_remote_disposable.py",
    "tests/test_verify_remote_disposable.py",
]


def plan_deletions(root: Path) -> list[Path]:
    """Return the remote-disposability files that exist and should be deleted.

    Args:
        root: Project root directory.

    Returns:
        Existing paths from :data:`_DELETE`, in declaration order.
    """
    return [root / relpath for relpath in _DELETE if (root / relpath).exists()]


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Delete the remote-disposability script pair and its unit test.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success or when nothing matched, 1 if aborted).
    """
    _common.section("Remove remote-disposability scripts")

    deletions = plan_deletions(root)
    if not deletions:
        print("\n  No remote-disposability scripts found; nothing to remove.")
        return 0

    print(f"\n  Files to delete ({len(deletions)}):")
    for path in deletions:
        print(f"    {path.relative_to(root)}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Remove the remote-disposability scripts?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    for path in deletions:
        path.unlink()
        print(f"  Deleted {path.relative_to(root)}")

    print(f"\n  Removed remote-disposability scripts: {len(deletions)} path(s) deleted.")
    print("  Reminder: the destructive_remote marker, conftest.py's gate, and")
    print("  AGENTS.TESTING.md's 'Remote destructive tests' section stay in place.")
    print("  The gate fails closed with the read half gone, so any destructive_remote")
    print("  test refuses to run until you restore and implement the pair.")
    return 0


def main() -> None:
    """Parse arguments and run the remote-disposability script removal."""
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
