"""Remove the Azure Key Vault credential backend.

The Key Vault backend is one file inside the config package, plus the unit
test module that imports it at module scope:

    src/<package>/config/keyvault_backend.py  the backend implementation
    tests/test_keyvault_backend.py            its unit tests

The backend is the only module in the package that imports ``azure-*``, so
deleting it removes every azure import. Only those files are deleted;
nothing else is edited. The dispatcher (``secrets.py``) selects backends by
naming convention and never names "keyvault", so it stays functional --
profiles simply cannot select ``credential_backend = "keyvault"`` any more.
The dispatcher's own tests (``tests/test_config_secrets.py``) use fake
backends and are deliberately not touched: ``secrets.py`` stays.

Manual follow-ups (this script only deletes files):

- Delete the ``keyvault`` extra in ``pyproject.toml``'s
  ``[project.optional-dependencies]``, then run ``uv lock`` and ``uv sync``.

Usage:
    uv run scripts/template_setup/remove_keyvault.py
    uv run scripts/template_setup/remove_keyvault.py --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import _common

# Fixed-path files deleted wholesale (relative to the project root).
_DELETE = [
    "tests/test_keyvault_backend.py",
]

# The backend file, located by glob because the package directory carries the
# project's own (possibly already renamed) import name.
_BACKEND_GLOB = "src/*/config/keyvault_backend.py"


def plan_deletions(root: Path) -> list[Path]:
    """Return the Key Vault backend files that exist and should be deleted.

    Args:
        root: Project root directory.

    Returns:
        The backend file (wherever the package lives under ``src/``) followed
        by the fixed-path files from :data:`_DELETE`, existing paths only.
    """
    paths = sorted(root.glob(_BACKEND_GLOB))
    paths.extend(root / relpath for relpath in _DELETE if (root / relpath).exists())
    return paths


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Delete the Key Vault backend.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success or when nothing matched, 1 if aborted).
    """
    _common.section("Remove the Key Vault backend")

    deletions = plan_deletions(root)
    if not deletions:
        print("\n  No Key Vault backend found; nothing to remove.")
        return 0

    print(f"\n  Files to delete ({len(deletions)}):")
    for path in deletions:
        print(f"    {path.relative_to(root)}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Remove the Key Vault backend?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    for path in deletions:
        path.unlink()
        print(f"  Deleted {path.relative_to(root)}")

    print(f"\n  Removed the Key Vault backend: {len(deletions)} path(s) deleted.")
    print("  Reminder: delete the 'keyvault' extra in pyproject.toml's")
    print("  [project.optional-dependencies], then run 'uv lock' and 'uv sync'.")
    return 0


def main() -> None:
    """Parse arguments and run the Key Vault backend removal."""
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
