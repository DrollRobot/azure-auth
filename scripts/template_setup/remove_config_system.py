"""Remove the config system (the config package and its tests) entirely.

The config system is the per-user ``config.toml`` machinery -- schema,
paths, file I/O, resolution engine, config CLI, and the credential-backend
dispatcher with both backends:

    src/<package>/config/          the whole package (schema, CLI, backends, ...)
    tests/_config_test_object.py   the test object shared by the config tests
    tests/test_config_*.py         the config package's unit tests

Only those paths are deleted; nothing else is edited. Removing the whole
package covers both credential backends, so the separate
``remove_keyring.py`` / ``remove_keyvault.py`` steps are redundant when this
one runs.

Manual follow-ups (this script only deletes files):

- Delete the config CLI entry point in ``pyproject.toml``'s
  ``[project.scripts]`` table.
- Delete the ``keyring`` and ``keyvault`` extras in ``pyproject.toml``'s
  ``[project.optional-dependencies]``, plus ``tomlkit`` and ``platformdirs``
  if nothing else uses them, then run ``uv lock`` and ``uv sync``.
- Remove the ``load_settings`` usage from ``src/<package>/main.py`` and the
  settings fixture from ``tests/conftest.py``.

Usage:
    uv run scripts/template_setup/remove_config_system.py
    uv run scripts/template_setup/remove_config_system.py --dry-run
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import _common

# Fixed-path files deleted wholesale (relative to the project root).
_DELETE = [
    "tests/_config_test_object.py",
]

# Globs for paths that carry the project's own (possibly already renamed)
# import name, or that share a common prefix.
_DELETE_GLOBS = [
    "src/*/config",
    "tests/test_config_*.py",
]


def plan_deletions(root: Path) -> list[Path]:
    """Return the config-system paths that exist and should be deleted.

    Args:
        root: Project root directory.

    Returns:
        The package directory and every matching test file, existing paths
        only, in sorted order.
    """
    paths: list[Path] = []
    for pattern in _DELETE_GLOBS:
        paths.extend(sorted(root.glob(pattern)))
    paths.extend(root / relpath for relpath in _DELETE if (root / relpath).exists())
    return paths


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Delete the config package and its tests.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success or when nothing matched, 1 if aborted).
    """
    _common.section("Remove the config system")

    deletions = plan_deletions(root)
    if not deletions:
        print("\n  No config system found; nothing to remove.")
        return 0

    print(f"\n  Files/directories to delete ({len(deletions)}):")
    for path in deletions:
        suffix = "/" if path.is_dir() else ""
        print(f"    {path.relative_to(root)}{suffix}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Remove the config system?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    for path in deletions:
        is_dir = path.is_dir()
        if is_dir:
            shutil.rmtree(path, onexc=_common.force_remove)
        else:
            path.unlink()
        suffix = "/" if is_dir else ""
        print(f"  Deleted {path.relative_to(root)}{suffix}")

    print(f"\n  Removed the config system: {len(deletions)} path(s) deleted.")
    print("  Reminders (not done automatically):")
    print("    - Delete the config CLI entry point in pyproject.toml's [project.scripts].")
    print("    - Delete the 'keyring' and 'keyvault' extras in pyproject.toml's")
    print("      [project.optional-dependencies] (and tomlkit/platformdirs if nothing")
    print("      else uses them), then run 'uv lock' and 'uv sync'.")
    print("    - Remove the load_settings usage from the package's main.py and the")
    print("      settings fixture from tests/conftest.py.")
    return 0


def main() -> None:
    """Parse arguments and run the config-system removal."""
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
