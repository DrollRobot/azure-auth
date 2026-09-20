"""Remove the commented-out private-repo-deps GitHub Actions steps.

``.github/workflows/ci.yml``, ``audit.yml``, and ``docs.yml`` each ship a
commented-out pair of steps for minting a GitHub App token and using it to
clone private git dependencies during CI. The block is delimited by
``# <private-repo-deps>`` / ``# </private-repo-deps>`` marker comments so it
can be found and stripped mechanically.

This deletes that block from all three workflow files. It never deletes the
files themselves -- unlike ``remove_mkdocs.py`` -- since ``ci.yml`` and
``audit.yml`` are required regardless of this feature, and ``docs.yml`` is
already handled by the ``mkdocs`` feature.

Usage:
    uv run scripts/template_setup/remove_private_repo_deps.py
    uv run scripts/template_setup/remove_private_repo_deps.py --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import _common

# Workflow files that carry the private-repo-deps block (relative to the
# project root).
_WORKFLOWS = [
    ".github/workflows/ci.yml",
    ".github/workflows/audit.yml",
    ".github/workflows/docs.yml",
]

_START = "# <private-repo-deps>"
_END = "</private-repo-deps>"


def _strip_workflow(text: str) -> tuple[str, list[str]]:
    """Remove the private-repo-deps block from one workflow file's contents."""
    return _common.remove_region(text, _START, _END, blank="leading")


def plan_edits(root: Path) -> list[tuple[Path, str, list[str]]]:
    """Compute the rewritten contents for every workflow that has the block.

    Files that are missing, unreadable, or already free of the block are
    skipped.

    Args:
        root: Project root directory.

    Returns:
        A list of ``(path, new_text, removed_lines)`` tuples for files that
        actually change.
    """
    edits: list[tuple[Path, str, list[str]]] = []
    for relpath in _WORKFLOWS:
        path = root / relpath
        text = _common.read_text(path)
        if text is None:
            continue
        new_text, removed = _strip_workflow(text)
        if removed:
            edits.append((path, new_text, removed))
    return edits


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Strip the private-repo-deps block from every workflow that has it.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success or when nothing matched, 1 if aborted).
    """
    _common.section("Remove private-repo-deps workflow steps")

    edits = plan_edits(root)
    if not edits:
        print("\n  No private-repo-deps blocks found; nothing to remove.")
        return 0

    print(f"\n  Files to update ({len(edits)}):")
    for path, _new, removed in edits:
        print(f"    {path.relative_to(root)}")
        for line in removed:
            print(f"      - {line}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Remove the private-repo-deps workflow steps?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    for path, new_text, _removed in edits:
        _common.write_text(path, new_text)
        print(f"  Updated {path.relative_to(root)}")

    print(f"\n  Removed private-repo-deps steps: {len(edits)} file(s) updated.")
    return 0


def main() -> None:
    """Parse arguments and run the private-repo-deps removal."""
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
