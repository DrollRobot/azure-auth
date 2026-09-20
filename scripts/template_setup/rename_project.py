"""Rename the template throughout the project.

Replaces every occurrence of the template's own package name in two forms:

    ``OLD_SNAKE``   (snake_case  -> import name / package dir)
    ``OLD_KEBAB``   (kebab-case  -> PyPI/distribution name)

with names derived from the one you supply, then renames the ``src/<package>/``
folder and the ``.code-workspace`` file to match.

Usage:
    uv run scripts/template_setup/rename_project.py my-project
    uv run scripts/template_setup/rename_project.py my_project --dry-run

The argument may be given in any case with spaces, hyphens, or underscores;
both the snake_case import name and kebab-case distribution name are derived
from it.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import _common

OLD_SNAKE = "python_repo_template"
OLD_KEBAB = "python-repo-template"

# The committed template workspace is named "<name>.code-workspace.FIXME.jsonc";
# renaming drops this marker so the result is a real "<name>.code-workspace".
_WORKSPACE_MARKER = ".code-workspace.FIXME.jsonc"

_SNAKE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_KEBAB_RE = re.compile(r"^[a-z][a-z0-9-]*$")


def derive_names(raw: str) -> tuple[str, str]:
    """Derive snake_case and kebab-case package names from free-form input.

    Args:
        raw: User-supplied project name (any case, spaces/hyphens/underscores).

    Returns:
        A ``(snake_case, kebab_case)`` tuple.

    Raises:
        ValueError: If either derived name is not a valid package identifier.
    """
    cleaned = raw.strip()
    snake = re.sub(r"[\s\-]+", "_", cleaned).lower()
    kebab = re.sub(r"[\s_]+", "-", cleaned).lower()

    if not _SNAKE_RE.match(snake):
        raise ValueError(
            f"'{raw}' yields invalid snake_case name '{snake}'. "
            "Use letters, digits, and underscores; must start with a letter."
        )
    if not _KEBAB_RE.match(kebab):
        raise ValueError(
            f"'{raw}' yields invalid kebab-case name '{kebab}'. "
            "Use letters, digits, and hyphens; must start with a letter."
        )
    return snake, kebab


def _workspace_target(name: str, snake: str) -> str:
    """Compute the final workspace file name from a template workspace file.

    Replaces the project token and strips the ``.code-workspace.FIXME.jsonc``
    template marker, leaving a real ``<project>.code-workspace`` file.

    Args:
        name: Current file name (ending in ``.code-workspace.FIXME.jsonc``).
        snake: New snake_case project name.

    Returns:
        The new file name, e.g. ``my_project.code-workspace``.
    """
    renamed = name.replace(OLD_SNAKE, snake)
    if renamed.endswith(_WORKSPACE_MARKER):
        renamed = renamed[: -len(_WORKSPACE_MARKER)] + ".code-workspace"
    return renamed


def _plan_content_changes(root: Path, snake: str, kebab: str) -> list[tuple[Path, str, int]]:
    """Find files containing the old name and compute their replacements.

    Args:
        root: Project root.
        snake: New snake_case name.
        kebab: New kebab-case name.

    Returns:
        A list of ``(path, new_text, occurrence_count)`` tuples for changed files.
    """
    changes: list[tuple[Path, str, int]] = []
    for path in _common.iter_text_files(root):
        text = _common.read_text(path)
        if text is None:
            continue
        count = text.count(OLD_SNAKE) + text.count(OLD_KEBAB)
        if count:
            new_text = text.replace(OLD_SNAKE, snake).replace(OLD_KEBAB, kebab)
            changes.append((path, new_text, count))
    return changes


def run(root: Path, raw_name: str, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Rename the project to ``raw_name`` across content, package dir, and workspace.

    Args:
        root: Project root directory.
        raw_name: User-supplied new project name.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success, 1 if aborted).
    """
    snake, kebab = derive_names(raw_name)

    _common.section("Rename project")
    _common.info("Import name", f"{OLD_SNAKE} -> {snake}")
    _common.info("Dist name", f"{OLD_KEBAB} -> {kebab}")

    changes = _plan_content_changes(root, snake, kebab)
    pkg_dir = root / "src" / OLD_SNAKE
    # Only the committed template workspace (".code-workspace.FIXME.jsonc"); a
    # bare "*.code-workspace" is a personal, gitignored file and is left alone.
    workspaces = sorted(root.glob(f"*{_WORKSPACE_MARKER}"))

    print()
    if changes:
        print(f"  Files to update ({len(changes)}):")
        for path, _new, count in changes:
            print(f"    {path.relative_to(root)}  ({count} occurrence(s))")
    else:
        print("  No file contents reference the old name.")

    if pkg_dir.is_dir():
        print(f"  Rename folder: src/{OLD_SNAKE}/ -> src/{snake}/")
    for workspace in workspaces:
        print(f"  Rename file:   {workspace.name} -> {_workspace_target(workspace.name, snake)}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    if not changes and not pkg_dir.is_dir() and not workspaces:
        print("\n  Nothing to rename.")
        return 0

    print()
    if not _common.confirm("Apply rename?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    for path, new_text, _count in changes:
        _common.write_text(path, new_text)
    if pkg_dir.is_dir():
        pkg_dir.rename(pkg_dir.with_name(snake))
    for workspace in workspaces:
        target = workspace.with_name(_workspace_target(workspace.name, snake))
        if target.exists():
            print(f"  Skipped {workspace.name}: {target.name} already exists.")
            continue
        workspace.rename(target)

    print(f"\n  Renamed to '{snake}' / '{kebab}'.")
    return 0


def main() -> None:
    """Parse arguments and run the rename."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("name", help="New project name (e.g. my-project or my_project).")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would change without writing."
    )
    args = parser.parse_args()

    root = _common.find_root()
    try:
        exit_code = run(root, args.name, assume_yes=args.yes, dry_run=args.dry_run)
    except ValueError as error:
        sys.exit(f"ERROR: {error}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
