"""Remove MkDocs (the documentation site) and all of its artifacts.

A fresh clone ships MkDocs for documentation, wired into several places:

    docs/                      the documentation sources (index + API reference)
    mkdocs.yml                 the MkDocs site configuration
    .github/workflows/docs.yml the GitHub Pages deploy workflow
    pyproject.toml             the "docs" dependency group and its "dev" include
    .gitignore                 the "/site" build-output ignore
    README.md                  the mkdocs bullet, the Pages step, the optional-
                               features table row
    CONTRIBUTING.md            the docs commands and the "docs/" structure bullet
    AGENTS.RELEASING.md        the "Update docs" release step

This deletes the doc tree and config files and strips every reference in one
pass, leaving a project with no documentation site.

Run ``uv lock`` (then ``uv sync``) afterwards to drop mkdocs (and mkdocs-material
and mkdocstrings) from the lockfile and the virtualenv -- this script does not
touch the generated ``uv.lock``.

Usage:
    uv run scripts/template_setup/remove_mkdocs.py
    uv run scripts/template_setup/remove_mkdocs.py --dry-run
"""

from __future__ import annotations

import argparse
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

import _common

# Files and directories deleted wholesale (relative to the project root).
_DELETE = [
    "docs",
    "mkdocs.yml",
    ".github/workflows/docs.yml",
]

# Long marker strings used to locate multi-line regions, kept here so the call
# sites stay readable and under the line-length limit.
_README_PAGES_HEADER = "**If using mkdocs, enable GitHub Pages for docs**"
_CONTRIB_DOCS_HEADER = "# Docs (live preview at http://127.0.0.1:8000)"


def _strip_pyproject(text: str) -> tuple[str, list[str]]:
    """Remove the ``docs`` dependency group and its ``dev`` include.

    The group runs from ``docs = [`` to its closing ``]``; the include is the
    single ``{include-group = "docs"},`` line inside the ``dev`` group.

    Args:
        text: Contents of ``pyproject.toml``.

    Returns:
        A ``(new_text, removed_lines)`` tuple.
    """
    lines = text.splitlines(keepends=True)
    kept: list[str] = []
    removed: list[str] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped == "docs = [":
            removed.append(stripped)
            index += 1
            while index < len(lines) and lines[index].strip() != "]":
                if lines[index].strip():
                    removed.append(lines[index].strip())
                index += 1
            if index < len(lines):
                removed.append(lines[index].strip())
                index += 1
            continue
        if stripped.startswith('{include-group = "docs"}'):
            removed.append(stripped)
            index += 1
            continue
        kept.append(lines[index])
        index += 1
    return "".join(kept), removed


def _strip_gitignore(text: str) -> tuple[str, list[str]]:
    """Remove the mkdocs ``/site`` build-output ignore block from ``.gitignore``."""
    return _common.remove_block(text, "# mkdocs documentation")


def _strip_agents_releasing(text: str) -> tuple[str, list[str]]:
    """Remove the ``Update docs`` release step from ``AGENTS.RELEASING.md``."""
    return _common.remove_section(text, "## Update docs", "## ")


def _strip_readme(text: str) -> tuple[str, list[str]]:
    """Remove every mkdocs reference from ``README.md``.

    Strips the tool-choices bullet, the GitHub Pages deploy step, and the
    optional-features table row.

    Args:
        text: Contents of ``README.md``.

    Returns:
        A ``(new_text, removed_lines)`` tuple.
    """
    removed: list[str] = []
    text, part = _common.remove_matching(text, lambda line: line.startswith("- **mkdocs**"))
    removed += part
    text, part = _common.remove_region(
        text, _README_PAGES_HEADER, ".github/workflows/docs.yml", blank="trailing"
    )
    removed += part
    text, part = _common.remove_matching(text, lambda line: line.startswith("| **MkDocs docs**"))
    removed += part
    return text, removed


def _strip_contributing(text: str) -> tuple[str, list[str]]:
    """Remove every mkdocs reference from ``CONTRIBUTING.md``.

    Strips the docs commands from the checks block and the ``docs/`` bullet from
    the project-structure list.

    Args:
        text: Contents of ``CONTRIBUTING.md``.

    Returns:
        A ``(new_text, removed_lines)`` tuple.
    """
    removed: list[str] = []
    text, part = _common.remove_region(
        text, _CONTRIB_DOCS_HEADER, "mkdocs gh-deploy", blank="leading"
    )
    removed += part
    text, part = _common.remove_matching(
        text, lambda line: line.startswith("- `docs/`") and "MkDocs" in line
    )
    removed += part
    return text, removed


# Fixed-path files and the transform that strips their mkdocs references.
_TRANSFORMS: list[tuple[str, Callable[[str], tuple[str, list[str]]]]] = [
    ("pyproject.toml", _strip_pyproject),
    (".gitignore", _strip_gitignore),
    ("README.md", _strip_readme),
    ("CONTRIBUTING.md", _strip_contributing),
    ("AGENTS.RELEASING.md", _strip_agents_releasing),
]


def plan_deletions(root: Path) -> list[Path]:
    """Return the mkdocs files and directories that exist and should be deleted.

    Args:
        root: Project root directory.

    Returns:
        Existing paths from :data:`_DELETE`, in declaration order.
    """
    return [root / relpath for relpath in _DELETE if (root / relpath).exists()]


def plan_edits(root: Path) -> list[tuple[Path, str, list[str]]]:
    """Compute the rewritten contents for every file that references mkdocs.

    Files that are missing, unreadable, or free of mkdocs references are skipped.

    Args:
        root: Project root directory.

    Returns:
        A list of ``(path, new_text, removed_lines)`` tuples for files that
        actually change.
    """
    edits: list[tuple[Path, str, list[str]]] = []
    for relpath, transform in _TRANSFORMS:
        path = root / relpath
        text = _common.read_text(path)
        if text is None:
            continue
        new_text, removed = transform(text)
        if removed:
            edits.append((path, new_text, removed))
    return edits


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Delete the mkdocs artifacts and strip every reference to them.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success or when nothing matched, 1 if aborted).
    """
    _common.section("Remove mkdocs")

    deletions = plan_deletions(root)
    edits = plan_edits(root)
    if not deletions and not edits:
        print("\n  No mkdocs artifacts found; nothing to remove.")
        return 0

    if deletions:
        print(f"\n  Files/directories to delete ({len(deletions)}):")
        for path in deletions:
            suffix = "/" if path.is_dir() else ""
            print(f"    {path.relative_to(root)}{suffix}")

    if edits:
        print(f"\n  Files to update ({len(edits)}):")
        for path, _new, removed in edits:
            print(f"    {path.relative_to(root)}")
            for line in removed:
                print(f"      - {line}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Remove mkdocs and its artifacts?", assume_yes=assume_yes):
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

    for path, new_text, _removed in edits:
        _common.write_text(path, new_text)
        print(f"  Updated {path.relative_to(root)}")

    print(f"\n  Removed mkdocs: {len(deletions)} path(s) deleted, {len(edits)} file(s) updated.")
    print("  Reminder: run 'uv lock' (then 'uv sync') to drop mkdocs from the lockfile and venv.")
    return 0


def main() -> None:
    """Parse arguments and run the mkdocs removal."""
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
