"""Remove the "TEMPLATE SETUP NOTES" header block from the top of files.

The template marks its explanatory headers with a ``TEMPLATE SETUP NOTES`` line
inside a banner of ``=`` separators. The banner appears in three comment styles:

    # ...   hash    (.editorconfig, *.yml, *.yaml, .env.example, ...)
    // ...  slash   (*.code-workspace files)
    <!-- --> markdown  (*.md)

This script finds those banners and removes the whole block (plus one trailing
blank line). It does not touch Python module docstrings or any other content --
only the separator-delimited template banner is removed.

Usage:
    uv run scripts/template_setup/strip_template_headers.py
    uv run scripts/template_setup/strip_template_headers.py --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import _common

MARKER = "TEMPLATE SETUP NOTES"

# A separator line such as "# ====..." or "// ====..." (comment marker + '='s).
_SEP_RE = re.compile(r"^\s*(?:#|//)\s*=+\s*$")


def _is_comment(line: str, prefix: str) -> bool:
    """Return whether ``line`` is a comment of the given style.

    Args:
        line: Line to test (with or without trailing newline).
        prefix: Comment marker, ``"#"`` or ``"//"``.

    Returns:
        ``True`` if the line's first non-space characters are ``prefix``.
    """
    return line.lstrip().startswith(prefix)


def _drop_block(lines: list[str], start: int, end: int) -> int:
    """Delete ``lines[start:end + 1]`` plus any blank lines that follow it.

    Args:
        lines: List of lines (modified in place).
        start: First index of the block to remove.
        end: Last index of the block to remove.

    Returns:
        The number of lines removed.
    """
    stop = end + 1
    while stop < len(lines) and lines[stop].strip() == "":
        stop += 1
    removed = stop - start
    del lines[start:stop]
    return removed


def _strip_comment_block(lines: list[str], marker_index: int, prefix: str) -> int | None:
    """Strip a hash/slash banner around ``marker_index``.

    The banner is the run of separator lines inside the contiguous comment block
    that contains the marker: from the first ``===`` separator to the last.

    Args:
        lines: File lines (modified in place when a block is found).
        marker_index: Index of the line containing ``MARKER``.
        prefix: Comment marker, ``"#"`` or ``"//"``.

    Returns:
        Number of lines removed, or ``None`` if no separator-delimited block.
    """
    top = marker_index
    while top - 1 >= 0 and _is_comment(lines[top - 1], prefix):
        top -= 1
    bottom = marker_index
    while bottom + 1 < len(lines) and _is_comment(lines[bottom + 1], prefix):
        bottom += 1

    separators = [i for i in range(top, bottom + 1) if _SEP_RE.match(lines[i])]
    if not separators:
        return None
    return _drop_block(lines, separators[0], separators[-1])


def _strip_markdown_block(lines: list[str], marker_index: int) -> int | None:
    """Strip a Markdown ``<!-- ... -->`` banner around ``marker_index``.

    Args:
        lines: File lines (modified in place when a block is found).
        marker_index: Index of the line containing ``MARKER``.

    Returns:
        Number of lines removed, or ``None`` if the comment is not well formed.
    """
    open_index = marker_index
    while open_index >= 0 and "<!--" not in lines[open_index]:
        open_index -= 1
    close_index = marker_index
    while close_index < len(lines) and "-->" not in lines[close_index]:
        close_index += 1
    if open_index < 0 or close_index >= len(lines):
        return None
    return _drop_block(lines, open_index, close_index)


def strip_header(text: str) -> tuple[str, int] | None:
    """Remove the template header banner from ``text`` if present.

    Args:
        text: Full file contents.

    Returns:
        A ``(new_text, lines_removed)`` tuple, or ``None`` if the file has no
        template header.
    """
    lines = text.splitlines(keepends=True)
    marker_index = next((i for i, line in enumerate(lines) if MARKER in line), None)
    if marker_index is None:
        return None

    marker_line = lines[marker_index].lstrip()
    if marker_line.startswith("#"):
        removed = _strip_comment_block(lines, marker_index, "#")
    elif marker_line.startswith("//"):
        removed = _strip_comment_block(lines, marker_index, "//")
    else:
        removed = _strip_markdown_block(lines, marker_index)

    if removed is None:
        return None
    return "".join(lines), removed


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Strip template headers from every file under ``root`` that has one.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (always 0).
    """
    _common.section("Strip template headers")

    plan: list[tuple[Path, str, int]] = []
    for path in _common.iter_text_files(root):
        text = _common.read_text(path)
        if text is None:
            continue
        result = strip_header(text)
        if result is not None:
            new_text, removed = result
            plan.append((path, new_text, removed))

    if not plan:
        print("  No template headers found.")
        return 0

    print(f"  Files with a template header ({len(plan)}):")
    for path, _new, removed in plan:
        print(f"    {path.relative_to(root)}  (-{removed} lines)")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Strip these headers?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    for path, new_text, _removed in plan:
        _common.write_text(path, new_text)
    print(f"\n  Stripped headers from {len(plan)} file(s).")
    return 0


def main() -> None:
    """Parse arguments and run the header strip."""
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
