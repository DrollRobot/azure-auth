"""List every remaining FIXME so you can work through them.

Scans file contents and file names for ``FIXME`` and prints a table of where
each one lives. This is read-only -- it never changes anything -- so run it as a
checklist before considering the template fully customized.

Usage:
    uv run scripts/template_setup/find_fixmes.py
    uv run scripts/template_setup/find_fixmes.py --ignore-case
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import _common

MARKER = "FIXME"


def find_fixmes(
    root: Path, *, ignore_case: bool = False
) -> tuple[list[Path], list[tuple[Path, int, str]]]:
    """Collect FIXME markers in file names and file contents.

    Args:
        root: Project root directory.
        ignore_case: Match ``fixme`` in any case as well as ``FIXME``.

    Returns:
        A ``(name_hits, content_hits)`` tuple. ``name_hits`` is a list of paths
        whose file name contains the token; ``content_hits`` is a list of
        ``(path, line_number, line_text)`` tuples.
    """
    needle = MARKER.lower() if ignore_case else MARKER
    name_hits: list[Path] = []
    content_hits: list[tuple[Path, int, str]] = []

    for path in _common.iter_text_files(root):
        name = path.name.lower() if ignore_case else path.name
        if needle in name:
            name_hits.append(path)

        text = _common.read_text(path)
        if text is None:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            haystack = line.lower() if ignore_case else line
            if needle in haystack:
                content_hits.append((path, number, line.strip()))

    return name_hits, content_hits


def run(root: Path, *, ignore_case: bool = False) -> int:
    """Print all FIXME markers found under ``root``.

    Args:
        root: Project root directory.
        ignore_case: Match ``fixme`` in any case as well as ``FIXME``.

    Returns:
        Process exit code (always 0; FIXMEs are reported, not treated as errors).
    """
    _common.section("Remaining FIXMEs")
    name_hits, content_hits = find_fixmes(root, ignore_case=ignore_case)

    if name_hits:
        print(f"  File names containing {MARKER} ({len(name_hits)}):")
        for path in name_hits:
            print(f"    {path.relative_to(root)}")
        print()

    if content_hits:
        rows: list[tuple[object, ...]] = [
            (str(path.relative_to(root)), number, _truncate(line))
            for path, number, line in content_hits
        ]
        table = _common.render_table(rows, ["File", "Line", "Content"])
        print(_indent(table))
    else:
        print(f"  No {MARKER} markers found in file contents.")

    print()
    print(f"  Total: {len(name_hits)} file name(s), {len(content_hits)} line(s).")
    return 0


def _truncate(text: str, limit: int = 90) -> str:
    """Shorten ``text`` to ``limit`` characters with an ellipsis if needed.

    Args:
        text: Text to shorten.
        limit: Maximum length before truncation.

    Returns:
        The original text, or a truncated version ending in an ellipsis.
    """
    return text if len(text) <= limit else text[: limit - 1] + "..."


def _indent(block: str, spaces: int = 4) -> str:
    """Indent every line of ``block`` by ``spaces`` spaces.

    Args:
        block: Multi-line text.
        spaces: Number of leading spaces to add per line.

    Returns:
        The indented text.
    """
    pad = " " * spaces
    return "\n".join(pad + line for line in block.splitlines())


def main() -> None:
    """Parse arguments and print the FIXME report."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--ignore-case", action="store_true", help="Also match 'fixme' in any case."
    )
    args = parser.parse_args()

    root = _common.find_root()
    sys.exit(run(root, ignore_case=args.ignore_case))


if __name__ == "__main__":
    main()
