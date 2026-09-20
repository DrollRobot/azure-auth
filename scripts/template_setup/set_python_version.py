"""Set the Python version the project targets, everywhere it is declared.

A fresh clone targets one Python version, written into several files in three
different spellings:

    3.14     dotted     (.python-version, requires-python, mypy, docs, badge)
    py314    compact    (ruff target-version)
    3.14.3   patch      (the bug-report issue template's example placeholder)

This rewrites every one of those to the version you choose, keeping each file's
surrounding syntax intact. It deliberately does **not** touch ``uv.lock`` -- that
is generated; run ``uv sync`` afterwards to regenerate it for the new version.

The default version lives in :data:`DEFAULT_VERSION` below; edit that one line to
change what a fresh clone targets, or pass a version on the command line.

Usage:
    uv run scripts/template_setup/set_python_version.py
    uv run scripts/template_setup/set_python_version.py 3.14
    uv run scripts/template_setup/set_python_version.py 3.14 --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import _common

# The Python version a fresh clone targets. Bump this one line (or pass a
# version on the command line) to retarget the whole project.
DEFAULT_VERSION = "3.14"

# Accepts MAJOR.MINOR or MAJOR.MINOR.PATCH (e.g. "3.14" or "3.14.3").
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)*$")


@dataclass(frozen=True)
class _Edit:
    """A single targeted version replacement within one file.

    Attributes:
        relpath: Path to the file, relative to the project root.
        pattern: Regex locating the version in its surrounding syntax. The
            pattern keeps the surrounding text in capture groups so only the
            version number itself is rewritten.
        replacement: ``re.sub`` replacement string (may reference groups).
        count: Maximum replacements to make; ``0`` means replace all matches.
    """

    relpath: str
    pattern: re.Pattern[str]
    replacement: str
    count: int = 0


def version_forms(version: str) -> tuple[str, str, str]:
    """Derive the three spellings of a Python version used across the project.

    Args:
        version: User-supplied version (``MAJOR.MINOR`` or ``MAJOR.MINOR.PATCH``).

    Returns:
        A ``(full, dotted, compact)`` tuple, e.g. ``("3.14.3", "3.14", "py314")``.
        ``full`` is the version exactly as given (used for the ``.python-version``
        pin), ``dotted`` is ``MAJOR.MINOR``, and ``compact`` is ``pyMAJORMINOR``.

    Raises:
        ValueError: If ``version`` is not a valid Python version string.
    """
    cleaned = version.strip()
    match = _VERSION_RE.match(cleaned)
    if not match:
        raise ValueError(
            f"'{version}' is not a valid Python version. "
            "Use MAJOR.MINOR or MAJOR.MINOR.PATCH, e.g. 3.14 or 3.14.3."
        )
    major, minor = match.group(1), match.group(2)
    return cleaned, f"{major}.{minor}", f"py{major}{minor}"


def _build_edits(full: str, dotted: str, compact: str) -> list[_Edit]:
    """Build the list of targeted version edits for the given version forms.

    Args:
        full: Version exactly as supplied (for the ``.python-version`` pin).
        dotted: ``MAJOR.MINOR`` form.
        compact: ``pyMAJORMINOR`` form.

    Returns:
        The edits to apply, in file order.
    """
    return [
        # .python-version: the file is just the version pin.
        _Edit(".python-version", re.compile(r"\d+\.\d+(?:\.\d+)*"), full, count=1),
        # pyproject.toml: requires-python floor, ruff target, mypy version.
        _Edit(
            "pyproject.toml",
            re.compile(r'(requires-python\s*=\s*">=\s*)\d+\.\d+(?:\.\d+)*'),
            rf"\g<1>{dotted}",
        ),
        _Edit(
            "pyproject.toml",
            re.compile(r'(target-version\s*=\s*")py\d+(")'),
            rf"\g<1>{compact}\g<2>",
        ),
        _Edit(
            "pyproject.toml",
            re.compile(r'(python_version\s*=\s*")\d+\.\d+(?:\.\d+)*(")'),
            rf"\g<1>{dotted}\g<2>",
        ),
        # .pre-commit-config.yaml: default_language_version pin.
        _Edit(
            ".pre-commit-config.yaml",
            re.compile(r"(python:\s*python)\d+\.\d+(?:\.\d+)*"),
            rf"\g<1>{dotted}",
        ),
        # CONTRIBUTING.md: "Requires Python 3.14+".
        _Edit(
            "CONTRIBUTING.md",
            re.compile(r"(Python\s+)\d+\.\d+(?:\.\d+)*\+"),
            rf"\g<1>{dotted}+",
        ),
        # README.md: shields.io version badge.
        _Edit(
            "README.md",
            re.compile(r"(badge/python-)\d+\.\d+(?:\.\d+)*(%2B)"),
            rf"\g<1>{dotted}\g<2>",
        ),
        # bug_report.yml: example placeholder under the python-version field only.
        _Edit(
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            re.compile(r'(id:\s*python-version\b[\s\S]*?placeholder:\s*")\d+\.\d+'),
            rf"\g<1>{dotted}",
        ),
    ]


def _changed_lines(old: str, new: str) -> list[tuple[int, str, str]]:
    """Pair up lines that differ between two versions of a file.

    Replacements never add or remove lines, so the two texts line up one-to-one.

    Args:
        old: Original file contents.
        new: Rewritten file contents.

    Returns:
        A list of ``(line_number, old_line, new_line)`` for each differing line,
        with both lines stripped of surrounding whitespace.
    """
    return [
        (number, old_line.strip(), new_line.strip())
        for number, (old_line, new_line) in enumerate(
            zip(old.splitlines(), new.splitlines(), strict=True), start=1
        )
        if old_line != new_line
    ]


def plan_changes(
    root: Path, edits: list[_Edit]
) -> list[tuple[Path, str, list[tuple[int, str, str]]]]:
    """Compute the rewritten contents for every file an edit changes.

    Edits are grouped by file so each file is read once and all of its edits are
    applied before comparing. Files that are missing, unreadable, or already at
    the target version are skipped.

    Args:
        root: Project root directory.
        edits: Edits to apply.

    Returns:
        A list of ``(path, new_text, changed_lines)`` tuples for files that
        actually change.
    """
    by_file: dict[str, list[_Edit]] = {}
    for edit in edits:
        by_file.setdefault(edit.relpath, []).append(edit)

    changes: list[tuple[Path, str, list[tuple[int, str, str]]]] = []
    for relpath, file_edits in by_file.items():
        path = root / relpath
        text = _common.read_text(path)
        if text is None:
            continue
        new_text = text
        for edit in file_edits:
            new_text = edit.pattern.sub(edit.replacement, new_text, count=edit.count)
        if new_text != text:
            changes.append((path, new_text, _changed_lines(text, new_text)))
    return changes


def run(root: Path, version: str, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Set the project's Python version everywhere it is declared.

    Args:
        root: Project root directory.
        version: Python version to set (``MAJOR.MINOR`` or ``MAJOR.MINOR.PATCH``).
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success, 1 if aborted).

    Raises:
        ValueError: If ``version`` is not a valid Python version string.
    """
    full, dotted, compact = version_forms(version)

    _common.section("Set Python version")
    _common.info("Version", full)
    _common.info("requires-python", f">={dotted}")
    _common.info("ruff / mypy", f"{compact} / {dotted}")

    changes = plan_changes(root, _build_edits(full, dotted, compact))
    if not changes:
        print(f"\n  Already at Python {dotted}; nothing to change.")
        return 0

    print(f"\n  Files to update ({len(changes)}):")
    for path, _new, lines in changes:
        print(f"    {path.relative_to(root)}")
        for number, old, new in lines:
            print(f"      {number}: {old}  ->  {new}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Apply Python version change?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    for path, new_text, _lines in changes:
        _common.write_text(path, new_text)
    print(f"\n  Updated {len(changes)} file(s) to Python {dotted}.")
    print("  Reminder: run 'uv sync' to regenerate uv.lock and the virtualenv.")
    return 0


def main() -> None:
    """Parse arguments and run the Python-version update."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "version",
        nargs="?",
        default=DEFAULT_VERSION,
        help=f"Python version to set (default: {DEFAULT_VERSION}).",
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would change without writing."
    )
    args = parser.parse_args()

    root = _common.find_root()
    try:
        exit_code = run(root, args.version, assume_yes=args.yes, dry_run=args.dry_run)
    except ValueError as error:
        sys.exit(f"ERROR: {error}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
