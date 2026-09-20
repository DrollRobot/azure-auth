"""Shared helpers for the one-time template-setup scripts in this folder.

These scripts turn a fresh clone of the template into a real project (rename,
strip template headers, set the GitHub user, choose a license, etc.). They use
only the Python standard library so they run with a bare ``python`` or ``uv run``
before any dependencies are installed.

Every scanning script walks the project with :func:`iter_text_files`, which skips
binary files, virtualenvs, VCS metadata, and this ``template_setup`` folder itself
so the scripts never rewrite or report their own source.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path

# Directory holding these setup scripts. Excluded from every scan so a script
# never edits or flags itself (each one contains the literal strings it searches
# for, e.g. the template's own package name and "FIXME").
SETUP_DIR = Path(__file__).resolve().parent

# Directory names that are never scanned, regardless of depth.
EXCLUDED_DIR_NAMES = {
    ".local",  # this repo's convention for local-only / untracked files
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "site",  # mkdocs build output
    ".idea",
    ".vscode",
}

# File suffixes treated as binary and skipped by text scans.
BINARY_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".webp",
    ".svg",
    ".zip",
    ".gz",
    ".tar",
    ".7z",
    ".rar",
    ".dll",
    ".exe",
    ".pdb",
    ".bin",
    ".lib",
    ".obj",
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
    ".pyc",
    ".whl",
}


def find_root(start: Path | None = None) -> Path:
    """Walk upward from ``start`` until a directory with ``pyproject.toml`` is found.

    Args:
        start: Directory to begin the search from. Defaults to this file's folder.

    Returns:
        The project root directory.

    Raises:
        RuntimeError: If no ``pyproject.toml`` is found in any parent directory.
    """
    current = (start or SETUP_DIR).resolve()
    while current != current.parent:
        if (current / "pyproject.toml").exists():
            return current
        current = current.parent
    raise RuntimeError("Could not find project root (no pyproject.toml found).")


def iter_text_files(root: Path) -> Iterator[Path]:
    """Yield every readable text file under ``root`` worth scanning.

    Skips excluded directories, binary suffixes, and this ``template_setup``
    folder. Files are yielded in sorted order for stable, reproducible output.

    Args:
        root: Project root to walk.

    Yields:
        Absolute paths to candidate text files.
    """
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path == SETUP_DIR or SETUP_DIR in path.parents:
            continue
        rel = path.relative_to(root)
        if any(part in EXCLUDED_DIR_NAMES for part in rel.parts):
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        yield path


def read_text(path: Path) -> str | None:
    """Read a file as UTF-8 without altering its line endings.

    Args:
        path: File to read.

    Returns:
        The file contents, or ``None`` if the file is not valid UTF-8 text or
        cannot be read (treated as binary/unreadable and skipped by callers).
    """
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            return handle.read()
    except (UnicodeDecodeError, OSError):  # fmt: skip
        return None


def write_text(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` as UTF-8, preserving its existing line endings.

    Args:
        path: File to write.
        text: Full file contents to write.
    """
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def remove_matching(text: str, predicate: Callable[[str], bool]) -> tuple[str, list[str]]:
    """Drop every whole line whose stripped form satisfies ``predicate``.

    Args:
        text: File contents.
        predicate: Returns ``True`` for a stripped line that should be removed.

    Returns:
        A ``(new_text, removed_lines)`` tuple.
    """
    kept: list[str] = []
    removed: list[str] = []
    for line in text.splitlines(keepends=True):
        if predicate(line.strip()):
            removed.append(line.strip())
        else:
            kept.append(line)
    return "".join(kept), removed


def remove_block(text: str, header: str) -> tuple[str, list[str]]:
    """Remove a block that starts at ``header`` and runs to the next blank line.

    A blank line immediately preceding the block is removed with it, so the
    surrounding file keeps a single separating blank line rather than two.

    Args:
        text: File contents.
        header: The exact (stripped) text of the block's first line.

    Returns:
        A ``(new_text, removed_lines)`` tuple.
    """
    lines = text.splitlines(keepends=True)
    kept: list[str] = []
    removed: list[str] = []
    index = 0
    while index < len(lines):
        if lines[index].strip() == header:
            if kept and not kept[-1].strip():
                kept.pop()
            removed.append(lines[index].strip())
            index += 1
            while index < len(lines) and lines[index].strip():
                removed.append(lines[index].strip())
                index += 1
            continue
        kept.append(lines[index])
        index += 1
    return "".join(kept), removed


def remove_section(text: str, header: str, stop_prefix: str) -> tuple[str, list[str]]:
    """Remove a heading section from ``header`` up to the next heading.

    The section runs from its heading line until (but not including) the next
    line whose stripped form starts with ``stop_prefix`` (or end of file). The
    blank line that separated it from the following heading is consumed too.

    Args:
        text: File contents.
        header: The exact (stripped) text of the section heading.
        stop_prefix: Prefix that marks the start of the next section.

    Returns:
        A ``(new_text, removed_lines)`` tuple.
    """
    lines = text.splitlines(keepends=True)
    kept: list[str] = []
    removed: list[str] = []
    index = 0
    while index < len(lines):
        if lines[index].strip() == header:
            removed.append(lines[index].strip())
            index += 1
            while index < len(lines) and not lines[index].lstrip().startswith(stop_prefix):
                if lines[index].strip():
                    removed.append(lines[index].strip())
                index += 1
            continue
        kept.append(lines[index])
        index += 1
    return "".join(kept), removed


def remove_region(
    text: str, start_text: str, end_marker: str, *, blank: str
) -> tuple[str, list[str]]:
    """Remove a multi-paragraph region between two markers.

    Removes from the line equal to ``start_text`` through the first later line
    that contains ``end_marker`` (inclusive), spanning any blank lines in
    between. One adjacent blank line is trimmed to avoid leaving a double gap:
    ``blank="leading"`` drops the blank before the region, ``blank="trailing"``
    the blank after it.

    Args:
        text: File contents.
        start_text: The exact (stripped) text of the region's first line.
        end_marker: Substring identifying the region's last line.
        blank: Which adjacent blank line to trim (``"leading"`` or ``"trailing"``).

    Returns:
        A ``(new_text, removed_lines)`` tuple.
    """
    lines = text.splitlines(keepends=True)
    kept: list[str] = []
    removed: list[str] = []
    index = 0
    while index < len(lines):
        if lines[index].strip() == start_text:
            if blank == "leading" and kept and not kept[-1].strip():
                kept.pop()
            removed.append(lines[index].strip())
            index += 1
            while index < len(lines):
                if lines[index].strip():
                    removed.append(lines[index].strip())
                ended = end_marker in lines[index]
                index += 1
                if ended:
                    break
            if blank == "trailing" and index < len(lines) and not lines[index].strip():
                index += 1
            continue
        kept.append(lines[index])
        index += 1
    return "".join(kept), removed


def force_remove(func: Callable[[str], object], path: str, _exc: BaseException) -> None:
    """Clear a read-only bit and retry a failed deletion (``shutil.rmtree`` hook).

    Windows marks git's packed object files read-only, which makes ``rmtree``
    fail; pass this as ``onexc`` so the offending file is made writable and
    removed.

    Args:
        func: The removal function that failed (e.g. ``os.unlink``).
        path: Path that could not be removed.
        _exc: The exception that was raised (unused).
    """
    os.chmod(path, stat.S_IWRITE)
    func(path)


def confirm(prompt: str, *, assume_yes: bool = False) -> bool:
    """Ask the user a yes/no question on the terminal.

    Args:
        prompt: Question to display (without the ``[y/n]`` suffix).
        assume_yes: When ``True``, return ``True`` without prompting. Used by the
            orchestrator so the user confirms once instead of per step.

    Returns:
        ``True`` for yes, ``False`` for no.
    """
    if assume_yes:
        return True
    while True:
        answer = input(f"{prompt} [y/n] ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  Please answer 'y' or 'n'.")


def prompt_value(prompt: str, *, default: str = "") -> str:
    """Prompt for a single line of input with an optional default.

    Args:
        prompt: Text to display before the input cursor.
        default: Value returned when the user presses Enter without typing.

    Returns:
        The entered value, or ``default`` if nothing was entered.
    """
    suffix = f" [{default}]" if default else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer or default


def section(title: str) -> None:
    """Print a labelled section header to separate steps in the output.

    Args:
        title: Section title.
    """
    print()
    print(f"== {title} ==")


def info(label: str, value: str) -> None:
    """Print an aligned ``label: value`` line.

    Args:
        label: Short field name.
        value: Field value.
    """
    print(f"  {label + ':':<20}{value}")


def render_table(rows: list[tuple[object, ...]], headers: list[str]) -> str:
    """Render rows as a simple fixed-width text table.

    Args:
        rows: Sequence of rows; each row has one cell per header.
        headers: Column headers.

    Returns:
        The formatted table as a single string (no trailing newline).
    """
    widths = [len(str(header)) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))

    lines = [
        "  ".join(str(header).ljust(widths[index]) for index, header in enumerate(headers)),
        "  ".join("-" * width for width in widths),
    ]
    lines.extend(
        "  ".join(str(cell).ljust(widths[index]) for index, cell in enumerate(row)) for row in rows
    )
    return "\n".join(lines)
