"""Replace the template author's GitHub username with your own.

Finds every occurrence of the template author's username (``OLD_USER``, matched
case-insensitively) -- in clone URLs, badges, docs, and config -- and replaces
it with the username you supply, written exactly as you type it.

Usage:
    uv run scripts/template_setup/set_github_user.py your-username
    uv run scripts/template_setup/set_github_user.py your-username --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import _common

OLD_USER = "drollrobot"
_OLD_RE = re.compile(re.escape(OLD_USER), re.IGNORECASE)

# GitHub usernames: 1-39 chars, alphanumeric or single hyphens.
_VALID_USER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")


def _plan_changes(root: Path, username: str) -> list[tuple[Path, str, list[tuple[int, str]]]]:
    """Find files referencing the old username and compute their replacements.

    Args:
        root: Project root.
        username: Replacement username.

    Returns:
        A list of ``(path, new_text, hits)`` tuples, where ``hits`` is a list of
        ``(line_number, line_text)`` for each matching line.
    """
    changes: list[tuple[Path, str, list[tuple[int, str]]]] = []
    for path in _common.iter_text_files(root):
        text = _common.read_text(path)
        if text is None or not _OLD_RE.search(text):
            continue
        hits = [
            (number, line.strip())
            for number, line in enumerate(text.splitlines(), start=1)
            if _OLD_RE.search(line)
        ]
        changes.append((path, _OLD_RE.sub(username, text), hits))
    return changes


def run(root: Path, username: str, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Replace the old GitHub username with ``username`` across the project.

    Args:
        root: Project root directory.
        username: Replacement GitHub username.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success, 1 if aborted).
    """
    _common.section("Set GitHub username")
    _common.info("Replace", f"{OLD_USER} -> {username}")
    if not _VALID_USER_RE.match(username):
        print(f"  WARNING: '{username}' is not a typical GitHub username; continuing anyway.")

    changes = _plan_changes(root, username)
    if not changes:
        print(f"  No occurrences of '{OLD_USER}' found.")
        return 0

    print(f"\n  Files to update ({len(changes)}):")
    for path, _new, hits in changes:
        print(f"    {path.relative_to(root)}")
        for number, line in hits:
            print(f"      {number}: {line}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Apply replacement?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    for path, new_text, _hits in changes:
        _common.write_text(path, new_text)
    print(f"\n  Updated {len(changes)} file(s).")
    return 0


def main() -> None:
    """Parse arguments and run the username replacement."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("username", help="Your GitHub username.")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would change without writing."
    )
    args = parser.parse_args()

    root = _common.find_root()
    sys.exit(run(root, args.username, assume_yes=args.yes, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
