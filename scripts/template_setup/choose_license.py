"""Pick one license, fill in the copyright line, and delete the rest.

The template ships four candidate licenses:

    LICENSE.mit.FIXME
    LICENSE.apache.FIXME
    LICENSE.gnu.FIXME
    LICENSE.proprietary.FIXME

This script lets you choose one, renames it to ``LICENSE`` (no extension),
substitutes the copyright year and holder name into the placeholders, and
deletes the unchosen candidates.

Usage:
    uv run scripts/template_setup/choose_license.py
    uv run scripts/template_setup/choose_license.py --license mit --year 2026 --name "Ada Lovelace"
    uv run scripts/template_setup/choose_license.py --license proprietary --year 2026 \
        --name "Ada Lovelace" --company "Acme Corp"
"""

from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

import _common

# key -> candidate file name shipped by the template.
CANDIDATES = {
    "mit": "LICENSE.mit.FIXME",
    "apache": "LICENSE.apache.FIXME",
    "gnu": "LICENSE.gnu.FIXME",
    "proprietary": "LICENSE.proprietary.FIXME",
}

# The GNU GPL text carries its own copyright notice and takes no per-project
# name, so name/year substitution is skipped for it.
_NEEDS_HOLDER = {"mit", "apache", "proprietary"}

# Proprietary additionally distinguishes the copyright holder (author) from the
# owning company, so it prompts for a company name on top of the holder name.
_NEEDS_COMPANY = {"proprietary"}


def _fill_placeholders(text: str, year: str, name: str, company: str = "") -> str:
    """Substitute the copyright year, holder, and company into placeholders.

    Every candidate uses the labeled brace form: ``FIXME{year}``,
    ``FIXME{holder}``, and (proprietary only) ``FIXME{company}``.

    Args:
        text: License file contents.
        year: Copyright year.
        name: Copyright holder (author) name.
        company: Owning company name; used by the proprietary license only.

    Returns:
        The license text with placeholders filled in.
    """
    replacements = [
        ("FIXME{year}", year),
        ("FIXME{holder}", name),
        ("FIXME{company}", company),
    ]
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def _available(root: Path) -> dict[str, Path]:
    """Return the candidate licenses that exist in the project.

    Args:
        root: Project root directory.

    Returns:
        Mapping of license key to its file path, for candidates present on disk.
    """
    return {key: root / name for key, name in CANDIDATES.items() if (root / name).exists()}


def run(
    root: Path,
    *,
    key: str | None = None,
    year: str | None = None,
    name: str | None = None,
    company: str | None = None,
    assume_yes: bool = False,
    dry_run: bool = False,
) -> int:
    """Choose a license, fill its copyright line, and remove the others.

    Args:
        root: Project root directory.
        key: License key (``mit``/``apache``/``gnu``/``proprietary``); prompt if ``None``.
        year: Copyright year; prompt (default current year) if ``None``.
        name: Copyright holder (author); prompt if ``None``.
        company: Owning company (proprietary only); prompt if ``None``.
        assume_yes: Skip the final confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success, 1 if aborted or unavailable).
    """
    _common.section("Choose a license")

    available = _available(root)
    if not available:
        print("  No LICENSE.*.FIXME candidates found (already chosen?).")
        return 1

    if key is None:
        key = _prompt_choice(available)
    if key not in available:
        print(f"  '{key}' is not available. Choose from: {', '.join(sorted(available))}.")
        return 1

    if key in _NEEDS_HOLDER:
        if year is None:
            year = _common.prompt_value("Copyright year", default=str(datetime.date.today().year))
        if name is None:
            name = _common.prompt_value("Copyright holder name")
    if key in _NEEDS_COMPANY and company is None:
        company = _common.prompt_value("Company name")
    year = year or ""
    name = name or ""
    company = company or ""

    chosen = available[key]
    others = [path for other_key, path in available.items() if other_key != key]

    _common.info("Chosen", f"{chosen.name} -> LICENSE")
    if key in _NEEDS_HOLDER:
        copyright_line = f"{year} {name}".strip()
        if key in _NEEDS_COMPANY:
            copyright_line = f"{copyright_line}, {company}".strip(", ")
        _common.info("Copyright", copyright_line)
    if others:
        print(f"  Delete: {', '.join(path.name for path in others)}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Apply license choice?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    text = _common.read_text(chosen) or ""
    if key in _NEEDS_HOLDER:
        text = _fill_placeholders(text, year, name, company)
    _common.write_text(root / "LICENSE", text)
    chosen.unlink()
    for path in others:
        path.unlink()

    print("\n  Wrote LICENSE.")
    print("  Reminder: update the license badge/link in README.md to match.")
    return 0


def _prompt_choice(available: dict[str, Path]) -> str:
    """Prompt the user to pick one of the available licenses by number.

    Args:
        available: Mapping of license key to file path.

    Returns:
        The chosen license key.
    """
    keys = sorted(available)
    print("  Available licenses:")
    for index, key in enumerate(keys, start=1):
        print(f"    {index}) {key}")
    while True:
        answer = input("  Choose a license [number]: ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(keys):
            return keys[int(answer) - 1]
        print("  Enter the number of one of the listed licenses.")


def main() -> None:
    """Parse arguments and run the license chooser."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--license", dest="key", choices=sorted(CANDIDATES), help="License to use.")
    parser.add_argument("--year", help="Copyright year (default: current year).")
    parser.add_argument("--name", help="Copyright holder (author) name.")
    parser.add_argument("--company", help="Owning company name (proprietary license only).")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would change without writing."
    )
    args = parser.parse_args()

    root = _common.find_root()
    sys.exit(
        run(
            root,
            key=args.key,
            year=args.year,
            name=args.name,
            company=args.company,
            assume_yes=args.yes,
            dry_run=args.dry_run,
        )
    )


if __name__ == "__main__":
    main()
