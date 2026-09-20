"""Remove the template-setup scaffolding once you are done with it.

After you have renamed the project, stripped the headers, chosen a license, and
worked through the FIXMEs, these setup scripts have served their purpose. This
script deletes them (the whole ``scripts/template_setup/`` folder, including
itself), the unit tests for the dev scripts (the scripts themselves stay --
their tests only matter while developing the template), and any leftover
``LICENSE.*.FIXME`` candidates -- but only once a real ``LICENSE`` file
exists, so you are never left with no license.

It also trims the pyproject.toml lines that only matter while developing the
template itself: the ``--cov=scripts`` coverage flag (the dev-script tests are
deleted here, so scripts coverage would read as untested), the
``scripts/template_setup`` entry in mypy's search path (that folder is gone),
and ``scripts`` from mypy's ``files``. The scripts themselves stay -- but they
are the template's code, not the project's, so a downstream project should not
have its type check fail on them. Run mypy on them by path
(``uv run mypy scripts``) if you do edit them.

It does NOT edit prose for you; it prints reminders for the manual bits (such as
working through the FIXMEs left in the project's own files).

Usage:
    uv run scripts/template_setup/cleanup.py
    uv run scripts/template_setup/cleanup.py --dry-run
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

import _common

REMINDERS = [
    "Run find_fixmes (before deleting) to confirm no FIXMEs remain.",
]

# pyproject.toml snippets that only matter while developing the template
# itself. Each (old, new) pair is an exact-string replacement; a missing
# snippet means pyproject.toml drifted from the template, so cleanup stops
# instead of guessing (fail early, fail loudly).
PYPROJECT_EDITS = [
    # Dev-script coverage: the tests covering scripts/ are deleted below, so
    # keeping the flag would only drag the project's coverage number down.
    ('    "--cov=scripts",\n', ""),
    # scripts/template_setup/ is deleted below; scripts/ stays in mypy's search
    # path so an import from a remaining dev script still resolves.
    ('mypy_path = ["scripts", "scripts/template_setup"]', 'mypy_path = ["scripts"]'),
    # The dev scripts are the template's code and are not type-checked as part
    # of the project: drop them from mypy's files so a downstream
    # `uv run mypy` covers src/ and tests/ only.
    ('files = ["src", "tests", "scripts"]', 'files = ["src", "tests"]'),
]


def strip_template_config(text: str) -> str:
    """Remove the template-only lines from pyproject.toml content.

    Args:
        text: Current pyproject.toml content.

    Returns:
        The content with every :data:`PYPROJECT_EDITS` replacement applied.

    Raises:
        ValueError: If an expected snippet is missing, meaning pyproject.toml
            has drifted from the template and needs manual attention.
    """
    for old, new in PYPROJECT_EDITS:
        if old not in text:
            raise ValueError(f"pyproject.toml has drifted from the template: {old!r} not found")
        text = text.replace(old, new)
    return text


def dev_script_tests(root: Path) -> list[Path]:
    """Find the unit tests that cover the dev scripts and setup scripts.

    The dev scripts in ``scripts/`` stay useful in the new project, but their
    unit tests only matter while developing the template itself. A test file is
    matched to its script by name: ``tests/test_<name>.py`` covers
    ``scripts/<name>.py`` or ``scripts/template_setup/<name>.py``. Tests with no
    matching script (the project's own tests) are kept.

    Args:
        root: Project root directory.

    Returns:
        Test files that cover an existing script, in sorted order.
    """
    script_dirs = (root / "scripts", root / "scripts" / "template_setup")
    tests: list[Path] = []
    for test_file in sorted((root / "tests").glob("test_*.py")):
        script_name = test_file.name.removeprefix("test_")
        if any((folder / script_name).exists() for folder in script_dirs):
            tests.append(test_file)
    return tests


def _gather_targets(root: Path) -> list[Path]:
    """Collect the scaffolding paths that are safe to delete.

    Args:
        root: Project root directory.

    Returns:
        Paths to delete: leftover license candidates (only when a real
        ``LICENSE`` already exists), the unit tests for the dev scripts, and
        the setup-scripts folder itself.
    """
    targets: list[Path] = []
    if (root / "LICENSE").exists():
        targets.extend(sorted(root.glob("LICENSE.*.FIXME")))
    targets.extend(dev_script_tests(root))
    targets.append(_common.SETUP_DIR)
    return targets


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False) -> int:
    """Delete the template-setup scaffolding and trim template-only config.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.

    Returns:
        Process exit code (0 on success, 1 if aborted or pyproject.toml has
        drifted from the template).
    """
    _common.section("Clean up template scaffolding")

    # Validate the pyproject.toml edit up front so a drifted file aborts the
    # whole cleanup before any tests are deleted.
    pyproject_path = root / "pyproject.toml"
    pyproject_text = _common.read_text(pyproject_path)
    if pyproject_text is None:
        print("  ERROR: pyproject.toml is not readable as UTF-8 text.")
        return 1
    try:
        stripped_pyproject = strip_template_config(pyproject_text)
    except ValueError as error:
        print(f"  ERROR: {error}")
        return 1

    targets = _gather_targets(root)
    print("  Will delete:")
    for path in targets:
        suffix = "/" if path.is_dir() else ""
        print(f"    {path.relative_to(root)}{suffix}")

    if (root / "LICENSE").exists() is False and any(root.glob("LICENSE.*.FIXME")):
        print("  (Keeping LICENSE.*.FIXME: no LICENSE chosen yet -- run choose_license first.)")

    print("\n  Will edit:")
    print("    pyproject.toml (drop --cov=scripts; drop scripts/template_setup from mypy_path;")
    print("                    drop scripts from mypy files)")

    print("\n  Reminders (not done automatically):")
    for reminder in REMINDERS:
        print(f"    - {reminder}")

    if dry_run:
        print("\n  (dry run -- nothing deleted)")
        return 0

    print()
    if not _common.confirm("Delete the scaffolding listed above?", assume_yes=assume_yes):
        print("  Aborted; nothing deleted.")
        return 1

    setup_dir = _common.SETUP_DIR
    # Move out of the setup folder so it can be removed while this script runs.
    os.chdir(root)
    for path in targets:
        if path == setup_dir:
            continue
        path.unlink()
        print(f"  Deleted {path.relative_to(root)}")

    _common.write_text(pyproject_path, stripped_pyproject)
    print("  Edited pyproject.toml")

    try:
        shutil.rmtree(setup_dir, onexc=_common.force_remove)
        print(f"  Deleted {setup_dir.relative_to(root)}/")
    except OSError as error:
        print(f"  Could not remove {setup_dir.relative_to(root)}/ ({error}).")
        print("  Delete it manually -- it is no longer needed.")

    print("\n  Cleanup complete.")
    return 0


def main() -> None:
    """Parse arguments and run cleanup."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be deleted without deleting."
    )
    args = parser.parse_args()

    root = _common.find_root()
    sys.exit(run(root, assume_yes=args.yes, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
