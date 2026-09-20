"""Remove the secret-storage machinery from the config package.

For projects whose configuration holds no secrets. The machinery is the
backend dispatcher, every credential backend, and their test modules:

    src/<package>/config/secrets.py       the backend dispatcher
    src/<package>/config/*_backend.py     every credential backend
    tests/test_config_secrets.py          the dispatcher's unit tests
    tests/test_keyring_backend.py         the keyring backend's unit tests
    tests/test_keyvault_backend.py        the Key Vault backend's unit tests

Only those files are deleted; nothing else is edited. The rest of the config
system imports the machinery lazily and only when the settings schema marks a
field ``secret``, so with no secret fields it keeps working untouched: the
resolver skips the secret layer, config.toml validation stops accepting
``credential_backend`` (and backend-declared keys), and the config CLI stops
offering ``set-secret``/``delete-secret``.

"With no secret fields" is a precondition, not a hope: before deleting
anything this script parses ``src/<package>/config/schema.py`` and refuses
when ``Settings`` still declares a secret field, naming the fields. Removing
the machinery under them leaves a package that fails on every run, so the
schema edit comes first. ``--force`` deletes anyway, with a warning.

Manual follow-up (this script only deletes files):

- Delete the ``keyring`` and ``keyvault`` extras in ``pyproject.toml``'s
  ``[project.optional-dependencies]``, then run ``uv lock`` and ``uv sync``.

Usage:
    uv run scripts/template_setup/remove_secret_storage.py
    uv run scripts/template_setup/remove_secret_storage.py --dry-run
    uv run scripts/template_setup/remove_secret_storage.py --force
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

import _common

# Fixed-path files deleted wholesale (relative to the project root).
_DELETE = [
    "tests/test_config_secrets.py",
    "tests/test_keyring_backend.py",
    "tests/test_keyvault_backend.py",
]

# The dispatcher and every backend, located by glob because the package
# directory carries the project's own (possibly already renamed) import name.
_DELETE_GLOBS = [
    "src/*/config/secrets.py",
    "src/*/config/*_backend.py",
]

# The settings schema, located the same way, and the class the precondition
# check inspects inside it.
_SCHEMA_GLOB = "src/*/config/schema.py"
_SETTINGS_CLASS = "Settings"


def find_schema(root: Path) -> Path | None:
    """Return the project's settings schema module, or None when absent.

    Args:
        root: Project root directory.

    Returns:
        ``src/<package>/config/schema.py``, or None when the config system
        is not present.
    """
    return next(iter(sorted(root.glob(_SCHEMA_GLOB))), None)


def _declares_secret(value: ast.expr | None) -> bool:
    """Return True when a field declaration marks the field as a secret.

    Recognizes both supported spellings: the schema's ``secret(...)`` helper
    and a bare ``field(metadata={"secret": True})``.

    Args:
        value: The right-hand side of an annotated class attribute.

    Returns:
        True when the declaration classifies the field as a secret.
    """
    if not isinstance(value, ast.Call):
        return False
    func = value.func
    called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    if called == "secret":
        return True
    if called != "field":
        return False
    for keyword in value.keywords:
        if keyword.arg != "metadata" or not isinstance(keyword.value, ast.Dict):
            continue
        for key, item in zip(keyword.value.keys, keyword.value.values, strict=True):
            if isinstance(key, ast.Constant) and key.value == "secret":
                return isinstance(item, ast.Constant) and bool(item.value)
    return False


def find_secret_fields(schema_path: Path) -> list[str]:
    """Return the ``Settings`` fields still marked secret, in declaration order.

    The module is parsed, never imported, so this runs before any dependency
    is installed and never executes project code. An unreadable or
    unparseable schema yields no names: this check exists to stop a known-bad
    removal, not to become a second syntax checker.

    Args:
        schema_path: Location of the project's ``config/schema.py``.

    Returns:
        The names of every secret-classified field of ``Settings``.
    """
    try:
        tree = ast.parse(schema_path.read_text(encoding="utf-8"))
    except OSError, SyntaxError, ValueError:
        return []
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != _SETTINGS_CLASS:
            continue
        for statement in node.body:
            if (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
                and _declares_secret(statement.value)
            ):
                names.append(statement.target.id)
    return names


def plan_deletions(root: Path) -> list[Path]:
    """Return the secret-storage files that exist and should be deleted.

    Args:
        root: Project root directory.

    Returns:
        The dispatcher and backend files (wherever the package lives under
        ``src/``) followed by the fixed-path files from :data:`_DELETE`,
        existing paths only.
    """
    paths: list[Path] = []
    for pattern in _DELETE_GLOBS:
        paths.extend(sorted(root.glob(pattern)))
    paths.extend(root / relpath for relpath in _DELETE if (root / relpath).exists())
    return paths


def run(root: Path, *, assume_yes: bool = False, dry_run: bool = False, force: bool = False) -> int:
    """Delete the secret-storage machinery and its test suites.

    Refuses before deleting anything when the settings schema still declares
    secret fields, unless *force* is set.

    Args:
        root: Project root directory.
        assume_yes: Skip the confirmation prompt.
        dry_run: Show the plan without changing anything.
        force: Delete even while the schema still declares secret fields.

    Returns:
        Process exit code (0 on success or when nothing matched, 1 if
        aborted or refused).
    """
    _common.section("Remove the secret-storage machinery")

    deletions = plan_deletions(root)
    if not deletions:
        print("\n  No secret-storage machinery found; nothing to remove.")
        return 0

    schema_path = find_schema(root)
    secret_fields = find_secret_fields(schema_path) if schema_path is not None else []
    if secret_fields and schema_path is not None:
        where = schema_path.relative_to(root)
        listing = ", ".join(secret_fields)
        if not force:
            print(f"\n  {where} still declares {len(secret_fields)} secret field(s):")
            for name in secret_fields:
                print(f"    {name}")
            print(
                "\n  Removing the machinery under them leaves a package that cannot\n"
                "  resolve its own configuration: every run fails with 'the settings\n"
                "  schema marks <field> as secret, but the secret-storage machinery\n"
                "  (secrets.py) has been removed'. Edit the schema first -- replace\n"
                "  those fields with option(...) or drop them -- then re-run.\n"
                "\n  Pass --force to delete the machinery anyway."
            )
            print("\n  Refused; nothing changed.")
            return 1
        print(f"\n  WARNING: --force: {where} still declares secret field(s): {listing}.")
        print("  Configuration will not resolve until they are removed from the schema.")

    print(f"\n  Files to delete ({len(deletions)}):")
    for path in deletions:
        print(f"    {path.relative_to(root)}")

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Remove the secret-storage machinery?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    for path in deletions:
        path.unlink()
        print(f"  Deleted {path.relative_to(root)}")

    print(f"\n  Removed the secret-storage machinery: {len(deletions)} path(s) deleted.")
    print("  Reminder (not done automatically):")
    print("    - Delete the 'keyring' and 'keyvault' extras in pyproject.toml's")
    print("      [project.optional-dependencies], then run 'uv lock' and 'uv sync'.")
    return 0


def main() -> None:
    """Parse arguments and run the secret-storage removal."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would change without writing."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Delete even while the settings schema still declares secret fields.",
    )
    args = parser.parse_args()

    root = _common.find_root()
    sys.exit(run(root, assume_yes=args.yes, dry_run=args.dry_run, force=args.force))


if __name__ == "__main__":
    main()
