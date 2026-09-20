"""Raise every direct dependency's lower-version bound to the latest allowed.

For each dependency declared in ``[project.dependencies]``, every
``[project.optional-dependencies]`` extra, and every ``[dependency-groups]``
table, this sets the ``>=`` floor to the newest version the project's existing
upper bounds already permit, sourced from ``uv.lock``.

The flow is index-aware and cap-respecting by design:

  1. ``uv lock --upgrade`` resolves the latest version of every dependency that
     still satisfies the bounds in pyproject.toml (honoring the configured index,
     ``exclude-newer``, and any ``[tool.uv]`` constraints).
  2. Each direct dependency's ``>=`` floor is raised to its locked version.
  3. ``uv tree --outdated`` reports anything a *newer major* still holds back.

Floors are only ever raised to a version the current upper bound allows, so the
result is never an unsatisfiable constraint. Crossing an upper bound (a new
major) is deliberately left as a manual decision -- see AGENTS.RELEASING.md --
and is only reported here, never applied. Upper bounds, extras, environment
markers, and every comment in pyproject.toml are preserved untouched.

Not modified: dependencies without a ``>=`` floor (e.g. an unpinned name or an
exact ``==`` pin), dependencies absent from uv.lock (marker-gated backports or
git/path sources), and ``[tool.uv] constraint-dependencies`` (security pins,
managed by hand per the releasing doc).

Usage:
    uv run scripts/update_floors.py
    uv run scripts/update_floors.py --dry-run     # preview from the current lock
    uv run scripts/update_floors.py --no-lock     # skip 'uv lock'; use the lock as-is
    uv run scripts/update_floors.py -y            # answer every prompt with 'yes'

Requirements:
    - Run from anywhere inside the project (the root is found automatically).
    - ``uv`` installed and the project managed with uv.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import _cli as cli

if sys.version_info >= (3, 11):  # noqa: UP036 # allows compatibility back to 3.10
    import tomllib
else:
    import tomli as tomllib

# Version of this helper script itself. Bump on every change so copies in other
# repos can be compared: patch = bugfix, minor = new flag/behavior, major =
# breaking CLI change.
__version__ = "1.1.0"

# The distribution name at the start of a PEP 508 requirement, plus optional
# extras (e.g. ``mkdocstrings[python]``). The rest of the string is the
# specifier set and any environment marker, which this script leaves alone.
_NAME_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?")

# The first ``>=`` lower bound and its version token (up to the next comma,
# semicolon, or space that begins the upper bound or marker).
_FLOOR_RE = re.compile(r">=\s*(?P<version>[^,;\s]+)")


@dataclass(frozen=True)
class Bump:
    """A single floor raise for one dependency.

    Attributes:
        name: PEP 503 normalized package name.
        original: The requirement string exactly as written in pyproject.toml.
        updated: The requirement string with its ``>=`` floor raised.
        old_floor: The floor version being replaced.
        new_floor: The version it is raised to (the version locked in uv.lock).
    """

    name: str
    original: str
    updated: str
    old_floor: str
    new_floor: str


def normalize_name(name: str) -> str:
    """Return the PEP 503 normalized form of a distribution name.

    Args:
        name: A distribution name as written by a human (any case, ``.``/``_``
            separators).

    Returns:
        The normalized name: lower-cased with runs of ``-``, ``_``, and ``.``
        collapsed to a single ``-`` (how uv.lock records names).
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_name(requirement: str) -> str | None:
    """Extract and normalize the distribution name from a requirement string.

    Args:
        requirement: A PEP 508 requirement string, e.g. ``mkdocs>=1.6,<2``.

    Returns:
        The normalized name, or ``None`` if the string does not begin with a
        recognizable distribution name.
    """
    match = _NAME_RE.match(requirement.strip())
    return normalize_name(match.group("name")) if match else None


def floor_version(requirement: str) -> str | None:
    """Return the first ``>=`` lower-bound version in a requirement, if any.

    Args:
        requirement: A PEP 508 requirement string.

    Returns:
        The floor version (e.g. ``1.6``), or ``None`` if the requirement has no
        ``>=`` clause.
    """
    match = _FLOOR_RE.search(requirement)
    return match.group("version") if match else None


def raise_floor(requirement: str, new_version: str) -> str:
    """Return ``requirement`` with its first ``>=`` floor set to ``new_version``.

    Only the version token after the first ``>=`` is replaced; extras, the upper
    bound, and any environment marker are left untouched. A requirement with no
    ``>=`` clause is returned unchanged.

    Args:
        requirement: A PEP 508 requirement string.
        new_version: The version to set as the new lower bound.

    Returns:
        The rewritten requirement string.
    """
    return _FLOOR_RE.sub(f">={new_version}", requirement, count=1)


def iter_dependencies(pyproject: dict[str, Any]) -> list[str]:
    """Collect every string requirement declared in a parsed pyproject.toml.

    Reads ``[project.dependencies]``, every ``[project.optional-dependencies]``
    extra, and every ``[dependency-groups]`` table. Non-string group entries
    (``{include-group = ...}``) are ignored.

    Args:
        pyproject: The parsed pyproject.toml document.

    Returns:
        The requirement strings, in declaration order (duplicates preserved).
    """
    deps: list[str] = []
    project = pyproject.get("project")
    if isinstance(project, dict):
        raw = project.get("dependencies")
        if isinstance(raw, list):
            deps.extend(item for item in raw if isinstance(item, str))
        extras = project.get("optional-dependencies")
        if isinstance(extras, dict):
            for entries in extras.values():
                if isinstance(entries, list):
                    deps.extend(item for item in entries if isinstance(item, str))
    groups = pyproject.get("dependency-groups")
    if isinstance(groups, dict):
        for entries in groups.values():
            if isinstance(entries, list):
                deps.extend(item for item in entries if isinstance(item, str))
    return deps


def locked_versions(lock: dict[str, Any]) -> dict[str, str]:
    """Map each package in a parsed uv.lock to its resolved version.

    Args:
        lock: The parsed uv.lock document.

    Returns:
        A ``{normalized_name: version}`` mapping over every ``[[package]]``.
    """
    versions: dict[str, str] = {}
    packages = lock.get("package")
    if isinstance(packages, list):
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            version = package.get("version")
            if isinstance(name, str) and isinstance(version, str):
                versions[normalize_name(name)] = version
    return versions


def build_bumps(
    dependencies: list[str], locked: dict[str, str]
) -> tuple[list[Bump], list[tuple[str, str]]]:
    """Compute the floor raises and record why any dependency is skipped.

    Args:
        dependencies: Requirement strings from pyproject.toml.
        locked: The ``{normalized_name: version}`` map from uv.lock.

    Returns:
        A ``(bumps, skipped)`` tuple. ``bumps`` lists the floor raises to apply;
        ``skipped`` lists ``(name_or_requirement, reason)`` for every dependency
        that is not raised, including those already at their locked version, so
        the plan accounts for every declared dependency.
    """
    bumps: list[Bump] = []
    skipped: list[tuple[str, str]] = []
    seen: set[str] = set()
    for requirement in dependencies:
        if requirement in seen:
            continue
        seen.add(requirement)
        name = requirement_name(requirement)
        if name is None:
            skipped.append((requirement, "unrecognized requirement"))
            continue
        old_floor = floor_version(requirement)
        if old_floor is None:
            skipped.append((name, "no >= lower bound"))
            continue
        new_floor = locked.get(name)
        if new_floor is None:
            skipped.append((name, "not in uv.lock (marker-gated or a source dependency)"))
            continue
        if new_floor == old_floor:
            skipped.append((name, f"already at latest allowed ({new_floor})"))
            continue
        updated = raise_floor(requirement, new_floor)
        bumps.append(Bump(name, requirement, updated, old_floor, new_floor))
    return bumps, skipped


def apply_bumps(text: str, bumps: list[Bump]) -> str:
    """Rewrite the pyproject.toml text with each planned floor raise.

    Replaces the quoted requirement string in place, so surrounding formatting
    and comments are untouched. A requirement declared identically in more than
    one table is updated in every occurrence.

    Args:
        text: The pyproject.toml contents.
        bumps: The floor raises to apply.

    Returns:
        The rewritten text.
    """
    for bump in bumps:
        replaced = False
        for quote in ('"', "'"):
            needle = f"{quote}{bump.original}{quote}"
            if needle in text:
                text = text.replace(needle, f"{quote}{bump.updated}{quote}")
                replaced = True
        if not replaced:
            cli.die(f"Could not locate '{bump.original}' in pyproject.toml to update.")
    return text


def find_root() -> Path:
    """Locate the project root by walking up to the nearest pyproject.toml.

    Returns:
        The directory containing pyproject.toml.
    """
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        if (parent / "pyproject.toml").is_file():
            return parent
    cli.die("Could not locate the project root (no pyproject.toml found).")


def report_outdated() -> None:
    """Show direct dependencies a newer major still holds back behind an upper bound."""
    cli.section("Upgrades still blocked by upper bounds")
    cli.info("Note", "any '(latest: ...)' below is a new major held back by a cap")
    cli.run(["uv", "tree", "--outdated", "--depth", "1", "--all-groups"])


def parse_args() -> argparse.Namespace:
    """Parse the command line.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="preview floor changes from the current uv.lock without writing or locking",
    )
    parser.add_argument(
        "--no-lock",
        action="store_true",
        help="use the existing uv.lock as-is; do not run 'uv lock'",
    )
    parser.add_argument(
        "-y", "--yes", action="store_true", help="assume 'yes' to every confirmation prompt"
    )
    return parser.parse_args()


def main() -> None:
    """Run the interactive floor-raising flow."""
    args = parse_args()
    cli.set_assume_yes(args.yes)
    # A dry run must not mutate anything, so it never locks and reads the lock as-is.
    do_lock = not args.no_lock and not args.dry_run

    root = find_root()
    pyproject_path = root / "pyproject.toml"
    lock_path = root / "uv.lock"

    cli.info("Script version", __version__)

    cli.section("Raise dependency floors to latest allowed")
    cli.info("Project root", str(root))

    if do_lock:
        cli.section("Step: refresh lockfile")
        cli.step("Run 'uv lock --upgrade' to resolve the latest allowed versions?")
        cli.run(["uv", "lock", "--upgrade"])
    elif args.dry_run:
        cli.info("Note", "dry run: plan reflects the current uv.lock (not re-resolved)")
    else:
        cli.info("Note", "using the existing uv.lock (--no-lock)")

    if not lock_path.is_file():
        cli.die("uv.lock not found; run 'uv lock' first or drop --no-lock.")

    pyproject_text = pyproject_path.read_text(encoding="utf-8")
    pyproject_data = tomllib.loads(pyproject_text)
    lock_data = tomllib.loads(lock_path.read_text(encoding="utf-8"))

    bumps, skipped = build_bumps(iter_dependencies(pyproject_data), locked_versions(lock_data))

    cli.section("Planned floor changes")
    for name, reason in skipped:
        cli.info(name, f"skipped ({reason})")
    if not bumps:
        cli.success("  All floors already at the latest allowed versions; nothing to change.")
        report_outdated()
        return
    for bump in bumps:
        cli.info(bump.name, f">={bump.old_floor}  ->  >={bump.new_floor}")

    if args.dry_run:
        cli.info("Result", "dry run; nothing written")
        return

    cli.section("Step: update pyproject.toml")
    cli.step(f"Raise {len(bumps)} floor(s) in pyproject.toml?")
    pyproject_path.write_text(apply_bumps(pyproject_text, bumps), encoding="utf-8")
    cli.success(f"  Updated {len(bumps)} floor(s).")

    if do_lock:
        cli.section("Step: re-lock")
        cli.step("Run 'uv lock' to record the new floors in uv.lock?")
        cli.run(["uv", "lock"])

    report_outdated()

    cli.section("Done")
    cli.success(f"  Raised {len(bumps)} floor(s) to the latest allowed versions.")
    cli.info(
        "Reminder",
        "run 'uv sync --all-groups --all-extras' and the test suite before committing.",
    )


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):  # fmt: skip
        print()
        sys.exit(130)
