"""Run the whole template-to-project transition from one config file.

Edit ``scripts/template_setup.toml`` with your values (project name, GitHub username,
Python/project version, license choice, which optional features to keep,
whether to re-initialize git), then run:

    uv run scripts/template_setup/setup_new_project.py

This validates every field in the config up front -- if anything is wrong,
nothing runs and every problem is listed at once. It then previews every
change every step would make (nothing applied yet), asks for a single
confirmation, and applies everything. ``--dry-run`` stops after the preview;
``-y``/``--yes`` skips the confirmation (the preview still runs first).

``scripts/template_setup.toml`` deliberately lives outside ``scripts/template_setup/``
(this script's own folder) so ``cleanup.py`` -- which deletes that whole
folder -- leaves it in place: ``scripts/compare_to_template.py`` keeps
reading it afterward to know which optional features this project kept.

Steps always execute in this order, regardless of the config file's own
table order: strip template headers -> reset README -> rename -> set GitHub
user -> set Python version -> set project version -> reset changelog -> choose
license -> remove mkdocs (if declined) -> remove keyring backend (if
declined) -> remove Key Vault backend (if declined) -> remove the whole
secret-storage machinery (if declined; replaces the two backend steps) ->
remove the whole config system (if declined; replaces all three) -> remove
private-repo-deps workflow steps (if declined) -> remove the
remote-disposability scripts (if declined) -> remove SECURITY.md (if
declined) -> remove CONTRIBUTING.md (if declined) -> re-initialize git (if
requested). A read-only FIXME report always runs last, whether or not anything
failed.

Each step is also runnable on its own with its own prompts/flags -- see that
script's module docstring (e.g. ``remove_mkdocs.py``). This script does NOT
delete ``scripts/template_setup/`` (``cleanup.py``) -- that stays a separate,
manual step; run it yourself whenever you're ready.

Usage:
    uv run scripts/template_setup/setup_new_project.py
    uv run scripts/template_setup/setup_new_project.py --dry-run
    uv run scripts/template_setup/setup_new_project.py -y
    uv run scripts/template_setup/setup_new_project.py --config path/to/other.toml
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import _common
import choose_license
import find_fixmes
import reinit_git
import remove_config_system
import remove_contributing_guide
import remove_keyring
import remove_keyvault
import remove_mkdocs
import remove_private_repo_deps
import remove_remote_disposable_scripts
import remove_secret_storage
import remove_security_policy
import rename_project
import reset_changelog
import reset_readme
import set_github_user
import set_python_version
import set_version
import strip_template_headers

CONFIG_FILENAME = "template_setup.toml"


@dataclass(frozen=True)
class Config:
    """Fully validated template_setup.toml contents, ready to drive every step."""

    name: str
    github_user: str
    python_version: str
    version: str
    license_key: str
    license_year: str
    license_name: str
    license_company: str
    mkdocs: bool
    config_system: bool
    secret_storage: bool
    keyring: bool
    keyvault: bool
    private_repo_deps: bool
    remote_disposable_scripts: bool
    security_policy: bool
    contributing_guide: bool
    reinit: bool
    branch: str


@dataclass(frozen=True)
class PlannedStep:
    """One orchestrated setup step, already bound to config values.

    Attributes:
        key: The step's module name, e.g. ``rename_project``.
        label: One-line description shown in the preview/summary.
        call: Runs the step; ``call(root, dry_run)`` forwards to the
            underlying script's own ``run(..., assume_yes=True, dry_run=...)``.
        destructive: Whether this step deletes things that cannot be restored.
    """

    key: str
    label: str
    call: Callable[[Path, bool], int]
    destructive: bool = False


def _load_toml(path: Path) -> tuple[dict[str, Any], str | None]:
    """Read and parse ``template_setup.toml``.

    Args:
        path: Path to the config file.

    Returns:
        A ``(raw, error)`` tuple. ``error`` is ``None`` on success; otherwise
        ``raw`` is ``{}`` and ``error`` describes why the file could not be
        loaded (missing, unreadable, or invalid TOML syntax).
    """
    if not path.exists():
        return {}, f"Config file not found: {path}"
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle), None
    except OSError as exc:
        return {}, f"Could not read {path}: {exc}"
    except tomllib.TOMLDecodeError as exc:
        return {}, f"{path} is not valid TOML: {exc}"


def _table(raw: dict[str, Any], name: str, problems: list[str]) -> dict[str, Any]:
    """Return ``raw[name]`` as a dict, recording a problem if it's missing or invalid.

    Args:
        raw: Parsed TOML content.
        name: Top-level table name to look up (e.g. ``"project"``).
        problems: Problem list to append to.

    Returns:
        The table's contents, or ``{}`` if it is missing or not a table.
    """
    value = raw.get(name)
    if not isinstance(value, dict):
        problems.append(f"[{name}] is missing or is not a table.")
        return {}
    return value


def _require_str(table: dict[str, Any], key: str, table_name: str, problems: list[str]) -> str:
    """Return ``table[key]`` as a string, recording a problem if it's missing or invalid.

    Args:
        table: Parsed contents of one TOML table.
        key: Key to look up within the table.
        table_name: The table's name, for the problem message.
        problems: Problem list to append to.

    Returns:
        The value, or ``""`` if it is missing or not a string.
    """
    value = table.get(key)
    if not isinstance(value, str):
        problems.append(f"[{table_name}].{key} is missing or is not a string.")
        return ""
    return value


def _require_bool(table: dict[str, Any], key: str, table_name: str, problems: list[str]) -> bool:
    """Return ``table[key]`` as a bool, recording a problem if it's missing or invalid.

    Args:
        table: Parsed contents of one TOML table.
        key: Key to look up within the table.
        table_name: The table's name, for the problem message.
        problems: Problem list to append to.

    Returns:
        The value, or ``False`` if it is missing or not a boolean.
    """
    value = table.get(key)
    if not isinstance(value, bool):
        problems.append(f"[{table_name}].{key} is missing or is not a true/false value.")
        return False
    return value


def validate_config(root: Path, raw: dict[str, Any]) -> tuple[Config | None, list[str]]:
    """Validate every field in ``raw`` and build a :class:`Config` if there are no problems.

    Scope: config value correctness only -- schema shape (required
    tables/keys present, correct types), per-field validity (reusing each
    step's own existing validator), cross-field constraints, and (only when
    ``git.reinit`` is true) the git pristine-clone guard. Deliberately does
    NOT check repo/filesystem state per step (e.g. whether a license
    candidate file still exists) -- that idempotency handling already lives
    in each step's own ``run()`` and stays there unchanged.

    Args:
        root: Project root directory (used only by the git-reinit guard).
        raw: Parsed TOML content.

    Returns:
        A ``(config, problems)`` tuple. ``config`` is ``None`` whenever
        ``problems`` is non-empty; otherwise every field is valid and
        ``problems == []``.
    """
    problems: list[str] = []

    project = _table(raw, "project", problems)
    license_table = _table(raw, "license", problems)
    features = _table(raw, "features", problems)
    git = _table(raw, "git", problems)

    name = _require_str(project, "name", "project", problems)
    github_user = _require_str(project, "github_user", "project", problems)
    python_version = _require_str(project, "python_version", "project", problems)
    version = _require_str(project, "version", "project", problems)

    license_key = _require_str(license_table, "key", "license", problems)
    license_year = _require_str(license_table, "year", "license", problems)
    license_name = _require_str(license_table, "name", "license", problems)
    license_company = _require_str(license_table, "company", "license", problems)

    mkdocs = _require_bool(features, "mkdocs", "features", problems)
    config_system = _require_bool(features, "config_system", "features", problems)
    secret_storage = _require_bool(features, "secret_storage", "features", problems)
    keyring = _require_bool(features, "keyring", "features", problems)
    keyvault = _require_bool(features, "keyvault", "features", problems)
    private_repo_deps = _require_bool(features, "private_repo_deps", "features", problems)
    remote_disposable_scripts = _require_bool(
        features, "remote_disposable_scripts", "features", problems
    )
    security_policy = _require_bool(features, "security_policy", "features", problems)
    contributing_guide = _require_bool(features, "contributing_guide", "features", problems)

    reinit = _require_bool(git, "reinit", "git", problems)
    branch = _require_str(git, "branch", "git", problems)

    if name:
        try:
            rename_project.derive_names(name)
        except ValueError as exc:
            problems.append(f"[project].name: {exc}")

    if github_user and not github_user.strip():
        problems.append("[project].github_user is empty.")

    if python_version:
        try:
            set_python_version.version_forms(python_version)
        except ValueError as exc:
            problems.append(f"[project].python_version: {exc}")

    if version:
        try:
            set_version.validate(version)
        except ValueError as exc:
            problems.append(f"[project].version: {exc}")

    if license_key and license_key not in choose_license.CANDIDATES:
        problems.append(
            f"[license].key {license_key!r} is not one of: "
            f"{', '.join(sorted(choose_license.CANDIDATES))}."
        )
    elif license_key:
        if license_key in choose_license._NEEDS_HOLDER:
            if not license_year.strip():
                problems.append("[license].year is required for this license.")
            if not license_name.strip():
                problems.append("[license].name is required for this license.")
        if license_key in choose_license._NEEDS_COMPANY and not license_company.strip():
            problems.append("[license].company is required for the proprietary license.")

    if branch and not branch.strip():
        problems.append("[git].branch is empty.")

    # The secret machinery lives inside the config package, and the backends
    # live inside the secret machinery: keeping an inner piece while removing
    # its container is contradictory, so demand an explicit false.
    if not config_system:
        for feature in ("secret_storage", "keyring", "keyvault"):
            if features.get(feature) is True:
                problems.append(
                    f"[features].{feature}=true requires [features].config_system=true "
                    "(it lives inside the config package); set it to false."
                )
    elif not secret_storage:
        for backend in ("keyring", "keyvault"):
            if features.get(backend) is True:
                problems.append(
                    f"[features].{backend}=true requires [features].secret_storage=true "
                    "(the backend lives inside the secret-storage machinery); "
                    "set it to false."
                )

    if reinit and not reinit_git._is_pristine_template_clone(root):
        problems.append(
            "[git].reinit=true, but this no longer looks like a pristine template clone "
            "(git history doesn't start at the template's own root commit). "
            "Set [git].reinit=false, or investigate before re-running."
        )

    if problems:
        return None, problems

    return (
        Config(
            name=name,
            github_user=github_user,
            python_version=python_version,
            version=version,
            license_key=license_key,
            license_year=license_year,
            license_name=license_name,
            license_company=license_company,
            mkdocs=mkdocs,
            config_system=config_system,
            secret_storage=secret_storage,
            keyring=keyring,
            keyvault=keyvault,
            private_repo_deps=private_repo_deps,
            remote_disposable_scripts=remote_disposable_scripts,
            security_policy=security_policy,
            contributing_guide=contributing_guide,
            reinit=reinit,
            branch=branch,
        ),
        [],
    )


def _step_strip_headers() -> PlannedStep:
    """Build the strip-template-headers step (always runs)."""

    def call(root: Path, dry_run: bool) -> int:
        return strip_template_headers.run(root, assume_yes=True, dry_run=dry_run)

    return PlannedStep("strip_template_headers", "Strip template headers", call)


def _step_reset_readme() -> PlannedStep:
    """Build the README-reset step (always runs)."""

    def call(root: Path, dry_run: bool) -> int:
        return reset_readme.run(root, assume_yes=True, dry_run=dry_run)

    return PlannedStep("reset_readme", "Reset the README", call)


def _step_rename(config: Config) -> PlannedStep:
    """Build the project-rename step, bound to ``config.name``."""

    def call(root: Path, dry_run: bool) -> int:
        return rename_project.run(root, config.name, assume_yes=True, dry_run=dry_run)

    return PlannedStep("rename_project", f"Rename project to '{config.name}'", call)


def _step_github_user(config: Config) -> PlannedStep:
    """Build the GitHub-username step, bound to ``config.github_user``."""

    def call(root: Path, dry_run: bool) -> int:
        return set_github_user.run(root, config.github_user, assume_yes=True, dry_run=dry_run)

    return PlannedStep("set_github_user", f"Set GitHub username to '{config.github_user}'", call)


def _step_python_version(config: Config) -> PlannedStep:
    """Build the Python-version step, bound to ``config.python_version``."""

    def call(root: Path, dry_run: bool) -> int:
        return set_python_version.run(root, config.python_version, assume_yes=True, dry_run=dry_run)

    return PlannedStep("set_python_version", f"Set Python version to {config.python_version}", call)


def _step_version(config: Config) -> PlannedStep:
    """Build the project-version step, bound to ``config.version``."""

    def call(root: Path, dry_run: bool) -> int:
        return set_version.run(root, config.version, assume_yes=True, dry_run=dry_run)

    return PlannedStep("set_version", f"Set project version to {config.version}", call)


def _step_reset_changelog() -> PlannedStep:
    """Build the changelog-reset step (always runs)."""

    def call(root: Path, dry_run: bool) -> int:
        return reset_changelog.run(root, assume_yes=True, dry_run=dry_run)

    return PlannedStep("reset_changelog", "Reset the changelog", call)


def _step_license(config: Config) -> PlannedStep:
    """Build the license step, bound to the ``license`` config fields."""

    def call(root: Path, dry_run: bool) -> int:
        return choose_license.run(
            root,
            key=config.license_key,
            year=config.license_year,
            name=config.license_name,
            company=config.license_company,
            assume_yes=True,
            dry_run=dry_run,
        )

    return PlannedStep("choose_license", f"Choose license: {config.license_key}", call)


def _step_remove_mkdocs() -> PlannedStep:
    """Build the mkdocs-removal step (only included when declined)."""

    def call(root: Path, dry_run: bool) -> int:
        return remove_mkdocs.run(root, assume_yes=True, dry_run=dry_run)

    return PlannedStep("remove_mkdocs", "Remove mkdocs (documentation site)", call)


def _step_remove_keyring() -> PlannedStep:
    """Build the keyring-backend-removal step (only included when declined)."""

    def call(root: Path, dry_run: bool) -> int:
        return remove_keyring.run(root, assume_yes=True, dry_run=dry_run)

    return PlannedStep("remove_keyring", "Remove the keyring backend", call)


def _step_remove_keyvault() -> PlannedStep:
    """Build the Key-Vault-backend-removal step (only included when declined)."""

    def call(root: Path, dry_run: bool) -> int:
        return remove_keyvault.run(root, assume_yes=True, dry_run=dry_run)

    return PlannedStep("remove_keyvault", "Remove the Key Vault backend", call)


def _step_remove_secret_storage() -> PlannedStep:
    """Build the secret-storage-removal step (only included when declined).

    Forced: the FIXME schema still declares its example secret fields at
    setup time, and the script would otherwise refuse. It prints a warning
    naming them, which is the reminder to replace them with option(...).
    """

    def call(root: Path, dry_run: bool) -> int:
        return remove_secret_storage.run(root, assume_yes=True, dry_run=dry_run, force=True)

    return PlannedStep("remove_secret_storage", "Remove the secret-storage machinery", call)


def _step_remove_config_system() -> PlannedStep:
    """Build the config-system-removal step (only included when declined)."""

    def call(root: Path, dry_run: bool) -> int:
        return remove_config_system.run(root, assume_yes=True, dry_run=dry_run)

    return PlannedStep("remove_config_system", "Remove the config system", call)


def _step_remove_private_repo_deps() -> PlannedStep:
    """Build the private-repo-deps-removal step (only included when declined)."""

    def call(root: Path, dry_run: bool) -> int:
        return remove_private_repo_deps.run(root, assume_yes=True, dry_run=dry_run)

    return PlannedStep("remove_private_repo_deps", "Remove private-repo-deps workflow steps", call)


def _step_remove_remote_disposable_scripts() -> PlannedStep:
    """Build the remote-disposability-scripts-removal step (only included when declined)."""

    def call(root: Path, dry_run: bool) -> int:
        return remove_remote_disposable_scripts.run(root, assume_yes=True, dry_run=dry_run)

    return PlannedStep(
        "remove_remote_disposable_scripts", "Remove remote-disposability scripts", call
    )


def _step_remove_security_policy() -> PlannedStep:
    """Build the security-policy-removal step (only included when declined)."""

    def call(root: Path, dry_run: bool) -> int:
        return remove_security_policy.run(root, assume_yes=True, dry_run=dry_run)

    return PlannedStep("remove_security_policy", "Remove SECURITY.md", call)


def _step_remove_contributing_guide() -> PlannedStep:
    """Build the contributor-guide-removal step (only included when declined)."""

    def call(root: Path, dry_run: bool) -> int:
        return remove_contributing_guide.run(root, assume_yes=True, dry_run=dry_run)

    return PlannedStep("remove_contributing_guide", "Remove CONTRIBUTING.md", call)


def _step_reinit_git(config: Config) -> PlannedStep:
    """Build the git re-initialization step (only included when requested), destructive."""

    def call(root: Path, dry_run: bool) -> int:
        return reinit_git.run(root, branch=config.branch, assume_yes=True, dry_run=dry_run)

    return PlannedStep(
        "reinit_git", f"Re-initialize git (branch '{config.branch}')", call, destructive=True
    )


def build_steps(config: Config) -> tuple[PlannedStep, ...]:
    """Build the ordered, config-bound steps for one run.

    Every step except the removable features and ``reinit_git`` always
    runs. ``find_fixmes`` is intentionally not included here -- it is
    read-only and always runs once, separately, after a successful apply,
    never gated by the confirmation.

    Args:
        config: The fully validated configuration.

    Returns:
        Steps in canonical execution order.
    """
    steps = [
        _step_strip_headers(),
        # Before the rename/user/version steps: they rewrite README.md by name,
        # so the skeleton has to be README.md by the time they run.
        _step_reset_readme(),
        _step_rename(config),
        _step_github_user(config),
        _step_python_version(config),
        _step_version(config),
        _step_reset_changelog(),
        _step_license(config),
    ]
    if not config.mkdocs:
        steps.append(_step_remove_mkdocs())
    # Declining the whole config system removes the package directory, which
    # covers the secret machinery and both backends; declining the secret
    # machinery covers both backends; the per-backend steps only run when
    # everything containing them is kept.
    if not config.config_system:
        steps.append(_step_remove_config_system())
    elif not config.secret_storage:
        steps.append(_step_remove_secret_storage())
    else:
        if not config.keyring:
            steps.append(_step_remove_keyring())
        if not config.keyvault:
            steps.append(_step_remove_keyvault())
    if not config.private_repo_deps:
        steps.append(_step_remove_private_repo_deps())
    if not config.remote_disposable_scripts:
        steps.append(_step_remove_remote_disposable_scripts())
    if not config.security_policy:
        steps.append(_step_remove_security_policy())
    if not config.contributing_guide:
        steps.append(_step_remove_contributing_guide())
    if config.reinit:
        steps.append(_step_reinit_git(config))
    return tuple(steps)


def preview_steps(root: Path, steps: Sequence[PlannedStep]) -> None:
    """Print every step's dry-run preview, in canonical order, under one summary.

    Args:
        root: Project root directory.
        steps: Steps to preview, in canonical order.
    """
    _common.section("Preview")
    for step in steps:
        step.call(root, True)


def apply_steps(root: Path, steps: Sequence[PlannedStep]) -> list[str]:
    """Run every step for real, in canonical order.

    Failures are collected, not fatal: these are independent file
    operations, not config-validity problems, so one failing does not block
    the rest.

    Args:
        root: Project root directory.
        steps: Steps to apply, in canonical order.

    Returns:
        Keys of the steps that returned a nonzero exit code.
    """
    failed: list[str] = []
    for step in steps:
        if step.call(root, False) != 0:
            failed.append(step.key)
    return failed


def run_setup(
    root: Path, config_path: Path, *, assume_yes: bool = False, dry_run: bool = False
) -> int:
    """Load, validate, preview, confirm (unless ``assume_yes``), and apply the setup config.

    Args:
        root: Project root directory.
        config_path: Path to the ``template_setup.toml`` config file.
        assume_yes: Skip the confirmation prompt.
        dry_run: Preview every step without applying anything.

    Returns:
        ``2`` if the config file is missing/unreadable/invalid TOML (nothing
        was validated); ``1`` if validation found problems, the user
        declined the confirmation, or the apply ran but one or more steps
        reported a problem; ``0`` on a clean dry run or an apply where every
        step succeeded.
    """
    raw, load_error = _load_toml(config_path)
    if load_error:
        print(f"ERROR: {load_error}")
        return 2

    config, problems = validate_config(root, raw)
    if config is None:
        _common.section("Config problems")
        for problem in problems:
            print(f"  - {problem}")
        print(f"\n  {len(problems)} problem(s) found in {config_path}; nothing changed.")
        return 1

    steps = build_steps(config)
    preview_steps(root, steps)

    if dry_run:
        print("\n  (dry run -- nothing changed)")
        return 0

    print()
    if not _common.confirm("Apply the setup above?", assume_yes=assume_yes):
        print("  Aborted; nothing changed.")
        return 1

    _common.section("Applying")
    failed = apply_steps(root, steps)

    find_fixmes.run(root)

    _common.section("Setup complete")
    if failed:
        print("  Steps that reported a problem: " + ", ".join(failed))
        print("  Review their output above; each can be re-run on its own.")
        return 1
    print("  Review the changes, then write some code!")
    print("  scripts/template_setup/ is yours to remove whenever you're ready --")
    print("  run cleanup.py, or delete the folder yourself.")
    return 0


def main() -> None:
    """Parse arguments and run the config-driven setup."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview every change without applying anything."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to template_setup.toml (default: scripts/template_setup.toml).",
    )
    args = parser.parse_args()

    root = _common.find_root()
    config_path = args.config or (_common.SETUP_DIR.parent / CONFIG_FILENAME)
    sys.exit(run_setup(root, config_path, assume_yes=args.yes, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
