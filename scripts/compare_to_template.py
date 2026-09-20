"""Compare a project's baseline files against the template it was created from.

A project generated from this template keeps a set of "baseline" files that
should track the template as it evolves: the GitHub workflows and templates,
the dev helper scripts, the AGENTS docs, lint/format config, and so on. This
script compares those files between a template checkout and the project,
replaying the mechanical transformations the template-setup scripts performed
so that only real drift is reported:

  - the template's snake_case / kebab-case project name -> the project's names
  - the template author's GitHub username -> the project's (from `git remote`)
  - the "TEMPLATE SETUP NOTES" banner comments -> stripped from both sides
  - the pinned Python version -> the project's (from `.python-version`)
  - the template-only pyproject.toml config -> dropped, as cleanup.py does
  - the commented-out private-repo-deps workflow steps -> stripped, as
    remove_private_repo_deps.py does, when the project declined them
  - AGENTS.md's "Package Purpose" section -> stripped from both sides, since
    every project fills it in with its own description

Each baseline file is strict (drift is an error) or lenient (expected to
diverge; reported for review only), and required or optional (optional
features such as mkdocs may be deleted from a
project). A few files (e.g. the README and the remote-disposability script
pair) are checked for existence only, as the project rewrites their contents
wholesale. Files the project adds on top of the template are ignored.

Files belonging to a config-driven optional feature (mkdocs, the config
system and its credential backends, the remote-disposability scripts,
SECURITY.md, CONTRIBUTING.md) are gated on
that project's own choices, read from ``scripts/template_setup.toml``. When that file
is missing the script offers to copy the template's own over verbatim and
exits so it can be filled in; an unparsable file, or one whose ``[project]``
name is still the template's (the file was never filled in, so its flags
cannot be trusted), is a hard error -- never a cue to guess. A feature the
project declined is left out of the comparison, the version preflight, and
``--diff`` entirely: it is never reported and never offered for copy, exactly
like a file the project simply doesn't have. A feature the project kept is
compared like any other required file, so an accidentally deleted one is
reported as drift instead of silently ignored. The private-repo-deps feature
is different: it is not a ``gate`` on any file (ci.yml/audit.yml/docs.yml
stay required and strict either way) -- instead its commented-out steps are
replayed away from the template side before comparing, per
``replay_private_repo_deps()``.

Before anything else -- reading ``template_setup.toml`` included -- the script checks
its own copy and its ``_cli`` module against the template and offers to copy
either over when out of date, stopping for a re-run if the executing copy
was replaced; a project whose config is missing or unfilled still gets the
current script first, whose setup handling may be the very thing that
changed. Then, before comparing, it checks the version of every other
versioned file (the dev helper scripts ``scripts/*.py`` and the ``mypy``
stub-guard test, minus the existence-only ones) on both sides and offers to
copy over any that are out of date or missing in the project, so those files
-- and the manifest and replay logic this script compares against -- match
the template's current ones. After comparing, any other required file found missing is also
offered for install. Every install writes the template's *normalized* text
(banner stripped, names/version/cleanup replayed), so a freshly installed
file compares as a match; ``--no-update`` suppresses every offer.

Run it from either repository; the other repository is given as the
positional path (default: a sibling folder with the template's name):

    uv run scripts/compare_to_template.py
    uv run scripts/compare_to_template.py C:/dev/TEMPLATE-CLONE
    uv run scripts/compare_to_template.py --diff        # open diffs in VS Code
    uv run scripts/compare_to_template.py --all         # also list matching files
    uv run scripts/compare_to_template.py --no-update   # CI: never write anything

Exit codes: 0 = no drift (lenient "review" differences allowed), 1 = drift
found (a strict file differs or a required file is missing) or a fatal error.
"""

from __future__ import annotations

import argparse
import difflib
import os
import platform
import re
import shlex
import shutil
import sys
import tempfile
from dataclasses import dataclass
from fnmatch import fnmatch
from os.path import normcase, normpath
from pathlib import Path
from typing import Any, NoReturn

import _cli as cli

if sys.version_info >= (3, 11):  # noqa: UP036 # allows compatibility back to 3.10
    import tomllib
else:
    import tomli as tomllib

# Version of this helper script itself. Bump on every change so copies in other
# repos can be compared: patch = bugfix, minor = new flag/behavior, major =
# breaking CLI change.
__version__ = "1.24.1"

# The template's identity tokens. Built from pieces so that a child project's
# rename_project.py / set_github_user.py runs (which string-replace these
# tokens across every text file) leave this script functional: the constants
# must keep their template-side values in every copy of this file.
TEMPLATE_SNAKE = "_".join(("python", "repo", "template"))
TEMPLATE_KEBAB = "-".join(("python", "repo", "template"))
TEMPLATE_USER = "".join(("droll", "robot"))

# This script's own path and its shared _cli module, checked against the
# template before anything else -- template_setup.toml included -- by the early
# self-check/update step (see check_self_update()).
SELF_REL = "scripts/compare_to_template.py"
_SELF_CHECK_PATHS = (SELF_REL, "scripts/_cli.py")

# Path (relative to a project root) of the config-driven setup's input file.
# It lives outside scripts/template_setup/ specifically so cleanup.py's
# deletion of that folder leaves it behind -- resolve_feature_flags() below
# keeps reading it long after the rest of the setup scaffolding is gone.
SETUP_CONFIG_REL = "scripts/template_setup.toml"

# The template-header banner marker (see scripts/template_setup/
# strip_template_headers.py). Assigning it here is safe: the strip script only
# removes the marker when it sits inside a comment banner.
_MARKER = "TEMPLATE SETUP NOTES"

# A banner separator line such as "# ====" or "// ====".
_SEP_RE = re.compile(r"^\s*(?:#|//)\s*=+\s*$")

_VERSION_RE = re.compile(r"""^__version__\s*=\s*["']([^"']+)["']""", re.MULTILINE)

# MAJOR.MINOR or MAJOR.MINOR.PATCH, as accepted by set_python_version.py.
_PY_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)*$")


@dataclass(frozen=True)
class BaselineFile:
    """One template file tracked by the comparison.

    Attributes:
        path: Template-relative POSIX path.
        required: Whether the file must exist in the project (``False`` for
            deletable optional features). Ignored when ``gate`` is set --
            see :func:`effective_required`.
        strict: Whether content drift is an error (``False`` for files that
            are expected to diverge and are reported for review only).
        compare_content: Whether to compare the file's contents at all. When
            ``False`` only the file's existence is checked -- a present file is
            a match whatever its contents, and a missing required one is drift;
            the ``strict`` flag is then irrelevant. Used for files the project
            is meant to rewrite wholesale, such as the README.
        versioned: Whether the file declares its own ``__version__`` that the
            version pre-flight and drift note should track. Implied for the
            ``scripts/*.py`` helpers (see :func:`carries_version`); set it
            explicitly for any other versioned file.
        gate: Name of the matching :class:`FeatureFlags` field, for a file
            that belongs to one config-driven optional feature (mkdocs,
            SECURITY.md). ``None`` for files
            that are always part of the baseline. See :func:`is_applicable`
            and :func:`effective_required`.
    """

    path: str
    required: bool = True
    strict: bool = True
    compare_content: bool = True
    versioned: bool = False
    gate: str | None = None


# Every tracked template file is either listed here or matched by the
# exclusion lists below; tests/test_compare_to_template.py enforces that, so
# adding a file to the template forces a decision about how to compare it.
MANIFEST: tuple[BaselineFile, ...] = (
    # GitHub configuration: identical apart from the name/user rename.
    BaselineFile(".github/ISSUE_TEMPLATE/bug_report.yml"),
    BaselineFile(".github/ISSUE_TEMPLATE/config.yml"),
    BaselineFile(".github/ISSUE_TEMPLATE/feature_request.yml"),
    BaselineFile(".github/PULL_REQUEST_TEMPLATE.md"),
    BaselineFile(".github/dependabot.yml"),
    BaselineFile(".github/workflows/audit.yml"),
    BaselineFile(".github/workflows/ci.yml"),
    BaselineFile(".github/workflows/docs.yml", gate="mkdocs"),
    # Claude Code configuration. settings.json accumulates per-project
    # permissions, so it stays optional and lenient instead of gated.
    BaselineFile(".claude/settings.json", required=False, strict=False),
    # Editor / lint / format / hygiene config.
    BaselineFile(".editorconfig"),
    BaselineFile(".gitattributes"),
    BaselineFile(".pre-commit-config.yaml"),
    BaselineFile(".gitignore", strict=False),  # projects append their own ignores
    # Agent and contributor docs.
    # strict=False: holds the project's own rules. Its "Package Purpose"
    # section is additionally stripped from both sides before comparing (see
    # strip_package_purpose()), since every project fills it in uniquely.
    BaselineFile("AGENTS.md", strict=False),
    BaselineFile("AGENTS.COMMITTING.md"),
    BaselineFile("AGENTS.RELEASING.md"),
    BaselineFile("AGENTS.TESTING.md"),
    BaselineFile("AGENTS.WORKTREE.md"),
    BaselineFile("CLAUDE.md"),
    # GitHub community docs, each independently removable at setup time.
    BaselineFile("CONTRIBUTING.md", gate="contributing_guide"),
    BaselineFile("SECURITY.md", gate="security_policy"),
    BaselineFile("README.md", compare_content=False),  # rewritten per project: only check it exists
    # Project configuration: always diverges (version, description, deps).
    BaselineFile("pyproject.toml", strict=False),
    # The config-driven setup's own input file (see SETUP_CONFIG_REL): its
    # content is this project's feature choices, never the template's, but
    # resolve_feature_flags() needs the file itself to stay present.
    BaselineFile(SETUP_CONFIG_REL, compare_content=False),
    # Dev helper scripts (each carries its own __version__).
    BaselineFile("scripts/_cli.py"),
    BaselineFile(SELF_REL),
    BaselineFile("scripts/complete_worktree.py"),
    BaselineFile("scripts/new_worktree.py"),
    BaselineFile("scripts/open_claude_settings.py"),
    BaselineFile("scripts/open_gitignore.py"),
    BaselineFile("scripts/push_new_tag_to_main.py"),
    BaselineFile("scripts/remove_worktree.py"),
    BaselineFile("scripts/update_floors.py"),
    # Remote-destructive-test feature, write half: run manually to mark a
    # target disposable. Its read half (verify_remote_disposable.py) lives in
    # tests/, next to the conftest.py gate that is its only automatic caller.
    # The marker mechanism is filled in per project, so the contents are
    # always different by design: only existence is checked, like README.md.
    BaselineFile(
        "scripts/mark_remote_disposable.py",
        compare_content=False,
        gate="remote_disposable_scripts",
    ),
    # Documentation site (mkdocs feature; content is the project's own).
    BaselineFile("mkdocs.yml", gate="mkdocs", strict=False),
    # The docs landing page is rewritten wholesale per project (it is always
    # completely different), so only its existence is checked, like README.md.
    BaselineFile("docs/index.md", gate="mkdocs", compare_content=False),
    BaselineFile(f"docs/reference/{TEMPLATE_SNAKE}.md", gate="mkdocs", strict=False),
    # Test infrastructure (conftest grows project fixtures).
    BaselineFile("tests/__init__.py", required=False),
    BaselineFile("tests/conftest.py", required=False, strict=False),
    # The config package (per-user config.toml + secret backends). The core
    # modules are generic and carry a __version__; schema.py holds the
    # project's own option definitions, so its drift is expected and reported
    # for review only (lenient), never as an error. The backend modules are
    # independently removable, each behind its own gate.
    BaselineFile(f"src/{TEMPLATE_SNAKE}/config/__init__.py", gate="config_system"),
    BaselineFile(f"src/{TEMPLATE_SNAKE}/config/__main__.py", gate="config_system"),
    BaselineFile(f"src/{TEMPLATE_SNAKE}/config/cli.py", versioned=True, gate="config_system"),
    BaselineFile(f"src/{TEMPLATE_SNAKE}/config/file.py", versioned=True, gate="config_system"),
    BaselineFile(f"src/{TEMPLATE_SNAKE}/config/paths.py", versioned=True, gate="config_system"),
    BaselineFile(f"src/{TEMPLATE_SNAKE}/config/resolve.py", versioned=True, gate="config_system"),
    BaselineFile(f"src/{TEMPLATE_SNAKE}/config/schema.py", strict=False, gate="config_system"),
    BaselineFile(f"src/{TEMPLATE_SNAKE}/config/secrets.py", versioned=True, gate="secret_storage"),
    BaselineFile(f"src/{TEMPLATE_SNAKE}/config/keyring_backend.py", versioned=True, gate="keyring"),
    BaselineFile(
        f"src/{TEMPLATE_SNAKE}/config/keyvault_backend.py", versioned=True, gate="keyvault"
    ),
    # Test object shared by the config-package tests (kept schema-independent
    # so downstream edits to Settings don't break them).
    BaselineFile("tests/_config_test_object.py", versioned=True, gate="config_system"),
    # The config package's unit tests ship to projects (cleanup.py keeps
    # them: no script shares their names) and must track the template, so
    # they are compared here despite the blanket tests/test_*.py exclusion.
    # None of them import a concrete backend, so they follow the package's
    # own gate -- except the dispatcher's tests, which go with the
    # secret-storage machinery; the per-backend tests are the two entries
    # below.
    BaselineFile("tests/test_config_cli.py", versioned=True, gate="config_system"),
    BaselineFile("tests/test_config_file.py", versioned=True, gate="config_system"),
    BaselineFile("tests/test_config_paths.py", versioned=True, gate="config_system"),
    BaselineFile("tests/test_config_resolve.py", versioned=True, gate="config_system"),
    BaselineFile("tests/test_config_schema.py", versioned=True, gate="config_system"),
    BaselineFile("tests/test_config_secrets.py", versioned=True, gate="secret_storage"),
    # Each backend's tests import that backend at module scope, so they follow
    # its gate and are deleted with it.
    BaselineFile("tests/test_keyring_backend.py", versioned=True, gate="keyring"),
    BaselineFile("tests/test_keyvault_backend.py", versioned=True, gate="keyvault"),
    # Remote-destructive-test feature, read half: run automatically by
    # conftest.py's destructive_remote gate. Paired with
    # scripts/mark_remote_disposable.py above; the marker mechanism is filled
    # in per project, so the contents are always different by design: only
    # existence is checked.
    BaselineFile(
        "tests/verify_remote_disposable.py",
        compare_content=False,
        gate="remote_disposable_scripts",
    ),
    # The mypy stub-guard test ships to projects (cleanup.py keeps it: no
    # matching script) and must track the template, so it is compared here
    # despite the blanket tests/test_*.py exclusion, and carries a __version__.
    BaselineFile("tests/test_mypy_stub_guard.py", versioned=True),
    # Same deal for the inline-suppression gate: it ships to every project
    # and carries a __version__.
    BaselineFile("tests/test_no_inline_suppressions_for_secrets.py", versioned=True),
    # Same deal for the audited-baseline gate: it ships to every project (it
    # backs the secrets-baseline-audited pre-commit hook) and carries a
    # __version__.
    BaselineFile("tests/test_secrets_baseline_audited.py", versioned=True),
    # Same deal for the hook-environment gate: it ships to every project (no
    # matching script, so cleanup.py keeps it) and carries a __version__.
    BaselineFile("tests/test_secrets_guards_under_hook_env.py", versioned=True),
)

# Tracked template paths deliberately not compared. Prefixes cover the
# project's own source and the setup scripts (deleted by cleanup.py); globs
# cover per-project files and the template-development test suite (also
# deleted by cleanup.py). The manifest is authoritative over these lists, so
# the config-package files under src/ and the tests/test_config_*.py suite
# are still compared (see is_excluded()).
EXCLUDED_PREFIXES = ("src/", "scripts/template_setup/")
EXCLUDED_GLOBS = (
    "CHANGELOG.md",
    "CHANGELOG.md.FIXME",
    "README.md.FIXME",
    "LICENSE.*.FIXME",
    "uv.lock",
    ".secrets.baseline",  # per-project: each repo scans and audits its own
    ".python-version",  # compared indirectly: replayed onto the template side
    "*.code-workspace.FIXME.jsonc",
    "tests/test_*.py",
)

# Strict files that remove_mkdocs.py edits in place; when the project has
# removed mkdocs they are compared leniently instead, because the template
# side still carries the mkdocs sections.
MKDOCS_EDITED = ("CONTRIBUTING.md", "AGENTS.RELEASING.md")

# Workflow files that carry the commented-out private-repo-deps GitHub
# Actions steps (see scripts/template_setup/remove_private_repo_deps.py).
# Unlike MKDOCS_EDITED, these stay strictly compared -- the block is stripped
# from the template side by replay_private_repo_deps() before comparing, so a
# project that declined the feature still needs to match byte-for-byte.
_PRIVATE_REPO_DEPS_PATHS = (
    ".github/workflows/ci.yml",
    ".github/workflows/audit.yml",
    ".github/workflows/docs.yml",
)
_PRIVATE_REPO_DEPS_START = "# <private-repo-deps>"
_PRIVATE_REPO_DEPS_END = "</private-repo-deps>"

# AGENTS.md's per-project description heading. Every project rewrites this
# section with its own content in place of the template's FIXME placeholder,
# so it is stripped from both sides before comparing -- see
# strip_package_purpose().
_PACKAGE_PURPOSE_HEADING = "## Package Purpose"


@dataclass(frozen=True)
class ProjectNames:
    """The project-side values of the template's identity tokens.

    Attributes:
        snake: The project's snake_case import/package name.
        kebab: The project's kebab-case distribution name.
        github_user: The project's GitHub username, or ``None`` when it could
            not be determined (username differences are then not normalized).
    """

    snake: str
    kebab: str
    github_user: str | None


@dataclass(frozen=True)
class FeatureFlags:
    """Which config-driven optional files this project actually kept.

    Each field name (other than ``source``) matches a :class:`BaselineFile`
    ``gate`` value; see :func:`is_applicable` and :func:`effective_required`,
    which consult these flags to decide whether a gated entry is part of this
    project's baseline at all.

    Attributes:
        mkdocs: Documentation site kept (``[features].mkdocs``).
        config_system: The config package (per-user config.toml, config CLI,
            secret backends) and its tests kept
            (``[features].config_system``).
        secret_storage: The secret-storage machinery inside the config
            package -- the backend dispatcher ``config/secrets.py`` and its
            tests -- kept (``[features].secret_storage``). Forced ``False``
            when ``config_system`` is ``False`` -- it lives inside the
            config package.
        keyring: OS-keyring secret backend kept (``[features].keyring``).
            Also gates ``tests/test_keyring_backend.py``, which imports the
            backend at module scope. Forced ``False`` when
            ``secret_storage`` is ``False`` -- the backend lives inside the
            secret-storage machinery.
        keyvault: Azure Key Vault secret backend kept
            (``[features].keyvault``). Also gates
            ``tests/test_keyvault_backend.py``, as above. Forced ``False``
            when ``secret_storage`` is ``False``, as above.
        private_repo_deps: Commented-out private-git-deps GitHub Actions
            steps kept in ci.yml/audit.yml/docs.yml
            (``[features].private_repo_deps``). Not a ``gate`` on any
            :class:`BaselineFile` -- those workflow files are always
            required/strict; when this is ``False``,
            :func:`normalize_template_text` strips the block from the
            template side before comparing, via
            :func:`replay_private_repo_deps`.
        remote_disposable_scripts: The mark/verify remote-disposability script
            pair kept (``[features].remote_disposable_scripts``). Gates both
            ``scripts/mark_remote_disposable.py`` and
            ``tests/verify_remote_disposable.py``.
        security_policy: ``SECURITY.md`` kept (``[features].security_policy``).
        contributing_guide: ``CONTRIBUTING.md`` kept
            (``[features].contributing_guide``).
        source: Where these flags came from -- always :data:`SETUP_CONFIG_REL`,
            the only supported source -- shown in the report for provenance.
    """

    mkdocs: bool
    config_system: bool
    secret_storage: bool
    keyring: bool
    keyvault: bool
    private_repo_deps: bool
    remote_disposable_scripts: bool
    security_policy: bool
    contributing_guide: bool
    source: str

    def wanted(self, gate: str) -> bool:
        """Return whether the config wants the feature named by ``gate``.

        Args:
            gate: A :class:`BaselineFile` ``gate`` value (one of this
                dataclass's own boolean field names).

        Returns:
            That field's value.
        """
        return bool(getattr(self, gate))


@dataclass(frozen=True)
class CompareContext:
    """Everything :func:`compare_one` needs to compare one baseline file.

    Attributes:
        template_root: Root of the template checkout.
        project_root: Root of the project checkout.
        names: Project-side identity tokens.
        dotted: Project Python version as ``MAJOR.MINOR``, or ``None`` to skip
            Python-version normalization.
        compact: Project Python version as ``pyMAJORMINOR``, or ``None``.
        ran_cleanup: Whether the project ran cleanup.py (its template-only
            pyproject.toml lines are then dropped from the template side too).
        flags: The project's resolved config-driven feature flags. Used both
            for gating (:func:`is_applicable`, :func:`effective_required`) and
            -- via ``flags.mkdocs`` -- to demote the :data:`MKDOCS_EDITED`
            files to lenient comparison when mkdocs is gone.
    """

    template_root: Path
    project_root: Path
    names: ProjectNames
    dotted: str | None
    compact: str | None
    ran_cleanup: bool
    flags: FeatureFlags


@dataclass(frozen=True)
class Comparison:
    """The comparison result for one baseline file.

    Attributes:
        entry: The manifest entry that was compared.
        project_rel: The project-relative path (differs from ``entry.path``
            when the path itself contains the project name).
        status: One of ``match``, ``modified``, ``review``, ``missing``,
            ``absent``, or ``no-template``.
        note: Extra detail appended to the report line.
        template_norm: Normalized template text (for ``--diff``), if any.
        project_norm: Normalized project text (for ``--diff``), if any.
    """

    entry: BaselineFile
    project_rel: str
    status: str
    note: str = ""
    template_norm: str | None = None
    project_norm: str | None = None


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested in tests/test_compare_to_template.py)
# ---------------------------------------------------------------------------


def is_excluded(rel: str) -> bool:
    """Return whether a tracked template path is deliberately not compared.

    The manifest is authoritative: a path listed there is always compared, even
    when an exclusion pattern would otherwise match it (e.g. the stub-guard test
    under the blanket ``tests/test_*.py`` glob).

    Args:
        rel: Template-relative POSIX path.

    Returns:
        ``True`` if the path is covered by the exclusion lists and not in the
        manifest.
    """
    if any(entry.path == rel for entry in MANIFEST):
        return False
    if rel.startswith(EXCLUDED_PREFIXES):
        return True
    return any(fnmatch(rel, pattern) for pattern in EXCLUDED_GLOBS)


def normalize_eol(text: str) -> str:
    """Normalize CRLF/CR line endings to LF so checkouts compare equal.

    Args:
        text: File contents.

    Returns:
        The contents with every line ending as a bare LF.
    """
    return text.replace("\r\n", "\n").replace("\r", "\n")


def strip_template_header(text: str) -> str:
    """Remove the template's "setup notes" banner from ``text``, if present.

    Mirrors scripts/template_setup/strip_template_headers.py: the banner is
    the separator-delimited comment block (hash, slash, or Markdown style)
    around the marker line, plus one run of trailing blank lines.

    Args:
        text: File contents.

    Returns:
        The contents without the banner, or unchanged when there is none.
    """
    lines = text.splitlines(keepends=True)
    marker_index = next((i for i, line in enumerate(lines) if _MARKER in line), None)
    if marker_index is None:
        return text

    marker_line = lines[marker_index].lstrip()
    if marker_line.startswith(("#", "//")):
        prefix = "#" if marker_line.startswith("#") else "//"
        top = marker_index
        while top - 1 >= 0 and lines[top - 1].lstrip().startswith(prefix):
            top -= 1
        bottom = marker_index
        while bottom + 1 < len(lines) and lines[bottom + 1].lstrip().startswith(prefix):
            bottom += 1
        separators = [i for i in range(top, bottom + 1) if _SEP_RE.match(lines[i])]
        if not separators:
            return text
        start, end = separators[0], separators[-1]
    else:
        start = marker_index
        while start >= 0 and "<!--" not in lines[start]:
            start -= 1
        end = marker_index
        while end < len(lines) and "-->" not in lines[end]:
            end += 1
        if start < 0 or end >= len(lines):
            return text

    stop = end + 1
    while stop < len(lines) and not lines[stop].strip():
        stop += 1
    del lines[start:stop]
    return "".join(lines)


def script_version(text: str) -> str | None:
    """Extract a helper script's ``__version__`` string.

    Args:
        text: The script's source text.

    Returns:
        The version string, or ``None`` when the script declares none.
    """
    match = _VERSION_RE.search(text)
    return match.group(1) if match else None


def version_tuple(version: str) -> tuple[int, ...] | None:
    """Parse a dotted version string into a comparable tuple of ints.

    Args:
        version: Version string such as ``"1.2.3"``.

    Returns:
        The numeric parts, or ``None`` when any part is not an integer.
    """
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return None


def python_version_forms(version: str) -> tuple[str, str, str]:
    """Derive the three spellings of a Python version used across the project.

    Mirrors scripts/template_setup/set_python_version.py.

    Args:
        version: Version string (``MAJOR.MINOR`` or ``MAJOR.MINOR.PATCH``).

    Returns:
        A ``(full, dotted, compact)`` tuple, e.g. ``("3.14.3", "3.14", "py314")``.

    Raises:
        ValueError: If ``version`` is not a valid Python version string.
    """
    cleaned = version.strip()
    match = _PY_VERSION_RE.match(cleaned)
    if not match:
        raise ValueError(f"'{version}' is not a valid Python version.")
    major, minor = match.group(1), match.group(2)
    return cleaned, f"{major}.{minor}", f"py{major}{minor}"


def github_user_from_url(url: str) -> str | None:
    """Extract the GitHub username from a remote URL.

    Handles ``https://github.com/USER/...``, ``git@github.com:USER/...``, and
    ``ssh://git@github.com/USER/...`` forms. Non-GitHub remotes yield ``None``.

    Args:
        url: The remote URL.

    Returns:
        The username, or ``None`` when it cannot be determined.
    """
    match = re.search(r"github\.com[:/]([A-Za-z0-9-]+)/", url)
    return match.group(1) if match else None


def replace_case_insensitive(text: str, old: str, new: str) -> str:
    """Replace every occurrence of ``old`` (any case) with ``new``.

    Args:
        text: Text to rewrite.
        old: Substring to find, case-insensitively.
        new: Literal replacement.

    Returns:
        The rewritten text.
    """
    return re.sub(re.escape(old), lambda _match: new, text, flags=re.IGNORECASE)


def replay_python_version(rel: str, text: str, dotted: str, compact: str) -> str:
    """Rewrite the template's Python version pins to the project's version.

    Applies the same targeted edits as set_python_version.py so a project on a
    different Python version does not read as drift. Files the setup script
    does not touch are returned unchanged.

    Args:
        rel: Template-relative path of the file.
        text: Template-side file contents.
        dotted: Project Python version as ``MAJOR.MINOR``.
        compact: Project Python version as ``pyMAJORMINOR``.

    Returns:
        The rewritten contents.
    """
    if rel == "pyproject.toml":
        text = re.sub(r'(requires-python\s*=\s*">=\s*)\d+\.\d+(?:\.\d+)*', rf"\g<1>{dotted}", text)
        text = re.sub(r'(target-version\s*=\s*")py\d+(")', rf"\g<1>{compact}\g<2>", text)
        text = re.sub(
            r'(python_version\s*=\s*")\d+\.\d+(?:\.\d+)*(")', rf"\g<1>{dotted}\g<2>", text
        )
    elif rel == ".pre-commit-config.yaml":
        text = re.sub(r"(python:\s*python)\d+\.\d+(?:\.\d+)*", rf"\g<1>{dotted}", text)
    elif rel == "CONTRIBUTING.md":
        text = re.sub(r"(Python\s+)\d+\.\d+(?:\.\d+)*\+", rf"\g<1>{dotted}+", text)
    elif rel == "README.md":
        text = re.sub(r"(badge/python-)\d+\.\d+(?:\.\d+)*(%2B)", rf"\g<1>{dotted}\g<2>", text)
    elif rel == ".github/ISSUE_TEMPLATE/bug_report.yml":
        text = re.sub(
            r'(id:\s*python-version\b[\s\S]*?placeholder:\s*")\d+\.\d+', rf"\g<1>{dotted}", text
        )
    return text


def replay_cleanup_pyproject(text: str) -> str:
    """Drop the template-only pyproject.toml lines, as cleanup.py does.

    Tolerates missing snippets (unlike cleanup.py) because the comparison
    still works either way; the difference simply shows up in the diff.

    Args:
        text: Template-side pyproject.toml contents (LF line endings).

    Returns:
        The trimmed contents.
    """
    text = text.replace('    "--cov=scripts",\n', "")
    text = text.replace(
        'mypy_path = ["scripts", "scripts/template_setup"]', 'mypy_path = ["scripts"]'
    )
    return text.replace('files = ["src", "tests", "scripts"]', 'files = ["src", "tests"]')


def replay_private_repo_deps(rel: str, text: str) -> str:
    """Strip the commented-out private-repo-deps GitHub Actions block.

    Mirrors scripts/template_setup/remove_private_repo_deps.py: removes the
    ``# <private-repo-deps>`` ... ``# </private-repo-deps>`` block (and the
    blank line immediately before it) from a workflow file's template-side
    text, so a project that declined ``[features].private_repo_deps``
    compares byte-equal instead of showing permanent drift. A no-op for any
    other file, or for one of the three workflows if the block is somehow
    already gone.

    Args:
        rel: Template-relative path of the file.
        text: Template-side file contents (LF line endings).

    Returns:
        The contents with the block removed, or unchanged.
    """
    if rel not in _PRIVATE_REPO_DEPS_PATHS:
        return text
    lines = text.splitlines(keepends=True)
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == _PRIVATE_REPO_DEPS_START), None
    )
    if start is None:
        return text
    end = next((i for i in range(start, len(lines)) if _PRIVATE_REPO_DEPS_END in lines[i]), None)
    if end is None:
        return text
    if start > 0 and not lines[start - 1].strip():
        start -= 1
    del lines[start : end + 1]
    return "".join(lines)


def strip_package_purpose(rel: str, text: str) -> str:
    """Remove AGENTS.md's "Package Purpose" section from ``text``, if present.

    Every project rewrites this section with its own description in place of
    the template's FIXME placeholder, so a difference there is never
    meaningful drift; it is stripped from both the template and project sides
    before comparing. A no-op for any file other than AGENTS.md, or if the
    heading is somehow already gone.

    Args:
        rel: Template- or project-relative path of the file.
        text: File contents (LF line endings).

    Returns:
        The contents without the "Package Purpose" section (its heading and
        body, up to the next heading or end of file), or unchanged.
    """
    if rel != "AGENTS.md":
        return text
    lines = text.splitlines(keepends=True)
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == _PACKAGE_PURPOSE_HEADING), None
    )
    if start is None:
        return text
    end = start + 1
    while end < len(lines) and not lines[end].lstrip().startswith("#"):
        end += 1
    del lines[start:end]
    return "".join(lines)


def map_project_path(rel: str, names: ProjectNames) -> str:
    """Map a template-relative path to its project-relative counterpart.

    Paths that embed the template name (e.g. the docs API-reference page) were
    renamed by rename_project.py; everything else maps to itself.

    Args:
        rel: Template-relative POSIX path.
        names: Project-side identity tokens.

    Returns:
        The project-relative POSIX path.
    """
    return rel.replace(TEMPLATE_SNAKE, names.snake).replace(TEMPLATE_KEBAB, names.kebab)


def normalize_template_text(
    rel: str,
    text: str,
    names: ProjectNames,
    *,
    dotted: str | None = None,
    compact: str | None = None,
    ran_cleanup: bool = False,
    private_repo_deps: bool = True,
) -> str:
    """Replay the template-setup transformations onto template-side content.

    After this, a project file that was never edited beyond the standard
    setup steps compares byte-equal to the template file.

    Args:
        rel: Template-relative path of the file.
        text: Raw template-side contents.
        names: Project-side identity tokens.
        dotted: Project Python version as ``MAJOR.MINOR`` (skip when ``None``).
        compact: Project Python version as ``pyMAJORMINOR`` (skip when ``None``).
        ran_cleanup: Whether to drop the template-only pyproject.toml lines.
        private_repo_deps: Whether the project kept the private-repo-deps
            workflow steps (``[features].private_repo_deps``); ``False``
            strips them from the template side too, mirroring
            ``remove_private_repo_deps.py``.

    Returns:
        The normalized contents.
    """
    text = strip_template_header(normalize_eol(text))
    text = strip_package_purpose(rel, text)
    if dotted is not None and compact is not None:
        text = replay_python_version(rel, text, dotted, compact)
    if rel == "pyproject.toml" and ran_cleanup:
        text = replay_cleanup_pyproject(text)
    if not private_repo_deps:
        text = replay_private_repo_deps(rel, text)
    text = text.replace(TEMPLATE_SNAKE, names.snake).replace(TEMPLATE_KEBAB, names.kebab)
    if names.github_user is not None:
        text = replace_case_insensitive(text, TEMPLATE_USER, names.github_user)
    return text


def normalize_project_text(rel: str, text: str) -> str:
    """Normalize project-side content for comparison.

    Args:
        rel: Project-relative path of the file.
        text: Raw project-side contents.

    Returns:
        The contents with line endings normalized, any leftover template
        banner stripped (in case the setup step was skipped), and AGENTS.md's
        "Package Purpose" section removed (see :func:`strip_package_purpose`).
    """
    text = strip_template_header(normalize_eol(text))
    return strip_package_purpose(rel, text)


def effective_strict(entry: BaselineFile, *, has_mkdocs: bool) -> bool:
    """Compute whether an entry is compared strictly for this project.

    Args:
        entry: The manifest entry.
        has_mkdocs: Whether the project still has mkdocs.

    Returns:
        ``False`` for the files remove_mkdocs.py edits when mkdocs was
        removed; otherwise the entry's own strictness.
    """
    if not has_mkdocs and entry.path in MKDOCS_EDITED:
        return False
    return entry.strict


def script_version_note(template_text: str, project_text: str) -> str:
    """Describe how two helper-script versions relate, for the report line.

    Args:
        template_text: Template-side script source.
        project_text: Project-side script source.

    Returns:
        A parenthesized note, or ``""`` when either version is unavailable.
    """
    template_version = script_version(template_text)
    project_version = script_version(project_text)
    if template_version is None or project_version is None:
        return ""
    template_parts = version_tuple(template_version)
    project_parts = version_tuple(project_version)
    if template_parts is None or project_parts is None:
        return ""
    if project_parts < template_parts:
        return f" (project {project_version} < template {template_version}: outdated)"
    if project_parts > template_parts:
        return f" (project {project_version} > template {template_version}: ahead - upstream?)"
    return f" (both {template_version}: changed without a version bump?)"


def self_check_action(
    template_version: str | None, project_version: str | None, *, same_content: bool
) -> str:
    """Decide what the self-check should do about the project's script copy.

    Args:
        template_version: ``__version__`` of the template's copy, if any.
        project_version: ``__version__`` of the project's copy, if any.
        same_content: Whether the two copies are identical (line endings
            normalized).

    Returns:
        ``"ok"`` (identical), ``"ahead"`` (project copy is newer; do not
        overwrite), ``"update"`` (project copy is older or unversioned), or
        ``"refresh"`` (same version but different content).
    """
    if same_content:
        return "ok"
    template_parts = version_tuple(template_version) if template_version else None
    project_parts = version_tuple(project_version) if project_version else None
    if template_parts is None or project_parts is None:
        return "update"
    if project_parts > template_parts:
        return "ahead"
    if project_parts < template_parts:
        return "update"
    return "refresh"


def decode_text(raw: bytes) -> str | None:
    """Decode file bytes as UTF-8 text.

    Args:
        raw: Raw file contents.

    Returns:
        The decoded text (BOM tolerated), or ``None`` for non-UTF-8 content,
        which is then compared byte-for-byte.
    """
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def pyproject_name(root: Path) -> str | None:
    """Read the ``[project] name`` from a repository's pyproject.toml.

    Args:
        root: Repository root.

    Returns:
        The distribution name, or ``None`` when the file is missing,
        unparsable, or has no name.
    """
    path = root / "pyproject.toml"
    if not path.is_file():
        return None
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):  # fmt: skip
        return None
    project = data.get("project")
    if not isinstance(project, dict):
        return None
    name = project.get("name")
    return name if isinstance(name, str) else None


def load_setup_config(project_root: Path) -> dict[str, Any] | None:
    """Read and parse a project's :data:`SETUP_CONFIG_REL`, if present.

    Args:
        project_root: Root of the project checkout.

    Returns:
        The parsed TOML content, or ``None`` when the file is missing,
        unreadable, or not valid TOML -- :func:`resolve_feature_flags` then
        errors out.
    """
    path = project_root / SETUP_CONFIG_REL
    if not path.is_file():
        return None
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):  # fmt: skip
        return None


def setup_config_name_unchanged(raw: dict[str, Any]) -> bool:
    """Whether ``template_setup.toml``'s ``[project] name`` is still the template's own.

    Setup replaces the template name everywhere -- ``template_setup.toml`` included --
    so a config that still names the project after the template was never
    filled in, and its feature flags cannot be trusted. The name is folded
    the same way ``rename_project.py``'s ``derive_names()`` folds its input
    (any case, spaces/hyphens/underscores all equivalent). A missing table or
    name is tolerated, like every other hand-trimmed key.

    Args:
        raw: Parsed TOML content.

    Returns:
        ``True`` when the name is present and still the template's.
    """
    project_raw = raw.get("project")
    project = project_raw if isinstance(project_raw, dict) else {}
    name = project.get("name")
    if not isinstance(name, str):
        return False
    return re.sub(r"[\s\-]+", "_", name.strip()).lower() == TEMPLATE_SNAKE


def feature_flags_from_config(raw: dict[str, Any]) -> FeatureFlags:
    """Derive :class:`FeatureFlags` from parsed ``template_setup.toml`` content.

    Tolerant of missing or malformed tables/keys -- a hand-trimmed config
    still yields a usable result -- by falling back to the template's own
    "keep everything" defaults for anything unreadable, mirroring
    what an unedited ``template_setup.toml`` means for each of these fields.

    Args:
        raw: Parsed TOML content.

    Returns:
        The resolved flags, tagged with :data:`SETUP_CONFIG_REL` as the source.
    """
    features_raw = raw.get("features")
    features = features_raw if isinstance(features_raw, dict) else {}
    # The secret machinery lives inside the config package and the backends
    # live inside the secret machinery, so declining a container drops its
    # contents too, whatever their own flags say.
    config_system = bool(features.get("config_system", True))
    secret_storage = config_system and bool(features.get("secret_storage", True))

    return FeatureFlags(
        mkdocs=bool(features.get("mkdocs", True)),
        config_system=config_system,
        secret_storage=secret_storage,
        keyring=secret_storage and bool(features.get("keyring", True)),
        keyvault=secret_storage and bool(features.get("keyvault", True)),
        private_repo_deps=bool(features.get("private_repo_deps", True)),
        remote_disposable_scripts=bool(features.get("remote_disposable_scripts", True)),
        security_policy=bool(features.get("security_policy", True)),
        contributing_guide=bool(features.get("contributing_guide", True)),
        source=SETUP_CONFIG_REL,
    )


def resolve_feature_flags(project_root: Path) -> FeatureFlags:
    """Determine which config-driven optional files this project kept.

    Reads :data:`SETUP_CONFIG_REL`, which ``setup_new_project.py`` leaves
    behind on purpose (see its module docstring) so it is always available
    here. Its absence or an unparsable body is a hard error, not a cue to
    guess: inferring the feature set from which files happen to exist would
    silently mask a genuinely deleted or broken config, and every gated file
    of a wrongly-guessed feature would then be mis-reported. (For the missing
    case, ``main()`` first runs :func:`offer_setup_config_install`, so this
    error is only the non-interactive backstop.) A config whose ``[project]``
    name is still the template's is equally fatal: the file was never filled
    in -- e.g. freshly copied over -- so every flag in it is just the
    template's default, not this project's choice.

    Args:
        project_root: Root of the project checkout.

    Returns:
        The resolved flags.

    Raises:
        SystemExit: If :data:`SETUP_CONFIG_REL` is missing, cannot be parsed
            as TOML, or still carries the template's own project name.
    """
    path = project_root / SETUP_CONFIG_REL
    if not path.is_file():
        cli.die(
            f"No {SETUP_CONFIG_REL} in the project ({path}). It records which "
            "optional features the project kept; setup_new_project.py leaves it "
            "in place on purpose. Restore it before comparing."
        )
    raw = load_setup_config(project_root)
    if raw is None:
        cli.die(f"Could not parse {path} as TOML; fix it before comparing.")
    if setup_config_name_unchanged(raw):
        cli.die(
            f"{path} still has [project] name "
            f"('{TEMPLATE_SNAKE}'). Change project name and fill in desired "
            "features."
        )
    return feature_flags_from_config(raw)


def carries_version(entry: BaselineFile) -> bool:
    """Whether an entry declares a ``__version__`` the comparison tracks.

    True for the dev helper scripts (``scripts/*.py``, by path) and for any
    entry explicitly flagged ``versioned`` -- except for existence-only
    entries (``compare_content=False``), whose project-side contents are the
    project's own by design. Tracking their version would offer to overwrite
    a deliberately customized file from the template (see
    :func:`check_versioned_file`), which is the same mistake as reporting
    their contents as drift.

    Args:
        entry: The manifest entry.

    Returns:
        ``True`` when the file participates in the version pre-flight and the
        drift note.
    """
    if not entry.compare_content:
        return False
    if entry.versioned:
        return True
    return entry.path.startswith("scripts/") and entry.path.endswith(".py")


def is_applicable(entry: BaselineFile, flags: FeatureFlags) -> bool:
    """Whether ``entry`` is part of this project's tracked baseline at all.

    An ungated entry always is. A gated entry is only tracked when the
    project's config wants that feature -- declining it drops the file out of
    comparison, the version pre-flight's copy offers, and ``--diff`` entirely,
    rather than reporting it as an always-ignorable "absent" optional file.

    Args:
        entry: The manifest entry.
        flags: The project's resolved feature flags.

    Returns:
        ``True`` if the entry should be compared for this project.
    """
    return entry.gate is None or flags.wanted(entry.gate)


def effective_required(entry: BaselineFile, flags: FeatureFlags) -> bool:
    """Whether ``entry`` must be present in this project.

    Only meaningful for entries :func:`is_applicable` has already kept in
    play: an ungated entry uses its own static ``required`` field; a gated
    one is only ever compared when its flag is ``True``, which makes it
    required by definition -- there is no "the project might not have this
    yet" state once the config says it wants the feature.

    Args:
        entry: The manifest entry.
        flags: The project's resolved feature flags.

    Returns:
        ``True`` if the file's absence should be reported as drift.
    """
    if entry.gate is None:
        return entry.required
    return True


def compare_one(entry: BaselineFile, ctx: CompareContext) -> Comparison:
    """Compare one baseline file between the template and the project.

    Args:
        entry: The manifest entry to compare.
        ctx: Comparison context (roots, names, normalization switches).

    Returns:
        The :class:`Comparison` result, carrying the normalized texts when
        the contents differ (for ``--diff``).
    """
    project_rel = map_project_path(entry.path, ctx.names)
    template_path = ctx.template_root / entry.path
    project_path = ctx.project_root / project_rel

    if not template_path.is_file():
        return Comparison(entry, project_rel, "no-template", " (not in this template checkout)")
    if not project_path.is_file():
        required = effective_required(entry, ctx.flags)
        return Comparison(entry, project_rel, "missing" if required else "absent")

    if not entry.compare_content:
        return Comparison(entry, project_rel, "match", " (exists; contents not compared)")

    template_raw = template_path.read_bytes()
    project_raw = project_path.read_bytes()
    strict = effective_strict(entry, has_mkdocs=ctx.flags.mkdocs)

    template_text = decode_text(template_raw)
    project_text = decode_text(project_raw)
    if template_text is None or project_text is None:
        if template_raw == project_raw:
            return Comparison(entry, project_rel, "match")
        return Comparison(entry, project_rel, "modified" if strict else "review", " (binary)")

    template_norm = normalize_template_text(
        entry.path,
        template_text,
        ctx.names,
        dotted=ctx.dotted,
        compact=ctx.compact,
        ran_cleanup=ctx.ran_cleanup,
        private_repo_deps=ctx.flags.private_repo_deps,
    )
    project_norm = normalize_project_text(entry.path, project_text)
    if template_norm == project_norm:
        return Comparison(entry, project_rel, "match")

    note = ""
    if carries_version(entry):
        note = script_version_note(template_text, project_text)
    if entry.strict and not strict:
        note += " (compared leniently: mkdocs removed)"
    elif not entry.strict:
        note += " (expected to differ)"
    return Comparison(
        entry,
        project_rel,
        "modified" if strict else "review",
        note,
        template_norm=template_norm,
        project_norm=project_norm,
    )


def install_from_template(entry: BaselineFile, ctx: CompareContext) -> str:
    """Write the template's normalized content for ``entry`` into the project.

    The installed text is exactly what :func:`compare_one` holds the project's
    side against (banner stripped, names/version/cleanup replayed), so a
    freshly installed file compares as a match. The versioned ``scripts/*.py``
    helpers are unaffected by the normalization by construction -- their
    template tokens are built from pieces and the replays are path-scoped --
    so this is the single install path for every baseline file.

    Args:
        entry: The manifest entry to install; its template file must exist.
        ctx: Comparison context (roots, names, normalization switches).

    Returns:
        The project-relative path the file was written to.
    """
    template_text = decode_text((ctx.template_root / entry.path).read_bytes())
    if template_text is None:
        cli.die(f"The template's {entry.path} is not decodable text; cannot install it.")
    text = normalize_template_text(
        entry.path,
        template_text,
        ctx.names,
        dotted=ctx.dotted,
        compact=ctx.compact,
        ran_cleanup=ctx.ran_cleanup,
        private_repo_deps=ctx.flags.private_repo_deps,
    )
    project_rel = map_project_path(entry.path, ctx.names)
    project_path = ctx.project_root / project_rel
    project_path.parent.mkdir(parents=True, exist_ok=True)
    project_path.write_text(text, encoding="utf-8", newline="")
    return project_rel


# ---------------------------------------------------------------------------
# Orchestration (interactive; not unit-tested)
# ---------------------------------------------------------------------------


def same_path(a: str, b: str) -> bool:
    """Compare two filesystem paths without requiring either to exist.

    Args:
        a: First path.
        b: Second path.

    Returns:
        ``True`` if the paths refer to the same location (case-insensitive
        on Windows).
    """
    return normcase(normpath(a)) == normcase(normpath(b))


def parse_args() -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Compare this repository's baseline files against its template."
    )
    parser.add_argument(
        "other_repo",
        nargs="?",
        default=None,
        help="path to the other repository (default: a sibling folder with the template's name)",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="open each differing file as a diff in VS Code (falls back to unified "
        "diffs in the terminal when the 'code' CLI is not on PATH)",
    )
    parser.add_argument(
        "--diff-tool",
        default=None,
        metavar="CMD",
        help="command used to open --diff pairs (default: 'code'); e.g. 'codium' or 'cursor'",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="list every baseline file, including matches, and the files skipped for "
        "declined features",
    )
    parser.add_argument(
        "--github-user",
        default=None,
        help="project GitHub username for normalization (default: parsed from 'git remote')",
    )
    parser.add_argument(
        "--no-update",
        action="store_true",
        help="never offer to install or update project files (for CI)",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="assume 'yes' to every confirmation prompt (non-interactive)",
    )
    return parser.parse_args()


def resolve_other_root(argument: str | None, this_root: Path) -> Path:
    """Resolve the other repository's root from the CLI argument or default.

    Args:
        argument: The positional path argument, if given.
        this_root: Root of the repository this script runs from.

    Returns:
        The other repository's root.
    """
    if argument is not None:
        other = Path(argument).resolve()
        if not (other / "pyproject.toml").is_file():
            cli.die(f"'{other}' does not look like a repository (no pyproject.toml).")
        return other
    for name in (TEMPLATE_SNAKE, TEMPLATE_KEBAB):
        candidate = (this_root.parent / name).resolve()
        if candidate != this_root and (candidate / "pyproject.toml").is_file():
            return candidate
    cli.die(
        "No template checkout found in a sibling folder; "
        "pass the other repository's path as an argument."
    )


def orient(this_root: Path, other_root: Path) -> tuple[Path, Path]:
    """Work out which repository is the template and which is the project.

    Args:
        this_root: Root of the repository this script runs from.
        other_root: Root of the repository given on the command line.

    Returns:
        A ``(template_root, project_root)`` pair.
    """
    this_is_template = pyproject_name(this_root) == TEMPLATE_KEBAB
    other_is_template = pyproject_name(other_root) == TEMPLATE_KEBAB
    if this_is_template and other_is_template:
        cli.die("Both repositories are the template; nothing to compare.")
    if not this_is_template and not other_is_template:
        cli.die(
            f"Neither repository's pyproject.toml has [project] name '{TEMPLATE_KEBAB}'; "
            "one side must be a template checkout."
        )
    if this_is_template:
        return this_root, other_root
    return other_root, this_root


def resolve_names(project_root: Path, github_user_override: str | None) -> ProjectNames:
    """Determine the project's identity tokens for normalization.

    Args:
        project_root: Root of the project checkout.
        github_user_override: The ``--github-user`` value, if given.

    Returns:
        The project's names; ``github_user`` is ``None`` when no override was
        given and the origin remote is not a GitHub URL.
    """
    kebab = pyproject_name(project_root)
    if kebab is None:
        cli.die(f"Could not read [project] name from {project_root / 'pyproject.toml'}.")
    snake = kebab.replace("-", "_")
    github_user = github_user_override
    if github_user is None:
        url = cli.capture_ok(["git", "-C", str(project_root), "remote", "get-url", "origin"])
        if url is not None:
            github_user = github_user_from_url(url)
    return ProjectNames(snake=snake, kebab=kebab, github_user=github_user)


def versioned_entries() -> tuple[BaselineFile, ...]:
    """Return the manifest entries that carry their own ``__version__``.

    Returns:
        The subset of :data:`MANIFEST` for which :func:`carries_version` holds
        (the ``scripts/*.py`` helpers and any ``versioned`` entry), in manifest
        order.
    """
    return tuple(entry for entry in MANIFEST if carries_version(entry))


def check_versioned_file(
    entry: BaselineFile,
    ctx: CompareContext,
    *,
    required: bool,
    allow_update: bool,
) -> bool:
    """Compare one versioned file and offer to update the project's copy.

    Args:
        entry: The manifest entry for a versioned file (see
            :func:`carries_version`).
        ctx: Comparison context (roots, names, normalization switches).
        required: Whether the project must have this file (see
            :func:`effective_required`); the caller has already filtered out
            entries that aren't :func:`is_applicable` at all.
        allow_update: Whether updating may be offered (``False`` under
            ``--no-update``).

    Returns:
        ``True`` when the project's copy was written (installed or updated).
    """
    rel = entry.path
    # The project-side path may be renamed (the config package lives under
    # src/<snake>/), so it must be mapped exactly as compare_one and
    # install_from_template do -- reading the project's copy from the
    # template-named path would report every renamed file as missing.
    project_rel = map_project_path(rel, ctx.names)
    template_path = ctx.template_root / rel
    project_path = ctx.project_root / project_rel

    if not template_path.is_file():
        cli.warn(f"  The template has no {rel}; skipping.")
        return False
    template_text = decode_text(template_path.read_bytes()) or ""
    template_version = script_version(template_text)

    if not project_path.is_file():
        # An absent optional file is a deliberately removed feature, not
        # drift; leave it out. The main comparison still reports it as absent.
        if not required:
            return False
        status = f"  {project_rel}: missing (template {template_version or 'unversioned'})."
        if not allow_update:
            cli.warn(status)
            return False
        if cli.confirm(f"{cli.YELLOW}{status}{cli.RESET} Copy it from the template?"):
            install_from_template(entry, ctx)
            return True
        return False

    project_text = decode_text(project_path.read_bytes()) or ""
    project_version = script_version(project_text)
    # Compare the same normalized texts compare_one holds the project against,
    # so a file whose contents embed the template's name (the config package)
    # is not reported as differing every run purely because of the rename.
    # The versioned scripts/*.py helpers are unaffected: their template tokens
    # are built from pieces and the replays are path-scoped.
    same = normalize_eol(
        normalize_template_text(
            rel,
            template_text,
            ctx.names,
            dotted=ctx.dotted,
            compact=ctx.compact,
            ran_cleanup=ctx.ran_cleanup,
            private_repo_deps=ctx.flags.private_repo_deps,
        )
    ) == normalize_eol(normalize_project_text(rel, project_text))
    action = self_check_action(template_version, project_version, same_content=same)
    if action == "ok":
        return False

    # One line per file, matching the missing-file branch above: the path, its
    # status and both versions, with the confirmation prompt on the same line.
    display = rel if project_rel == rel else f"{rel} -> {project_rel}"
    template_label = template_version or "unversioned"
    project_label = project_version or "unversioned"
    if action == "ahead":
        cli.warn(
            f"  {display}: NEWER than the template (project {project_label}, "
            f"template {template_label}); not overwriting, consider upstreaming."
        )
        return False
    if action == "update":
        status = f"  {display}: outdated (project {project_label}, template {template_label})"
    else:  # "refresh": same version, different content
        status = f"  {display}: contents differ at version {template_label} (missing bump?)"
    if not allow_update:
        cli.warn(f"{status}; not updating (--no-update).")
        return False
    if not cli.confirm(f"{cli.YELLOW}{status}.{cli.RESET} Update it from the template?"):
        return False
    install_from_template(entry, ctx)
    return True


def exit_if_running_copy_replaced(entry: BaselineFile, ctx: CompareContext) -> None:
    """Stop the program when the file it is running from was just replaced.

    Both this script and the ``_cli`` module it imports are baseline files:
    once the executing copy is overwritten from the template, the manifest and
    replay logic in memory are stale, so the program stops right then (exit
    code 0) and the user re-runs the freshly copied version, which re-checks
    everything. A no-op when the updated copy is not the executing one (the
    script running from the template checkout updating the project's copy).

    Args:
        entry: The manifest entry whose project-side copy was just written.
        ctx: Comparison context (roots, names, normalization switches).
    """
    running_files = {
        normcase(normpath(str(Path(__file__).resolve()))),
        normcase(normpath(str(Path(cli.__file__).resolve()))),
    }
    project_rel = map_project_path(entry.path, ctx.names)
    project_path = normcase(normpath(str((ctx.project_root / project_rel).resolve())))
    if project_path not in running_files:
        return
    cli.warn(f"  Stopping; re-run the script to use the updated {entry.path}.")
    sys.exit(0)


def check_self_update(
    template_root: Path, project_root: Path, names: ProjectNames, *, allow_update: bool
) -> None:
    """Check this script and its ``_cli`` module against the template.

    Runs before ``template_setup.toml`` is even read, so a project whose config is
    missing or unfilled is still offered the template's current script first
    -- whose setup handling may be the very thing that changed. Only these
    two files can be checked this early: they are ungated, and normalization
    is a no-op for them by construction (their template tokens are built from
    pieces and the replays are path-scoped), so a provisional context built
    from template-default flags compares them correctly without the project's
    real feature choices. The remaining versioned files are handled afterward
    by :func:`check_versioned_files`, once the real flags are known.

    Args:
        template_root: Root of the template checkout.
        project_root: Root of the project checkout.
        names: Project-side identity tokens.
        allow_update: Whether updating may be offered (``False`` under
            ``--no-update``).
    """
    cli.section("Self check")
    ctx = CompareContext(
        template_root=template_root,
        project_root=project_root,
        names=names,
        dotted=None,
        compact=None,
        ran_cleanup=False,
        flags=feature_flags_from_config({}),
    )
    updated = 0
    for entry in MANIFEST:
        if entry.path not in _SELF_CHECK_PATHS:
            continue
        if check_versioned_file(entry, ctx, required=True, allow_update=allow_update):
            updated += 1
            exit_if_running_copy_replaced(entry, ctx)
    if updated == 0:
        cli.success("  This script and its _cli module are up to date with the template.")


def check_versioned_files(ctx: CompareContext, *, allow_update: bool) -> None:
    """Compare every versioned file and offer to update the project's copies.

    Runs before the main comparison so outdated copies (whose manifest and
    replay logic may lag the template) are refreshed first. This script and
    its ``_cli`` module are not re-checked here: the earlier
    :func:`check_self_update` already handled them -- and stopped the program
    for a re-run if the executing copy was replaced. Entries tied to
    a declined feature (:func:`is_applicable` is ``False``) are skipped entirely
    -- never offered for copy, same as they're never reported as drift in the
    main comparison.

    Args:
        ctx: Comparison context (roots, names, normalization switches).
        allow_update: Whether updating may be offered (``False`` under
            ``--no-update``).
    """
    cli.section("Versioned files")
    updated = 0
    for entry in versioned_entries():
        if entry.path in _SELF_CHECK_PATHS:
            continue
        if not is_applicable(entry, ctx.flags):
            continue
        if not check_versioned_file(
            entry,
            ctx,
            required=effective_required(entry, ctx.flags),
            allow_update=allow_update,
        ):
            continue
        updated += 1
    if updated == 0:
        cli.success("  All versioned files are up to date with the template.")


def offer_missing_installs(
    results: list[Comparison], ctx: CompareContext, *, allow_update: bool
) -> list[Comparison]:
    """Offer to install every missing required file from the template.

    The versioned files are excluded: the version pre-flight already offered
    to install those, so one still missing here was declined moments ago.
    Declined files keep their ``missing`` status (and exit-code weight).

    Args:
        results: Comparison results in manifest order.
        ctx: Comparison context (roots, names, normalization switches).
        allow_update: Whether installing may be offered (``False`` under
            ``--no-update``).

    Returns:
        The results in the same order, with each installed file re-compared.
    """
    candidates = [r for r in results if r.status == "missing" and not carries_version(r.entry)]
    if not candidates or not allow_update:
        return results
    cli.section("Missing files")
    replacements: dict[str, Comparison] = {}
    for result in candidates:
        status = f"  {result.project_rel}: missing."
        if not cli.confirm(f"{cli.YELLOW}{status}{cli.RESET} Copy it from the template?"):
            continue
        install_from_template(result.entry, ctx)
        replacements[result.entry.path] = compare_one(result.entry, ctx)
    return [replacements.get(r.entry.path, r) for r in results]


def offer_setup_config_install(
    template_root: Path, project_root: Path, *, allow_update: bool
) -> NoReturn:
    """Offer to copy the template's ``template_setup.toml`` into a project lacking one.

    The comparison cannot run without :data:`SETUP_CONFIG_REL` (see
    :func:`resolve_feature_flags`), so either way this exits. The copy is
    byte-for-byte on purpose -- not :func:`install_from_template`'s
    normalization, which would rename the ``[project]`` name in passing and
    let the freshly copied file (whose flags are all still the template's
    defaults) slip past :func:`setup_config_name_unchanged`'s guard. The user
    must fill the copy in and re-run.

    Args:
        template_root: Root of the template checkout.
        project_root: Root of the project checkout.
        allow_update: Whether the copy may be offered (``False`` under
            ``--no-update``).

    Raises:
        SystemExit: Always -- code 1 whether the copy was made, declined, or
            impossible; the comparison never ran.
    """
    path = project_root / SETUP_CONFIG_REL
    template_path = template_root / SETUP_CONFIG_REL
    cli.warn(f"  The project has no {SETUP_CONFIG_REL} ({path}).")
    cli.warn("  It records which optional features the project kept; the comparison")
    cli.warn("  cannot run without it.")
    if not template_path.is_file():
        cli.die(f"The template has no {SETUP_CONFIG_REL} either; restore the project's copy.")
    if not allow_update:
        cli.die("Restore it before comparing (--no-update: not offering to copy it).")
    if not cli.confirm(f"  Copy the template's {SETUP_CONFIG_REL} into the project?"):
        cli.die("Restore it before comparing.")
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(template_path, path)
    cli.success(f"  Copied {SETUP_CONFIG_REL} into the project.")
    cli.die(
        "Configure this project's settings in template_setup.toml, then run "
        "compare_to_template.py again."
    )
    sys.exit(1)


def build_context(
    template_root: Path, project_root: Path, names: ProjectNames, flags: FeatureFlags
) -> CompareContext:
    """Assemble the comparison context from the project's on-disk state.

    Args:
        template_root: Root of the template checkout.
        project_root: Root of the project checkout.
        names: Project-side identity tokens.
        flags: The project's resolved feature flags.

    Returns:
        The context used by :func:`compare_one`.
    """
    dotted: str | None = None
    compact: str | None = None
    version_file = project_root / ".python-version"
    if version_file.is_file():
        try:
            _full, dotted, compact = python_version_forms(
                version_file.read_text(encoding="utf-8").strip()
            )
        except (OSError, ValueError):  # fmt: skip
            cli.warn("  Could not parse the project's .python-version; not normalizing it.")
    return CompareContext(
        template_root=template_root,
        project_root=project_root,
        names=names,
        dotted=dotted,
        compact=compact,
        ran_cleanup=not (project_root / "scripts" / "template_setup").exists(),
        flags=flags,
    )


_STATUS_COLORS = {
    "modified": cli.RED,
    "missing": cli.RED,
    "review": cli.YELLOW,
    "no-template": cli.YELLOW,
    "match": cli.GREEN,
    "absent": cli.GRAY,
}


def print_results(results: list[Comparison], *, show_all: bool) -> None:
    """Print the per-file report lines.

    Args:
        results: Comparison results in manifest order.
        show_all: Whether to include matching and absent-optional files.
    """
    shown = [r for r in results if show_all or r.status not in ("match", "absent")]
    if not shown:
        cli.success("  All baseline files match the template.")
        return
    for result in shown:
        color = _STATUS_COLORS.get(result.status, "")
        path_display = result.entry.path
        if result.project_rel != result.entry.path:
            path_display = f"{result.entry.path} -> {result.project_rel}"
        print(
            f"  {color}{result.status:<12}{cli.RESET}{path_display}"
            f"{cli.GRAY}{result.note}{cli.RESET}"
        )


def print_diffs(results: list[Comparison]) -> None:
    """Print a unified diff for every differing text file.

    Diffs compare the normalized texts, so expected renames do not appear.

    Args:
        results: Comparison results in manifest order.
    """
    for result in results:
        if result.status not in ("modified", "review"):
            continue
        cli.section(f"Diff: {result.entry.path}")
        if result.template_norm is None or result.project_norm is None:
            print("  (binary file; no diff)")
            continue
        diff = difflib.unified_diff(
            result.template_norm.splitlines(),
            result.project_norm.splitlines(),
            fromfile=f"template/{result.entry.path}",
            tofile=f"project/{result.project_rel}",
            lineterm="",
        )
        for line in diff:
            if line.startswith(("+++", "---", "@@")):
                print(f"{cli.CYAN}{line}{cli.RESET}")
            elif line.startswith("+"):
                print(f"{cli.GREEN}{line}{cli.RESET}")
            elif line.startswith("-"):
                print(f"{cli.RED}{line}{cli.RESET}")
            else:
                print(line)


def resolve_code(explicit: str | None) -> list[str] | None:
    """Resolve the command used to open diff pairs in an editor.

    Args:
        explicit: The ``--diff-tool`` value, if given (e.g. ``"codium"``).

    Returns:
        The command split into arguments, or ``None`` when no explicit tool was
        given and ``code`` is not on ``PATH`` (the caller then falls back to
        printing diffs in the terminal).
    """
    if explicit and explicit.strip():
        return shlex.split(explicit, posix=(os.name != "nt"))
    if shutil.which("code"):
        return ["code"]
    return None


def launch_argv(argv: list[str]) -> list[str]:
    """Adapt an editor command line so it launches on the current platform.

    On Windows, VS Code's ``code`` entry point is a batch file (``code.cmd``)
    that ``subprocess`` cannot run without a shell, so such commands are routed
    through ``cmd /c``. On other platforms the command is returned unchanged.

    Args:
        argv: The command and its arguments, editor first.

    Returns:
        A command line suitable for :func:`subprocess.run` on this platform.
    """
    # platform.system() (unlike os.name/sys.platform) is not constant-folded by
    # type checkers, so this Windows branch stays analyzable on every platform.
    if platform.system() == "Windows" and argv:
        resolved = shutil.which(argv[0])
        if resolved and Path(resolved).suffix.lower() in (".cmd", ".bat"):
            return ["cmd", "/c", resolved, *argv[1:]]
    return argv


def diff_files_for(
    results: list[Comparison], base: Path, project_root: Path
) -> list[tuple[Path, Path]]:
    """Write each differing file's normalized template text under ``base``.

    The project side is opened directly from its live path in the project
    checkout, so edits made in the diff view apply straight to the real file.
    Only the template side needs a temp copy: its normalized text (banner
    stripped, names/version/cleanup replayed) exists nowhere on disk. Binary
    differences are skipped (they have no normalized text).

    Args:
        results: Comparison results in manifest order.
        base: Directory to write the temporary template copies into.
        project_root: Root of the project checkout.

    Returns:
        One ``(template_path, project_path)`` pair per differing text file, in
        manifest order.
    """
    pairs: list[tuple[Path, Path]] = []
    for result in results:
        if result.status not in ("modified", "review"):
            continue
        if result.template_norm is None or result.project_norm is None:
            continue
        left = base / result.entry.path
        right = project_root / result.project_rel
        left.parent.mkdir(parents=True, exist_ok=True)
        left.write_text(result.template_norm, encoding="utf-8")
        pairs.append((left, right))
    return pairs


def open_diffs_in_vscode(
    results: list[Comparison], code_argv: list[str], project_root: Path
) -> None:
    """Open each differing text file as a side-by-side diff in VS Code.

    Writes the template's normalized text to a temporary directory and diffs
    it against the project's live file, so edits on the project side land
    directly in the real file. The temp files are deliberately left in place:
    the editor reads them asynchronously, well after this process returns.

    Args:
        results: Comparison results in manifest order.
        code_argv: The resolved diff-tool command (see :func:`resolve_code`).
        project_root: Root of the project checkout.
    """
    binaries = [
        result.entry.path
        for result in results
        if result.status in ("modified", "review")
        and (result.template_norm is None or result.project_norm is None)
    ]
    for name in binaries:
        cli.warn(f"  Skipping binary file (no diff): {name}")

    base = Path(tempfile.mkdtemp(prefix="compare_to_template_"))
    pairs = diff_files_for(results, base, project_root)
    if not pairs:
        if not binaries:
            cli.warn("  No text differences to open.")
        return

    cli.info("Diff files", str(base))
    failures = 0
    for left, right in pairs:
        if cli.run_ok(launch_argv([*code_argv, "--diff", str(left), str(right)])) != 0:
            failures += 1
    if failures:
        cli.warn(f"  {failures} diff(s) failed to open.")
    cli.success(f"  Opened {len(pairs) - failures} diff(s) with {code_argv[0]}.")


# FeatureFlags field name -> human label, in the order printed in the
# "Feature configuration" section.
_FEATURE_LABELS: tuple[tuple[str, str], ...] = (
    ("mkdocs", "mkdocs"),
    ("config_system", "config package"),
    ("secret_storage", "secret-storage machinery"),
    ("keyring", "keyring secret backend"),
    ("keyvault", "Key Vault secret backend"),
    ("private_repo_deps", "private-repo-deps workflow steps"),
    ("remote_disposable_scripts", "remote-disposability scripts"),
    ("security_policy", "SECURITY.md"),
    ("contributing_guide", "CONTRIBUTING.md"),
)


def show_diffs(results: list[Comparison], diff_tool: str | None, project_root: Path) -> None:
    """Present the diffs: open them in VS Code, or print them if it is absent.

    Args:
        results: Comparison results in manifest order.
        diff_tool: The ``--diff-tool`` override, or ``None`` to auto-detect
            ``code``.
        project_root: Root of the project checkout.
    """
    code_argv = resolve_code(diff_tool)
    if code_argv is None:
        cli.warn("  VS Code CLI ('code') not found on PATH; printing diffs in the terminal.")
        cli.warn("  Install it (VS Code > Command Palette > Shell Command: Install 'code'),")
        cli.warn("  or pass --diff-tool to name another editor.")
        print_diffs(results)
        return
    cli.section("Diffs (VS Code)")
    open_diffs_in_vscode(results, code_argv, project_root)


def main() -> None:
    """Run the template comparison."""
    args = parse_args()
    cli.set_assume_yes(args.yes)

    print(f"{cli.CYAN}compare_to_template - baseline drift report{cli.RESET}")
    cli.info("Script version", __version__)

    this_root = Path(__file__).resolve().parent.parent
    other_root = resolve_other_root(args.other_repo, this_root)
    template_root, project_root = orient(this_root, other_root)
    names = resolve_names(project_root, args.github_user)

    cli.section("Repositories")
    cli.info("Template", str(template_root))
    cli.info("Project", str(project_root))
    cli.info("Project names", f"{names.snake} / {names.kebab}")
    if names.github_user is None:
        cli.warn("  No GitHub username found (origin remote is not GitHub?).")
        cli.warn("  Username differences will show as drift; pass --github-user to fix.")
    else:
        cli.info("GitHub user", names.github_user)

    check_self_update(template_root, project_root, names, allow_update=not args.no_update)

    if not (project_root / SETUP_CONFIG_REL).is_file():
        cli.section("Setup configuration")
        offer_setup_config_install(template_root, project_root, allow_update=not args.no_update)
    flags = resolve_feature_flags(project_root)
    cli.section("Feature configuration")
    cli.info("Source", flags.source)
    for gate, label in _FEATURE_LABELS:
        cli.info(label, "on" if flags.wanted(gate) else "off")

    ctx = build_context(template_root, project_root, names, flags)
    check_versioned_files(ctx, allow_update=not args.no_update)

    applicable = [entry for entry in MANIFEST if is_applicable(entry, flags)]
    skipped = [entry for entry in MANIFEST if not is_applicable(entry, flags)]
    results = [compare_one(entry, ctx) for entry in applicable]
    results = offer_missing_installs(results, ctx, allow_update=not args.no_update)

    cli.section("Comparison")
    if skipped and args.all:
        cli.warn(f"  Skipping {len(skipped)} file(s) tied to features this project doesn't have:")
        for entry in skipped:
            print(f"    {entry.path}")
    print_results(results, show_all=args.all)
    if args.diff:
        show_diffs(results, args.diff_tool, project_root)

    counts = {status: sum(1 for r in results if r.status == status) for status in _STATUS_COLORS}
    cli.section("Summary")
    cli.info("Baseline files", str(len(results)))
    cli.info("Match", str(counts["match"]))
    cli.info("Modified (drift)", str(counts["modified"]))
    cli.info("Missing (drift)", str(counts["missing"]))
    cli.info("Review only", str(counts["review"]))
    cli.info("Absent (optional)", str(counts["absent"]))
    if counts["no-template"]:
        cli.info("Not in template", str(counts["no-template"]))

    differing = counts["modified"] + counts["review"]
    if differing and not args.diff:
        print(f"\n  {cli.GRAY}Run again with --diff to see the differences.{cli.RESET}")

    drift = counts["modified"] + counts["missing"]
    print()
    if drift:
        cli.warn(f"Drift detected in {drift} baseline file(s).")
        sys.exit(1)
    cli.success("No drift in strict baseline files.")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):  # fmt: skip
        print()
        sys.exit(130)
