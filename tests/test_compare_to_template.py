"""Unit tests for the pure helpers in scripts/compare_to_template.py.

The scripts folder is not a package, so the module is imported by adding the
folder to sys.path, mirroring how the scripts import their shared _cli module.
Token strings (template name, author username) are built from the module's
constants rather than written literally, so the template-setup rename scripts
cannot rewrite them here.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import fields
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import _cli as cli
from compare_to_template import (
    _FEATURE_LABELS,
    _MARKER,
    _PRIVATE_REPO_DEPS_END,
    _PRIVATE_REPO_DEPS_START,
    MANIFEST,
    SETUP_CONFIG_REL,
    TEMPLATE_KEBAB,
    TEMPLATE_SNAKE,
    TEMPLATE_USER,
    BaselineFile,
    CompareContext,
    Comparison,
    FeatureFlags,
    ProjectNames,
    carries_version,
    check_self_update,
    check_versioned_file,
    check_versioned_files,
    compare_one,
    diff_files_for,
    effective_required,
    effective_strict,
    feature_flags_from_config,
    github_user_from_url,
    install_from_template,
    is_applicable,
    is_excluded,
    load_setup_config,
    map_project_path,
    normalize_eol,
    normalize_project_text,
    normalize_template_text,
    offer_missing_installs,
    offer_setup_config_install,
    pyproject_name,
    python_version_forms,
    replace_case_insensitive,
    replay_cleanup_pyproject,
    replay_private_repo_deps,
    replay_python_version,
    resolve_code,
    resolve_feature_flags,
    script_version,
    script_version_note,
    self_check_action,
    setup_config_name_unchanged,
    strip_package_purpose,
    strip_template_header,
    version_tuple,
)

NAMES = ProjectNames(snake="my_proj", kebab="my-proj", github_user="octocat")

BANNER = (
    "# =============================================================================\n"
    f"# {_MARKER} -- remove this block when you use this template\n"
    "# Explanatory text for template users.\n"
    "# =============================================================================\n"
    "\n"
)


def write(root: Path, rel: str, text: str) -> Path:
    """Write a file with exact contents (no newline translation)."""
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")
    return path


def make_flags(
    *,
    mkdocs: bool = True,
    config_system: bool = True,
    secret_storage: bool = True,
    keyring: bool = True,
    keyvault: bool = True,
    private_repo_deps: bool = True,
    remote_disposable_scripts: bool = True,
    security_policy: bool = True,
    contributing_guide: bool = True,
    source: str = "test",
) -> FeatureFlags:
    """Build a FeatureFlags with every feature on, unless overridden."""
    return FeatureFlags(
        mkdocs=mkdocs,
        config_system=config_system,
        secret_storage=secret_storage,
        keyring=keyring,
        keyvault=keyvault,
        private_repo_deps=private_repo_deps,
        remote_disposable_scripts=remote_disposable_scripts,
        security_policy=security_policy,
        contributing_guide=contributing_guide,
        source=source,
    )


def make_ctx(
    tmp_path: Path,
    *,
    names: ProjectNames = NAMES,
    dotted: str | None = None,
    compact: str | None = None,
    ran_cleanup: bool = False,
    flags: FeatureFlags | None = None,
) -> CompareContext:
    """Create template/ and project/ dirs under tmp_path and build a context."""
    template_root = tmp_path / "template"
    project_root = tmp_path / "project"
    template_root.mkdir(exist_ok=True)
    project_root.mkdir(exist_ok=True)
    return CompareContext(
        template_root=template_root,
        project_root=project_root,
        names=names,
        dotted=dotted,
        compact=compact,
        ran_cleanup=ran_cleanup,
        flags=flags if flags is not None else make_flags(),
    )


# --- version parsing ---------------------------------------------------------


@pytest.mark.unit
def test_version_tuple_parses_numeric_versions() -> None:
    assert version_tuple("1.2.3") == (1, 2, 3)
    assert version_tuple("10.0") == (10, 0)


@pytest.mark.unit
def test_version_tuple_rejects_non_numeric_parts() -> None:
    assert version_tuple("1.2.3rc1") is None
    assert version_tuple("abc") is None
    assert version_tuple("") is None


@pytest.mark.unit
def test_script_version_finds_declaration() -> None:
    assert script_version('x = 1\n__version__ = "1.4.0"\n') == "1.4.0"
    assert script_version("__version__ = '2.0.0'\n") == "2.0.0"


@pytest.mark.unit
def test_script_version_missing_returns_none() -> None:
    assert script_version("x = 1\n") is None


@pytest.mark.unit
def test_python_version_forms_major_minor() -> None:
    assert python_version_forms("3.13") == ("3.13", "3.13", "py313")


@pytest.mark.unit
def test_python_version_forms_keeps_patch_in_full_form() -> None:
    assert python_version_forms("3.14.3") == ("3.14.3", "3.14", "py314")


@pytest.mark.unit
def test_python_version_forms_rejects_garbage() -> None:
    with pytest.raises(ValueError, match="not a valid Python version"):
        python_version_forms("py314")


# --- GitHub username extraction ----------------------------------------------


@pytest.mark.unit
def test_github_user_from_https_url() -> None:
    assert github_user_from_url("https://github.com/octocat/my-proj.git") == "octocat"


@pytest.mark.unit
def test_github_user_from_scp_style_ssh_url() -> None:
    assert github_user_from_url("git@github.com:octocat/my-proj.git") == "octocat"


@pytest.mark.unit
def test_github_user_from_ssh_scheme_url() -> None:
    assert github_user_from_url("ssh://git@github.com/octocat/my-proj.git") == "octocat"


@pytest.mark.unit
def test_github_user_from_non_github_url_is_none() -> None:
    assert github_user_from_url("https://gitlab.com/octocat/my-proj.git") is None
    assert github_user_from_url("") is None


# --- text normalization -------------------------------------------------------


@pytest.mark.unit
def test_normalize_eol_converts_crlf_and_cr() -> None:
    assert normalize_eol("a\r\nb\rc\n") == "a\nb\nc\n"


@pytest.mark.unit
def test_replace_case_insensitive_replaces_all_casings() -> None:
    old = TEMPLATE_USER
    text = f"see {old} and {old.upper()} and {old.title()}"
    assert replace_case_insensitive(text, old, "octocat") == "see octocat and octocat and octocat"


@pytest.mark.unit
def test_strip_template_header_removes_hash_banner() -> None:
    assert strip_template_header(BANNER + "content\n") == "content\n"


@pytest.mark.unit
def test_strip_template_header_removes_slash_banner() -> None:
    banner = f"// ====\n// {_MARKER}\n// ====\n\ncontent\n"
    assert strip_template_header(banner) == "content\n"


@pytest.mark.unit
def test_strip_template_header_removes_markdown_banner() -> None:
    banner = f"<!--\n{_MARKER}\nexplanation\n-->\n\n# Title\n"
    assert strip_template_header(banner) == "# Title\n"


@pytest.mark.unit
def test_strip_template_header_without_marker_is_unchanged() -> None:
    text = "# just a comment\ncontent\n"
    assert strip_template_header(text) == text


@pytest.mark.unit
def test_strip_template_header_without_separators_is_unchanged() -> None:
    text = f"# {_MARKER}\ncontent\n"
    assert strip_template_header(text) == text


@pytest.mark.unit
def test_strip_template_header_ignores_marker_in_code() -> None:
    text = f'_MARKER = "{_MARKER}"\n'
    assert strip_template_header(text) == text


# --- setup-script replays ------------------------------------------------------


@pytest.mark.unit
def test_replay_python_version_rewrites_pyproject_pins() -> None:
    text = 'requires-python = ">=3.14"\ntarget-version = "py314"\npython_version = "3.14"\n'
    result = replay_python_version("pyproject.toml", text, "3.13", "py313")
    expected = 'requires-python = ">=3.13"\ntarget-version = "py313"\npython_version = "3.13"\n'
    assert result == expected


@pytest.mark.unit
def test_replay_python_version_rewrites_precommit_pin() -> None:
    result = replay_python_version(
        ".pre-commit-config.yaml", "  python: python3.14\n", "3.13", "py313"
    )
    assert result == "  python: python3.13\n"


@pytest.mark.unit
def test_replay_python_version_rewrites_contributing_and_readme() -> None:
    assert (
        replay_python_version("CONTRIBUTING.md", "Requires Python 3.14+.\n", "3.13", "py313")
        == "Requires Python 3.13+.\n"
    )
    assert (
        replay_python_version("README.md", "badge/python-3.14%2B-blue\n", "3.13", "py313")
        == "badge/python-3.13%2B-blue\n"
    )


@pytest.mark.unit
def test_replay_python_version_rewrites_bug_report_placeholder() -> None:
    text = 'id: python-version\n  attributes:\n    placeholder: "3.14.3"\n'
    result = replay_python_version(".github/ISSUE_TEMPLATE/bug_report.yml", text, "3.13", "py313")
    assert 'placeholder: "3.13.3"' in result


@pytest.mark.unit
def test_replay_python_version_leaves_other_files_alone() -> None:
    text = "python 3.14 mentioned in prose\n"
    assert replay_python_version("SECURITY.md", text, "3.13", "py313") == text


@pytest.mark.unit
def test_replay_cleanup_pyproject_drops_template_only_lines() -> None:
    text = (
        'addopts = [\n    "--cov=scripts",\n]\nmypy_path = ["scripts", "scripts/template_setup"]\n'
    )
    assert replay_cleanup_pyproject(text) == 'addopts = [\n]\nmypy_path = ["scripts"]\n'


@pytest.mark.unit
def test_replay_cleanup_pyproject_tolerates_missing_snippets() -> None:
    text = "unrelated = true\n"
    assert replay_cleanup_pyproject(text) == text


_PRIVATE_REPO_DEPS_BLOCK = (
    f"      {_PRIVATE_REPO_DEPS_START}\n"
    "      # FIXME uncomment if using Github app tokens to access private repos\n"
    "      # - name: Mint a token for private git deps\n"
    f"      # {_PRIVATE_REPO_DEPS_END}\n"
)


@pytest.mark.unit
def test_replay_private_repo_deps_strips_block_from_known_workflow() -> None:
    text = (
        "      - name: Install uv\n"
        "\n" + _PRIVATE_REPO_DEPS_BLOCK + "\n" + "      - name: Sync dependencies\n"
    )
    result = replay_private_repo_deps(".github/workflows/ci.yml", text)
    assert result == ("      - name: Install uv\n\n      - name: Sync dependencies\n")


@pytest.mark.unit
def test_replay_private_repo_deps_leaves_unrelated_files_alone() -> None:
    text = "      - name: Install uv\n\n" + _PRIVATE_REPO_DEPS_BLOCK + "\n"
    assert replay_private_repo_deps("README.md", text) == text


@pytest.mark.unit
def test_replay_private_repo_deps_tolerates_missing_block() -> None:
    text = "      - name: Install uv\n      - name: Sync dependencies\n"
    assert replay_private_repo_deps(".github/workflows/ci.yml", text) == text


@pytest.mark.unit
def test_strip_package_purpose_removes_section_from_agents_md() -> None:
    text = (
        "# Agent Rules\n"
        "\n"
        "## Package Purpose\n"
        "<!-- FIXME: describe the package. -->\n"
        "\n"
        "## General rules\n"
        "- Rule one.\n"
    )
    result = strip_package_purpose("AGENTS.md", text)
    assert result == "# Agent Rules\n\n## General rules\n- Rule one.\n"


@pytest.mark.unit
def test_strip_package_purpose_treats_differing_content_as_equal() -> None:
    template = "# Agent Rules\n\n## Package Purpose\n<!-- FIXME -->\n\n## General rules\n- Rule.\n"
    project = (
        "# Agent Rules\n\n## Package Purpose\nThis package parses widgets.\n\n"
        "## General rules\n- Rule.\n"
    )
    assert strip_package_purpose("AGENTS.md", template) == strip_package_purpose(
        "AGENTS.md", project
    )


@pytest.mark.unit
def test_strip_package_purpose_leaves_unrelated_files_alone() -> None:
    text = "## Package Purpose\nSomething unrelated in another file.\n"
    assert strip_package_purpose("README.md", text) == text


@pytest.mark.unit
def test_strip_package_purpose_tolerates_missing_heading() -> None:
    text = "# Agent Rules\n\n## General rules\n- Rule one.\n"
    assert strip_package_purpose("AGENTS.md", text) == text


@pytest.mark.unit
def test_strip_package_purpose_handles_last_section_in_file() -> None:
    text = "# Agent Rules\n\n## Package Purpose\nDescribes the package.\n"
    assert strip_package_purpose("AGENTS.md", text) == "# Agent Rules\n\n"


# --- token mapping -------------------------------------------------------------


@pytest.mark.unit
def test_map_project_path_renames_tokens_in_path() -> None:
    rel = f"docs/reference/{TEMPLATE_SNAKE}.md"
    assert map_project_path(rel, NAMES) == "docs/reference/my_proj.md"


@pytest.mark.unit
def test_map_project_path_leaves_plain_paths_alone() -> None:
    assert map_project_path("scripts/_cli.py", NAMES) == "scripts/_cli.py"


@pytest.mark.unit
def test_normalize_template_text_full_pipeline() -> None:
    text = BANNER + f"pkg {TEMPLATE_SNAKE} dist {TEMPLATE_KEBAB} by {TEMPLATE_USER.title()}\n"
    result = normalize_template_text("notes.md", text, NAMES)
    assert result == "pkg my_proj dist my-proj by octocat\n"


@pytest.mark.unit
def test_normalize_template_text_skips_user_when_unknown() -> None:
    names = ProjectNames(snake="my_proj", kebab="my-proj", github_user=None)
    text = f"by {TEMPLATE_USER}\n"
    assert normalize_template_text("notes.md", text, names) == f"by {TEMPLATE_USER}\n"


@pytest.mark.unit
def test_normalize_template_text_strips_package_purpose_from_agents_md() -> None:
    text = "# Agent Rules\n\n## Package Purpose\n<!-- FIXME -->\n\n## General rules\n- Rule.\n"
    result = normalize_template_text("AGENTS.md", text, NAMES)
    assert result == "# Agent Rules\n\n## General rules\n- Rule.\n"


@pytest.mark.unit
def test_normalize_project_text_strips_package_purpose_from_agents_md() -> None:
    text = "# Agent Rules\n\n## Package Purpose\nParses widgets.\n\n## General rules\n- Rule.\n"
    result = normalize_project_text("AGENTS.md", text)
    assert result == "# Agent Rules\n\n## General rules\n- Rule.\n"


@pytest.mark.unit
def test_normalize_project_text_leaves_other_files_alone() -> None:
    text = "## Package Purpose\nUnrelated content.\n"
    assert normalize_project_text("README.md", text) == text


# --- strictness ------------------------------------------------------------------


@pytest.mark.unit
def test_effective_strict_demotes_mkdocs_edited_files_when_removed() -> None:
    entry = BaselineFile("CONTRIBUTING.md")
    assert effective_strict(entry, has_mkdocs=True) is True
    assert effective_strict(entry, has_mkdocs=False) is False


@pytest.mark.unit
def test_effective_strict_keeps_other_files_strict() -> None:
    entry = BaselineFile("CLAUDE.md")
    assert effective_strict(entry, has_mkdocs=False) is True


@pytest.mark.unit
def test_effective_strict_never_promotes_lenient_files() -> None:
    entry = BaselineFile("pyproject.toml", strict=False)
    assert effective_strict(entry, has_mkdocs=True) is False


# --- version notes and self-check ------------------------------------------------


@pytest.mark.unit
def test_script_version_note_outdated_and_ahead() -> None:
    older = '__version__ = "1.1.0"\n'
    newer = '__version__ = "1.2.0"\n'
    assert "outdated" in script_version_note(newer, older)
    assert "upstream" in script_version_note(older, newer)


@pytest.mark.unit
def test_script_version_note_same_version() -> None:
    text = '__version__ = "1.0.0"\n'
    assert "without a version bump" in script_version_note(text, text)


@pytest.mark.unit
def test_script_version_note_missing_version_is_empty() -> None:
    assert script_version_note("x = 1\n", '__version__ = "1.0.0"\n') == ""


@pytest.mark.unit
def test_self_check_action_identical_content() -> None:
    assert self_check_action("1.0.0", "1.0.0", same_content=True) == "ok"


@pytest.mark.unit
def test_self_check_action_project_older() -> None:
    assert self_check_action("1.2.0", "1.1.0", same_content=False) == "update"


@pytest.mark.unit
def test_self_check_action_project_newer() -> None:
    assert self_check_action("1.1.0", "1.2.0", same_content=False) == "ahead"


@pytest.mark.unit
def test_self_check_action_unparseable_version() -> None:
    assert self_check_action("1.1.0", None, same_content=False) == "update"


@pytest.mark.unit
def test_self_check_action_same_version_different_content() -> None:
    assert self_check_action("1.1.0", "1.1.0", same_content=False) == "refresh"


# --- compare_one -------------------------------------------------------------------


@pytest.mark.unit
def test_compare_one_match_after_normalization(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    template = BANNER + f"pkg {TEMPLATE_SNAKE} dist {TEMPLATE_KEBAB} by {TEMPLATE_USER}\n"
    write(ctx.template_root, "notes.md", template)
    write(ctx.project_root, "notes.md", "pkg my_proj dist my-proj by octocat\n")
    result = compare_one(BaselineFile("notes.md"), ctx)
    assert result.status == "match"


@pytest.mark.unit
def test_compare_one_match_ignores_line_endings(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "notes.md", "line one\nline two\n")
    write(ctx.project_root, "notes.md", "line one\r\nline two\r\n")
    assert compare_one(BaselineFile("notes.md"), ctx).status == "match"


@pytest.mark.unit
def test_compare_one_modified_strict(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "notes.md", "template says A\n")
    write(ctx.project_root, "notes.md", "project says B\n")
    result = compare_one(BaselineFile("notes.md"), ctx)
    assert result.status == "modified"
    assert result.template_norm is not None
    assert result.project_norm is not None


@pytest.mark.unit
def test_compare_one_review_for_lenient_entries(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "notes.md", "template says A\n")
    write(ctx.project_root, "notes.md", "project says B\n")
    result = compare_one(BaselineFile("notes.md", strict=False), ctx)
    assert result.status == "review"
    assert "expected to differ" in result.note


@pytest.mark.unit
def test_compare_one_missing_required(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "notes.md", "content\n")
    assert compare_one(BaselineFile("notes.md"), ctx).status == "missing"


@pytest.mark.unit
def test_compare_one_absent_optional(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "notes.md", "content\n")
    assert compare_one(BaselineFile("notes.md", required=False), ctx).status == "absent"


@pytest.mark.unit
def test_compare_one_no_template(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.project_root, "notes.md", "content\n")
    assert compare_one(BaselineFile("notes.md"), ctx).status == "no-template"


@pytest.mark.unit
def test_compare_one_existence_only_ignores_content(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "README.md", "template readme\n")
    write(ctx.project_root, "README.md", "a completely different project readme\n")
    result = compare_one(BaselineFile("README.md", compare_content=False), ctx)
    assert result.status == "match"
    assert "contents not compared" in result.note
    # The contents are never read, so no normalized text is stored for --diff.
    assert result.template_norm is None
    assert result.project_norm is None


@pytest.mark.unit
def test_compare_one_existence_only_missing_required_is_drift(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "README.md", "template readme\n")
    result = compare_one(BaselineFile("README.md", compare_content=False), ctx)
    assert result.status == "missing"


@pytest.mark.unit
def test_compare_one_existence_only_absent_when_optional(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "extra.md", "template extra\n")
    result = compare_one(BaselineFile("extra.md", required=False, compare_content=False), ctx)
    assert result.status == "absent"


@pytest.mark.unit
def test_compare_one_binary_files(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    (ctx.template_root / "blob.bin").write_bytes(b"\xff\xfe\x00\x01")
    (ctx.project_root / "blob.bin").write_bytes(b"\xff\xfe\x00\x01")
    assert compare_one(BaselineFile("blob.bin"), ctx).status == "match"
    (ctx.project_root / "blob.bin").write_bytes(b"\xff\xfe\x00\x02")
    result = compare_one(BaselineFile("blob.bin"), ctx)
    assert result.status == "modified"
    assert "binary" in result.note


@pytest.mark.unit
def test_compare_one_notes_script_versions(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "scripts/helper.py", '__version__ = "1.2.0"\nnew = True\n')
    write(ctx.project_root, "scripts/helper.py", '__version__ = "1.1.0"\n')
    result = compare_one(BaselineFile("scripts/helper.py"), ctx)
    assert result.status == "modified"
    assert "project 1.1.0 < template 1.2.0" in result.note


@pytest.mark.unit
def test_compare_one_notes_versioned_non_script(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "tests/test_guard.py", '__version__ = "1.2.0"\nnew = True\n')
    write(ctx.project_root, "tests/test_guard.py", '__version__ = "1.1.0"\n')
    result = compare_one(BaselineFile("tests/test_guard.py", versioned=True), ctx)
    assert result.status == "modified"
    assert "project 1.1.0 < template 1.2.0" in result.note


@pytest.mark.unit
def test_compare_one_demotes_mkdocs_edited_file(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path, flags=make_flags(mkdocs=False))
    write(ctx.template_root, "CONTRIBUTING.md", "with docs section\n")
    write(ctx.project_root, "CONTRIBUTING.md", "docs section removed\n")
    result = compare_one(BaselineFile("CONTRIBUTING.md"), ctx)
    assert result.status == "review"
    assert "mkdocs removed" in result.note


@pytest.mark.unit
def test_compare_one_matches_after_private_repo_deps_removal(tmp_path: Path) -> None:
    # Unlike mkdocs (demoted to "review"), a declined private_repo_deps still
    # compares as a clean "match": the template side is stripped down to what
    # remove_private_repo_deps.py leaves in the project, byte-for-byte.
    ctx = make_ctx(tmp_path, flags=make_flags(private_repo_deps=False))
    template = (
        "      - name: Install uv\n\n" + _PRIVATE_REPO_DEPS_BLOCK + "\n"
        "      - name: Sync dependencies\n"
    )
    project = "      - name: Install uv\n\n      - name: Sync dependencies\n"
    write(ctx.template_root, ".github/workflows/ci.yml", template)
    write(ctx.project_root, ".github/workflows/ci.yml", project)
    result = compare_one(BaselineFile(".github/workflows/ci.yml"), ctx)
    assert result.status == "match"


@pytest.mark.unit
def test_compare_one_reports_drift_when_private_repo_deps_kept_but_edited(tmp_path: Path) -> None:
    # With the feature kept (the default), the block is never stripped from
    # the template side, so a project that hand-edited it still shows drift.
    ctx = make_ctx(tmp_path, flags=make_flags(private_repo_deps=True))
    template = (
        "      - name: Install uv\n\n" + _PRIVATE_REPO_DEPS_BLOCK + "\n"
        "      - name: Sync dependencies\n"
    )
    project = "      - name: Install uv\n\n      - name: Sync dependencies\n"
    write(ctx.template_root, ".github/workflows/ci.yml", template)
    write(ctx.project_root, ".github/workflows/ci.yml", project)
    result = compare_one(BaselineFile(".github/workflows/ci.yml"), ctx)
    assert result.status == "modified"


@pytest.mark.unit
def test_compare_one_matches_agents_md_despite_differing_package_purpose(
    tmp_path: Path,
) -> None:
    # AGENTS.md is a strict=False entry, but even the "review" note it would
    # otherwise get should not fire just because each project's Package
    # Purpose section is, by design, always different from the template's.
    ctx = make_ctx(tmp_path)
    template = "# Agent Rules\n\n## Package Purpose\n<!-- FIXME -->\n\n## General rules\n- R.\n"
    project = "# Agent Rules\n\n## Package Purpose\nParses widgets.\n\n## General rules\n- R.\n"
    write(ctx.template_root, "AGENTS.md", template)
    write(ctx.project_root, "AGENTS.md", project)
    result = compare_one(BaselineFile("AGENTS.md", strict=False), ctx)
    assert result.status == "match"


@pytest.mark.unit
def test_compare_one_maps_renamed_paths(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    rel = f"docs/reference/{TEMPLATE_SNAKE}.md"
    write(ctx.template_root, rel, f"::: {TEMPLATE_SNAKE}\n")
    write(ctx.project_root, "docs/reference/my_proj.md", "::: my_proj\n")
    result = compare_one(BaselineFile(rel, required=False, strict=False), ctx)
    assert result.status == "match"
    assert result.project_rel == "docs/reference/my_proj.md"


# --- installing from the template ----------------------------------------------------


@pytest.mark.unit
def test_install_from_template_writes_normalized_text(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    template = BANNER + f"pkg {TEMPLATE_SNAKE} dist {TEMPLATE_KEBAB} by {TEMPLATE_USER}\n"
    write(ctx.template_root, "notes.md", template)
    assert install_from_template(BaselineFile("notes.md"), ctx) == "notes.md"
    installed = (ctx.project_root / "notes.md").read_bytes().decode("utf-8")
    assert installed == "pkg my_proj dist my-proj by octocat\n"
    assert compare_one(BaselineFile("notes.md"), ctx).status == "match"


@pytest.mark.unit
def test_install_from_template_maps_renamed_paths(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    rel = f"docs/reference/{TEMPLATE_SNAKE}.md"
    write(ctx.template_root, rel, f"::: {TEMPLATE_SNAKE}\n")
    assert install_from_template(BaselineFile(rel), ctx) == "docs/reference/my_proj.md"
    installed = ctx.project_root / "docs" / "reference" / "my_proj.md"
    assert installed.read_bytes().decode("utf-8") == "::: my_proj\n"


@pytest.mark.unit
def test_offer_missing_installs_installs_on_confirm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "notes.md", f"pkg {TEMPLATE_SNAKE}\n")
    entry = BaselineFile("notes.md")
    results = [compare_one(entry, ctx)]
    assert results[0].status == "missing"
    monkeypatch.setattr(cli, "confirm", lambda _msg: True)
    updated = offer_missing_installs(results, ctx, allow_update=True)
    assert updated[0].status == "match"
    assert (ctx.project_root / "notes.md").read_bytes().decode("utf-8") == "pkg my_proj\n"


@pytest.mark.unit
def test_offer_missing_installs_keeps_missing_when_declined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "notes.md", "content\n")
    results = [compare_one(BaselineFile("notes.md"), ctx)]
    monkeypatch.setattr(cli, "confirm", lambda _msg: False)
    updated = offer_missing_installs(results, ctx, allow_update=True)
    assert updated[0].status == "missing"
    assert not (ctx.project_root / "notes.md").exists()


@pytest.mark.unit
def test_offer_missing_installs_skips_versioned_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The version pre-flight already offered these; no second prompt.
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "scripts/helper.py", '__version__ = "1.0.0"\n')

    def unexpected(_msg: str) -> bool:
        raise AssertionError("confirm() should not be called for versioned entries")

    monkeypatch.setattr(cli, "confirm", unexpected)
    results = [compare_one(BaselineFile("scripts/helper.py"), ctx)]
    updated = offer_missing_installs(results, ctx, allow_update=True)
    assert updated[0].status == "missing"
    assert not (ctx.project_root / "scripts" / "helper.py").exists()


@pytest.mark.unit
def test_offer_missing_installs_respects_no_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, "notes.md", "content\n")

    def unexpected(_msg: str) -> bool:
        raise AssertionError("confirm() should not be called under --no-update")

    monkeypatch.setattr(cli, "confirm", unexpected)
    results = [compare_one(BaselineFile("notes.md"), ctx)]
    updated = offer_missing_installs(results, ctx, allow_update=False)
    assert updated[0].status == "missing"
    assert not (ctx.project_root / "notes.md").exists()


# --- the versioned-file pre-flight ---------------------------------------------------

# A versioned entry whose path embeds the template's package name, so the
# project's copy lives at a renamed path (the config package). Built from the
# module's constant, per this file's docstring.
_RENAMED_VERSIONED_REL = f"src/{TEMPLATE_SNAKE}/config/cli.py"
_RENAMED_PROJECT_REL = f"src/{NAMES.snake}/config/cli.py"


def _renamed_entry() -> BaselineFile:
    """Build the manifest entry for the renamed versioned file above."""
    return BaselineFile(_RENAMED_VERSIONED_REL, versioned=True, gate="config_system")


@pytest.mark.unit
@pytest.mark.regression
def test_check_versioned_file_reads_the_renamed_project_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: the pre-flight used to stat the project at the template's
    # own path, so every file under src/<template snake>/ read as missing and
    # was offered for copy -- overwriting the project's real copy.
    ctx = make_ctx(tmp_path)
    body = f'__version__ = "1.0.0"\npkg = "{TEMPLATE_SNAKE}"\n'
    write(ctx.template_root, _RENAMED_VERSIONED_REL, body)
    write(ctx.project_root, _RENAMED_PROJECT_REL, body.replace(TEMPLATE_SNAKE, NAMES.snake))

    def unexpected(_msg: str) -> bool:
        raise AssertionError("confirm() should not be called for an up-to-date copy")

    monkeypatch.setattr(cli, "confirm", unexpected)
    assert not check_versioned_file(_renamed_entry(), ctx, required=True, allow_update=True)


@pytest.mark.unit
def test_check_versioned_file_updates_the_renamed_project_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, _RENAMED_VERSIONED_REL, '__version__ = "1.2.0"\nnew = True\n')
    write(ctx.project_root, _RENAMED_PROJECT_REL, '__version__ = "1.1.0"\n')
    monkeypatch.setattr(cli, "confirm", lambda _msg: True)
    assert check_versioned_file(_renamed_entry(), ctx, required=True, allow_update=True)
    written = (ctx.project_root / _RENAMED_PROJECT_REL).read_bytes().decode("utf-8")
    assert written == '__version__ = "1.2.0"\nnew = True\n'
    assert not (ctx.project_root / _RENAMED_VERSIONED_REL).exists()


@pytest.mark.unit
def test_check_versioned_file_reports_the_missing_project_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A genuinely missing file is named by its project-side path, so the user
    # can go look for it.
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, _RENAMED_VERSIONED_REL, '__version__ = "1.0.0"\n')
    monkeypatch.setattr(cli, "confirm", lambda _msg: False)
    assert not check_versioned_file(_renamed_entry(), ctx, required=True, allow_update=True)
    out = capsys.readouterr().out
    assert f"missing {_RENAMED_PROJECT_REL}" in out


@pytest.mark.unit
def test_check_versioned_file_leaves_optional_missing_file_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, _RENAMED_VERSIONED_REL, '__version__ = "1.0.0"\n')

    def unexpected(_msg: str) -> bool:
        raise AssertionError("confirm() should not be called for an optional absent file")

    monkeypatch.setattr(cli, "confirm", unexpected)
    assert not check_versioned_file(_renamed_entry(), ctx, required=False, allow_update=True)


# --- self check ----------------------------------------------------------------------


_SELF_REL = "scripts/compare_to_template.py"
_CLI_REL = "scripts/_cli.py"


@pytest.mark.unit
def test_check_self_update_runs_without_setup_toml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The whole point of the early self-check: an outdated script copy is
    # offered before template_setup.toml is ever read, so neither side needs one here.
    template_root = tmp_path / "template"
    project_root = tmp_path / "project"
    write(template_root, _SELF_REL, '__version__ = "9.9.9"\nnew = True\n')
    write(template_root, _CLI_REL, '__version__ = "1.0.0"\n')
    write(project_root, _SELF_REL, '__version__ = "1.0.0"\n')
    write(project_root, _CLI_REL, '__version__ = "1.0.0"\n')
    monkeypatch.setattr(cli, "confirm", lambda _msg: True)
    check_self_update(template_root, project_root, NAMES, allow_update=True)
    written = (project_root / _SELF_REL).read_bytes().decode("utf-8")
    assert written == '__version__ = "9.9.9"\nnew = True\n'


@pytest.mark.unit
def test_check_self_update_leaves_up_to_date_copies_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template_root = tmp_path / "template"
    project_root = tmp_path / "project"
    for rel in (_SELF_REL, _CLI_REL):
        write(template_root, rel, '__version__ = "1.0.0"\n')
        write(project_root, rel, '__version__ = "1.0.0"\n')

    def unexpected(_msg: str) -> bool:
        raise AssertionError("confirm() should not be called for up-to-date copies")

    monkeypatch.setattr(cli, "confirm", unexpected)
    check_self_update(template_root, project_root, NAMES, allow_update=True)


@pytest.mark.unit
def test_check_versioned_files_skips_the_self_check_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The early self-check already handled these two; re-checking here would
    # re-prompt for a copy the user just declined.
    ctx = make_ctx(tmp_path)
    write(ctx.template_root, _SELF_REL, '__version__ = "9.9.9"\n')
    write(ctx.template_root, _CLI_REL, '__version__ = "9.9.9"\n')
    write(ctx.project_root, _SELF_REL, '__version__ = "1.0.0"\n')
    write(ctx.project_root, _CLI_REL, '__version__ = "1.0.0"\n')

    def unexpected(_msg: str) -> bool:
        raise AssertionError("confirm() should not be called for the self-check pair")

    monkeypatch.setattr(cli, "confirm", unexpected)
    check_versioned_files(ctx, allow_update=True)
    assert (ctx.project_root / _SELF_REL).read_bytes() == b'__version__ = "1.0.0"\n'


# --- feature gating ------------------------------------------------------------------


@pytest.mark.unit
def test_feature_labels_cover_every_flag() -> None:
    # Every FeatureFlags toggle is printed in the report; a flag added without
    # a label would silently drop out of the "Feature configuration" section.
    labelled = {gate for gate, _label in _FEATURE_LABELS}
    toggles = {f.name for f in fields(FeatureFlags) if f.name != "source"}
    assert labelled == toggles


@pytest.mark.unit
def test_is_applicable_true_for_ungated_entries() -> None:
    assert is_applicable(BaselineFile("CLAUDE.md"), make_flags(mkdocs=False)) is True


@pytest.mark.unit
def test_is_applicable_follows_the_matching_flag() -> None:
    entry = BaselineFile("mkdocs.yml", gate="mkdocs")
    assert is_applicable(entry, make_flags(mkdocs=True)) is True
    assert is_applicable(entry, make_flags(mkdocs=False)) is False


@pytest.mark.unit
def test_effective_required_uses_static_field_when_ungated() -> None:
    flags = make_flags()
    assert effective_required(BaselineFile("CLAUDE.md"), flags) is True
    assert effective_required(BaselineFile("extra.md", required=False), flags) is False


@pytest.mark.unit
def test_effective_required_ignores_the_flag_for_gated_entries() -> None:
    # Meaningful only once a caller's is_applicable() check has already kept
    # the entry in play (which implies the flag is True); as a pure function
    # it always reports a gated entry as required, trusting the caller to
    # have filtered out declined features first.
    entry = BaselineFile("SECURITY.md", gate="security_policy")
    assert effective_required(entry, make_flags(security_policy=False)) is True


@pytest.mark.unit
def test_compare_one_missing_is_drift_when_feature_kept(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path, flags=make_flags(security_policy=True))
    write(ctx.template_root, "SECURITY.md", "content\n")
    entry = BaselineFile("SECURITY.md", gate="security_policy")
    assert compare_one(entry, ctx).status == "missing"


@pytest.mark.unit
def test_feature_flags_from_config_reads_features_table() -> None:
    raw = {
        "features": {
            "mkdocs": False,
            "config_system": False,
            "secret_storage": False,
            "keyring": False,
            "keyvault": False,
            "private_repo_deps": False,
            "remote_disposable_scripts": False,
            "security_policy": False,
            "contributing_guide": False,
        },
    }
    flags = feature_flags_from_config(raw)
    assert flags.mkdocs is False
    assert flags.config_system is False
    assert flags.secret_storage is False
    assert flags.keyring is False
    assert flags.keyvault is False
    assert flags.private_repo_deps is False
    assert flags.remote_disposable_scripts is False
    assert flags.security_policy is False
    assert flags.contributing_guide is False
    assert flags.source == SETUP_CONFIG_REL


@pytest.mark.unit
def test_feature_flags_from_config_defaults_to_keep_everything() -> None:
    # An unedited config's [features] table is all-true; a config missing that
    # table entirely reads the same way.
    flags = feature_flags_from_config({})
    assert flags.mkdocs is True
    assert flags.config_system is True
    assert flags.secret_storage is True
    assert flags.keyring is True
    assert flags.keyvault is True
    assert flags.private_repo_deps is True
    assert flags.remote_disposable_scripts is True
    assert flags.security_policy is True
    assert flags.contributing_guide is True


@pytest.mark.unit
def test_feature_flags_from_config_backends_follow_config_system() -> None:
    # The secret machinery lives inside the config package and the backends
    # inside the machinery: declining a container drops its contents too,
    # whatever their own flags say.
    raw = {
        "features": {
            "config_system": False,
            "secret_storage": True,
            "keyring": True,
            "keyvault": True,
        }
    }
    flags = feature_flags_from_config(raw)
    assert flags.config_system is False
    assert flags.secret_storage is False
    assert flags.keyring is False
    assert flags.keyvault is False


@pytest.mark.unit
def test_feature_flags_from_config_backends_follow_secret_storage() -> None:
    raw = {"features": {"secret_storage": False, "keyring": True, "keyvault": True}}
    flags = feature_flags_from_config(raw)
    assert flags.config_system is True
    assert flags.secret_storage is False
    assert flags.keyring is False
    assert flags.keyvault is False


@pytest.mark.unit
def test_feature_flags_from_config_backends_independent_when_package_kept() -> None:
    raw = {"features": {"config_system": True, "keyring": False, "keyvault": True}}
    flags = feature_flags_from_config(raw)
    assert flags.keyring is False
    assert flags.keyvault is True


@pytest.mark.unit
def test_feature_flags_from_config_tolerates_malformed_tables() -> None:
    flags = feature_flags_from_config({"features": "not a table"})
    assert flags.mkdocs is True


@pytest.mark.unit
def test_load_setup_config_missing_file_is_none(tmp_path: Path) -> None:
    assert load_setup_config(tmp_path) is None


@pytest.mark.unit
def test_load_setup_config_invalid_toml_is_none(tmp_path: Path) -> None:
    write(tmp_path, SETUP_CONFIG_REL, "not [ valid toml")
    assert load_setup_config(tmp_path) is None


@pytest.mark.unit
def test_load_setup_config_parses_valid_toml(tmp_path: Path) -> None:
    write(tmp_path, SETUP_CONFIG_REL, "[features]\nmkdocs = false\n")
    raw = load_setup_config(tmp_path)
    assert raw is not None
    assert raw["features"]["mkdocs"] is False


@pytest.mark.unit
def test_resolve_feature_flags_reads_config(tmp_path: Path) -> None:
    # The config drives the result: mkdocs is on even though no mkdocs.yml
    # exists on disk (the file presence is never consulted).
    write(tmp_path, SETUP_CONFIG_REL, "[features]\nmkdocs = true\n")
    flags = resolve_feature_flags(tmp_path)
    assert flags.source == SETUP_CONFIG_REL
    assert flags.mkdocs is True


@pytest.mark.unit
def test_resolve_feature_flags_errors_when_config_absent(tmp_path: Path) -> None:
    # A missing template_setup.toml is a hard error, not a cue to guess from file
    # presence -- even when feature files exist on disk.
    write(tmp_path, "mkdocs.yml", "site_name: x\n")
    with pytest.raises(SystemExit):
        resolve_feature_flags(tmp_path)


@pytest.mark.unit
def test_resolve_feature_flags_errors_when_config_unparsable(tmp_path: Path) -> None:
    write(tmp_path, SETUP_CONFIG_REL, "not [ valid toml")
    with pytest.raises(SystemExit):
        resolve_feature_flags(tmp_path)


@pytest.mark.unit
def test_resolve_feature_flags_errors_when_name_still_template(tmp_path: Path) -> None:
    # A config still naming the project after the template was never filled
    # in, so its flags are just the template's defaults -- a hard error.
    write(tmp_path, SETUP_CONFIG_REL, f'[project]\nname = "{TEMPLATE_SNAKE}"\n')
    with pytest.raises(SystemExit):
        resolve_feature_flags(tmp_path)


@pytest.mark.unit
def test_resolve_feature_flags_accepts_a_renamed_project(tmp_path: Path) -> None:
    write(tmp_path, SETUP_CONFIG_REL, '[project]\nname = "my_proj"\n[features]\nmkdocs = false\n')
    flags = resolve_feature_flags(tmp_path)
    assert flags.mkdocs is False


@pytest.mark.unit
def test_setup_config_name_unchanged_folds_case_and_separators() -> None:
    # Mirrors rename_project.derive_names(): any case, spaces/hyphens fold to
    # underscores, so every spelling of the template's name is caught.
    assert setup_config_name_unchanged({"project": {"name": TEMPLATE_SNAKE}}) is True
    assert setup_config_name_unchanged({"project": {"name": TEMPLATE_KEBAB}}) is True
    assert (
        setup_config_name_unchanged({"project": {"name": TEMPLATE_SNAKE.replace("_", " ").title()}})
        is True
    )


@pytest.mark.unit
def test_setup_config_name_unchanged_false_for_other_or_missing_names() -> None:
    assert setup_config_name_unchanged({"project": {"name": "my_proj"}}) is False
    # A trimmed or malformed [project] table is tolerated, like every other
    # hand-trimmed key -- only a present template name is the error signal.
    assert setup_config_name_unchanged({}) is False
    assert setup_config_name_unchanged({"project": "not a table"}) is False
    assert setup_config_name_unchanged({"project": {"name": 3}}) is False


# --- offer_setup_config_install ------------------------------------------------------


@pytest.mark.unit
def test_offer_setup_config_install_copies_verbatim_and_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The copy must be byte-for-byte -- the template's own name included --
    # so the unfilled copy still trips the name guard on the next run.
    template_root = tmp_path / "template"
    project_root = tmp_path / "project"
    text = f'[project]\nname = "{TEMPLATE_SNAKE}"\n[features]\nmkdocs = true\n'
    write(template_root, SETUP_CONFIG_REL, text)
    project_root.mkdir()
    monkeypatch.setattr(cli, "confirm", lambda prompt: True)
    with pytest.raises(SystemExit) as excinfo:
        offer_setup_config_install(template_root, project_root, allow_update=True)
    assert excinfo.value.code == 1
    assert (project_root / SETUP_CONFIG_REL).read_text(encoding="utf-8") == text


@pytest.mark.unit
def test_offer_setup_config_install_declined_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template_root = tmp_path / "template"
    project_root = tmp_path / "project"
    write(template_root, SETUP_CONFIG_REL, "[features]\n")
    project_root.mkdir()
    monkeypatch.setattr(cli, "confirm", lambda prompt: False)
    with pytest.raises(SystemExit):
        offer_setup_config_install(template_root, project_root, allow_update=True)
    assert not (project_root / SETUP_CONFIG_REL).exists()


@pytest.mark.unit
def test_offer_setup_config_install_never_prompts_under_no_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template_root = tmp_path / "template"
    project_root = tmp_path / "project"
    write(template_root, SETUP_CONFIG_REL, "[features]\n")
    project_root.mkdir()

    def _fail(prompt: str) -> bool:
        raise AssertionError("confirm() must not be called under --no-update")

    monkeypatch.setattr(cli, "confirm", _fail)
    with pytest.raises(SystemExit):
        offer_setup_config_install(template_root, project_root, allow_update=False)
    assert not (project_root / SETUP_CONFIG_REL).exists()


@pytest.mark.unit
def test_offer_setup_config_install_errors_when_template_also_lacks_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template_root = tmp_path / "template"
    project_root = tmp_path / "project"
    template_root.mkdir()
    project_root.mkdir()
    monkeypatch.setattr(cli, "confirm", lambda prompt: True)
    with pytest.raises(SystemExit):
        offer_setup_config_install(template_root, project_root, allow_update=True)
    assert not (project_root / SETUP_CONFIG_REL).exists()


# --- manifest ------------------------------------------------------------------------


@pytest.mark.unit
def test_manifest_has_no_duplicates() -> None:
    paths = [entry.path for entry in MANIFEST]
    assert len(paths) == len(set(paths))


@pytest.mark.unit
def test_carries_version_true_for_scripts_by_path() -> None:
    assert carries_version(BaselineFile("scripts/helper.py")) is True


@pytest.mark.unit
def test_carries_version_true_for_flagged_entries() -> None:
    assert carries_version(BaselineFile("tests/test_guard.py", versioned=True)) is True


@pytest.mark.unit
def test_carries_version_false_for_plain_files() -> None:
    assert carries_version(BaselineFile("tests/test_guard.py")) is False
    assert carries_version(BaselineFile("scripts/notes.md")) is False


@pytest.mark.unit
def test_carries_version_false_for_existence_only_entries() -> None:
    # A file whose contents are never compared must not be offered for
    # overwrite by the version pre-flight either, whatever its path or flag.
    assert carries_version(BaselineFile("scripts/helper.py", compare_content=False)) is False
    assert (
        carries_version(BaselineFile("tests/test_guard.py", versioned=True, compare_content=False))
        is False
    )


@pytest.mark.unit
def test_manifest_tracks_versioned_stub_guard() -> None:
    (guard,) = [e for e in MANIFEST if e.path == "tests/test_mypy_stub_guard.py"]
    assert guard.required is True
    assert guard.strict is True
    assert guard.versioned is True


@pytest.mark.unit
def test_is_excluded_manifest_entry_beats_glob() -> None:
    # The stub-guard test matches the blanket tests/test_*.py glob but is
    # manifested, so it must not be reported as excluded.
    assert is_excluded("tests/test_mypy_stub_guard.py") is False
    # A dev-script test with no manifest entry stays excluded by the glob.
    assert is_excluded("tests/test_cleanup.py") is True


@pytest.mark.unit
def test_manifest_readme_is_required_but_existence_only() -> None:
    (readme,) = [entry for entry in MANIFEST if entry.path == "README.md"]
    assert readme.required is True
    assert readme.compare_content is False


@pytest.mark.unit
def test_manifest_index_md_is_existence_only_and_gated_on_mkdocs() -> None:
    # The docs landing page is rewritten wholesale per project, so its
    # contents are never compared -- only its existence, and only when the
    # project kept mkdocs.
    (entry,) = [e for e in MANIFEST if e.path == "docs/index.md"]
    assert entry.gate == "mkdocs"
    assert entry.compare_content is False


@pytest.mark.unit
def test_manifest_setup_config_is_required_existence_only_and_ungated() -> None:
    (entry,) = [e for e in MANIFEST if e.path == SETUP_CONFIG_REL]
    assert entry.required is True
    assert entry.compare_content is False
    assert entry.gate is None


@pytest.mark.unit
def test_manifest_remote_disposable_pair_is_gated_and_existence_only() -> None:
    # Both halves are deleted together by
    # remove_remote_disposable_scripts.py, and their marker mechanism is
    # filled in per project, so their contents always differ by design: only
    # existence is checked, and they stay out of the version pre-flight.
    paths = ("scripts/mark_remote_disposable.py", "tests/verify_remote_disposable.py")
    entries = [e for e in MANIFEST if e.path in paths]
    assert len(entries) == len(paths)
    for entry in entries:
        assert entry.gate == "remote_disposable_scripts"
        assert entry.compare_content is False
        assert carries_version(entry) is False


@pytest.mark.unit
def test_manifest_community_docs_are_gated_separately() -> None:
    # SECURITY.md and CONTRIBUTING.md are independently removable at setup
    # time, so each is gated on its own flag and compared strictly whenever
    # the project kept it.
    expected = {"SECURITY.md": "security_policy", "CONTRIBUTING.md": "contributing_guide"}
    entries = [e for e in MANIFEST if e.path in expected]
    assert len(entries) == len(expected)
    for entry in entries:
        assert entry.gate == expected[entry.path]
        assert entry.strict is True


@pytest.mark.unit
def test_manifest_config_package_is_gated_and_schema_lenient() -> None:
    # The config package is one config-driven feature; its backends are each
    # behind their own gate so either can be removed alone. schema.py holds
    # the project's own option definitions, so its content is diffed but only
    # for review (lenient, never an error); the generic modules carry a
    # __version__ and join the version pre-flight.
    prefix = f"src/{TEMPLATE_SNAKE}/config/"
    entries = {e.path.removeprefix(prefix): e for e in MANIFEST if e.path.startswith(prefix)}
    assert set(entries) == {
        "__init__.py",
        "__main__.py",
        "cli.py",
        "file.py",
        "paths.py",
        "resolve.py",
        "schema.py",
        "secrets.py",
        "keyring_backend.py",
        "keyvault_backend.py",
    }
    assert entries["keyring_backend.py"].gate == "keyring"
    assert entries["keyvault_backend.py"].gate == "keyvault"
    assert entries["secrets.py"].gate == "secret_storage"
    for name, entry in entries.items():
        if name not in ("keyring_backend.py", "keyvault_backend.py", "secrets.py"):
            assert entry.gate == "config_system"
    assert entries["schema.py"].compare_content is True
    assert entries["schema.py"].strict is False
    for name in ("cli.py", "file.py", "paths.py", "resolve.py", "secrets.py"):
        assert entries[name].versioned is True


@pytest.mark.unit
def test_manifest_config_tests_follow_their_import_gates() -> None:
    # The config test suite imports no concrete backend, so it follows the
    # config-system gate -- except the dispatcher's tests, which go with the
    # secret-storage machinery. Only the per-backend test modules, which
    # import their backend at module scope, follow a backend gate.
    for name in ("cli", "file", "paths", "resolve", "schema"):
        (entry,) = [e for e in MANIFEST if e.path == f"tests/test_config_{name}.py"]
        assert entry.gate == "config_system"
        assert entry.versioned is True
    (secrets_entry,) = [e for e in MANIFEST if e.path == "tests/test_config_secrets.py"]
    assert secrets_entry.gate == "secret_storage"
    assert secrets_entry.versioned is True
    for backend, gate in (("keyring", "keyring"), ("keyvault", "keyvault")):
        (entry,) = [e for e in MANIFEST if e.path == f"tests/test_{backend}_backend.py"]
        assert entry.gate == gate
        assert entry.versioned is True
    (test_object,) = [e for e in MANIFEST if e.path == "tests/_config_test_object.py"]
    assert test_object.gate == "config_system"
    assert test_object.versioned is True


@pytest.mark.unit
def test_manifest_gates_match_feature_flags_fields() -> None:
    # Every gate string must resolve to a real FeatureFlags field (else
    # FeatureFlags.wanted() raises at runtime), and every field should be
    # used by at least one entry, or it's dead code.
    valid_gates = {
        "mkdocs",
        "config_system",
        "secret_storage",
        "keyring",
        "keyvault",
        "remote_disposable_scripts",
        "security_policy",
        "contributing_guide",
    }
    gates = {entry.gate for entry in MANIFEST if entry.gate is not None}
    assert gates == valid_gates


@pytest.mark.integration
@pytest.mark.functional
def test_manifest_covers_all_tracked_template_files() -> None:
    """Every tracked template file must be in the manifest or excluded.

    Runs only in the template repository itself; in a generated project this
    test file is deleted by cleanup.py anyway.
    """
    root = Path(__file__).resolve().parent.parent
    if pyproject_name(root) != TEMPLATE_KEBAB:
        pytest.skip("not running inside the template repository")
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not available")
    result = subprocess.run(  # noqa: S603  (fixed argv list, no shell)
        [git, "-C", str(root), "ls-files"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("not a git checkout")
    tracked = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    manifest_paths = {entry.path for entry in MANIFEST}
    uncovered = [p for p in tracked if p not in manifest_paths and not is_excluded(p)]
    assert uncovered == [], f"add to MANIFEST or EXCLUDED_*: {uncovered}"
    missing = [p for p in sorted(manifest_paths) if not (root / p).is_file()]
    assert missing == [], f"manifest entries not in template: {missing}"


# --- diff output (VS Code) --------------------------------------------------------------


@pytest.mark.unit
def test_diff_files_for_writes_pairs_and_skips_match_and_binary(tmp_path: Path) -> None:
    results = [
        Comparison(
            BaselineFile("a.md"), "a.md", "modified", template_norm="T-A\n", project_norm="P-A\n"
        ),
        Comparison(
            BaselineFile("b.md", strict=False),
            "b.md",
            "review",
            template_norm="T-B\n",
            project_norm="P-B\n",
        ),
        Comparison(
            BaselineFile("blob.bin"), "blob.bin", "modified", note=" (binary)"
        ),  # no norm texts
        Comparison(BaselineFile("c.md"), "c.md", "match"),  # unchanged; nothing to diff
    ]
    base = tmp_path / "out"
    project_root = tmp_path / "project"
    pairs = diff_files_for(results, base, project_root)

    assert len(pairs) == 2
    (left_a, right_a), (_left_b, right_b) = pairs
    # The template side is a temp copy of the normalized text; the project side
    # is the live file path so edits in the diff view land on the real file.
    assert (left_a, right_a) == (base / "a.md", project_root / "a.md")
    assert left_a.read_text(encoding="utf-8") == "T-A\n"
    assert right_b == project_root / "b.md"
    # The binary and matching entries produce no files.
    assert not (base / "blob.bin").exists()
    assert not (base / "c.md").exists()


@pytest.mark.unit
def test_diff_files_for_uses_project_rel_for_the_project_side(tmp_path: Path) -> None:
    rel = f"docs/reference/{TEMPLATE_SNAKE}.md"
    results = [
        Comparison(
            BaselineFile(rel, required=False, strict=False),
            "docs/reference/my_proj.md",
            "review",
            template_norm="t\n",
            project_norm="p\n",
        ),
    ]
    project_root = tmp_path / "project"
    ((left, right),) = diff_files_for(results, tmp_path, project_root)
    assert left == tmp_path / rel
    assert right == project_root / "docs/reference/my_proj.md"


@pytest.mark.unit
def test_resolve_code_splits_an_explicit_tool() -> None:
    assert resolve_code("codium") == ["codium"]
    assert resolve_code("code --new-window") == ["code", "--new-window"]


@pytest.mark.unit
def test_resolve_code_ignores_a_blank_override() -> None:
    # A blank override falls through to auto-detection of the 'code' CLI, which
    # is present or not depending on the environment.
    expected = ["code"] if shutil.which("code") else None
    assert resolve_code("   ") == expected
