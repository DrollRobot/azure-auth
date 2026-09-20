"""Unit tests for the pure helpers in scripts/remove_worktree.py.

The scripts folder is not a package, so the module is imported by adding the
folder to sys.path, mirroring how the scripts import their shared _cli module.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from remove_worktree import (
    copied_config_candidates,
    diverged_copies,
    is_env_name,
    open_worktree_slugs,
    parse_args,
    parse_choice,
    parse_worktrees,
    slug_arg,
)

pytestmark = pytest.mark.unit

MAIN = ("C:/dev/repo", "refs/heads/develop")


def porcelain(*blocks: str) -> str:
    """Join porcelain blocks with the blank line git puts between them."""
    return "\n\n".join(blocks) + "\n"


def test_parse_worktrees_empty_output() -> None:
    """No output (not a repo, or stripped) yields no entries."""
    assert parse_worktrees("") == []


def test_parse_worktrees_main_only() -> None:
    """A single block yields one (path, branch) pair."""
    text = porcelain("worktree C:/dev/repo\nHEAD abc123\nbranch refs/heads/develop")
    assert parse_worktrees(text) == [MAIN]


def test_parse_worktrees_multiple_blocks() -> None:
    """Each block becomes one entry, in listing order (main worktree first)."""
    text = porcelain(
        "worktree C:/dev/repo\nHEAD abc123\nbranch refs/heads/develop",
        "worktree C:/dev/repo-wt/issue-42\nHEAD def456\nbranch refs/heads/wt/issue-42",
    )
    assert parse_worktrees(text) == [
        MAIN,
        ("C:/dev/repo-wt/issue-42", "refs/heads/wt/issue-42"),
    ]


def test_parse_worktrees_detached_head_has_no_branch() -> None:
    """A detached worktree is reported with branch ``None``."""
    text = porcelain(
        "worktree C:/dev/repo\nHEAD abc123\nbranch refs/heads/develop",
        "worktree C:/dev/repo-wt/pinned\nHEAD def456\ndetached",
    )
    assert parse_worktrees(text) == [MAIN, ("C:/dev/repo-wt/pinned", None)]


def test_parse_worktrees_ignores_extra_attribute_lines() -> None:
    """Lines like 'locked' or 'prunable' do not disturb the pairs."""
    text = porcelain(
        "worktree C:/dev/repo\nHEAD abc123\nbranch refs/heads/develop",
        "worktree C:/dev/repo-wt/issue-42\nHEAD def456\n"
        "branch refs/heads/wt/issue-42\nlocked reason",
    )
    assert parse_worktrees(text)[1] == ("C:/dev/repo-wt/issue-42", "refs/heads/wt/issue-42")


def test_open_worktree_slugs_skips_main_worktree() -> None:
    """The main worktree is never offered, even if its branch matched the prefix."""
    worktrees = [("C:/dev/repo", "refs/heads/wt/oops")]
    assert open_worktree_slugs(worktrees, "wt/") == []


def test_open_worktree_slugs_matches_prefix_only() -> None:
    """Only linked worktrees on a prefixed branch are offered; slug drops the prefix."""
    worktrees = [
        MAIN,
        ("C:/dev/repo-wt/issue-42", "refs/heads/wt/issue-42"),
        ("C:/dev/other", "refs/heads/feature/login"),
        ("C:/dev/repo-wt/pinned", None),
    ]
    assert open_worktree_slugs(worktrees, "wt/") == [("issue-42", "C:/dev/repo-wt/issue-42")]


def test_open_worktree_slugs_keeps_slashes_in_slug() -> None:
    """A slug that itself contains slashes survives the prefix strip."""
    worktrees = [MAIN, ("C:/dev/repo-wt/fix-login", "refs/heads/wt/fix/login")]
    assert open_worktree_slugs(worktrees, "wt/") == [("fix/login", "C:/dev/repo-wt/fix-login")]


def test_open_worktree_slugs_honours_custom_prefix() -> None:
    """A different branch prefix changes which branches are offered."""
    worktrees = [MAIN, ("C:/dev/repo-wt/issue-42", "refs/heads/wt/issue-42")]
    assert open_worktree_slugs(worktrees, "agent/") == []


def test_parse_choice_accepts_numbers_in_range() -> None:
    """Numbers from 1 to count are returned as ints."""
    assert parse_choice("1", 3) == 1
    assert parse_choice("3", 3) == 3


def test_parse_choice_rejects_out_of_range() -> None:
    """0, negatives, and numbers past the end are rejected."""
    assert parse_choice("0", 3) is None
    assert parse_choice("4", 3) is None
    assert parse_choice("-1", 3) is None


def test_parse_choice_rejects_non_numbers() -> None:
    """Anything that is not an integer is rejected."""
    assert parse_choice("", 3) is None
    assert parse_choice("x", 3) is None
    assert parse_choice("1.5", 3) is None


# slug_arg is duplicated byte-for-byte in new_worktree.py; these cover both.


def test_slug_arg_accepts_plain_slug() -> None:
    """A simple slug passes through unchanged."""
    assert slug_arg("issue-42") == "issue-42"


def test_slug_arg_accepts_internal_slash() -> None:
    """An internal slash is allowed (becomes a nested branch like wt/fix/login)."""
    assert slug_arg("fix/login") == "fix/login"


def test_slug_arg_rejects_disallowed_characters() -> None:
    """Characters outside the allowed set are rejected."""
    with pytest.raises(argparse.ArgumentTypeError):
        slug_arg("has space")


def test_slug_arg_rejects_dotdot() -> None:
    """A '..' sequence (path traversal) is rejected."""
    with pytest.raises(argparse.ArgumentTypeError):
        slug_arg("a..b")


@pytest.mark.parametrize("bad", ["/login", "login/", "fix//login"])
def test_slug_arg_rejects_edge_slashes(bad: str) -> None:
    """Leading, trailing, or doubled slashes would build malformed branch names."""
    with pytest.raises(argparse.ArgumentTypeError):
        slug_arg(bad)


# --- is_env_name -------------------------------------------------------------


@pytest.mark.parametrize("name", [".env", ".env.local", ".env.production"])
def test_is_env_name_accepts_env_files(name: str) -> None:
    """.env and .env.* names are recognized."""
    assert is_env_name(name) is True


@pytest.mark.parametrize("name", [".env.example", ".env.local.example", ".envrc", "env", "config"])
def test_is_env_name_rejects_others(name: str) -> None:
    """.example templates, .envrc, and non-.env names are rejected."""
    assert is_env_name(name) is False


# --- copied_config_candidates ------------------------------------------------


def _make_repos(tmp_path: Path) -> tuple[Path, Path]:
    """Create empty main-repo and worktree directories under ``tmp_path``."""
    main_repo = tmp_path / "repo"
    wt_path = tmp_path / "repo-wt" / "issue-42"
    main_repo.mkdir()
    wt_path.mkdir(parents=True)
    return main_repo, wt_path


def test_candidates_missing_worktree_is_empty(tmp_path: Path) -> None:
    """A worktree directory that does not exist yields no candidates."""
    assert copied_config_candidates(tmp_path / "gone") == []


def test_candidates_collect_env_and_vscode(tmp_path: Path) -> None:
    """Env files and linked .vscode files are collected; env first, then .vscode."""
    _, wt_path = _make_repos(tmp_path)
    (wt_path / ".env").write_text("A=1\n", encoding="utf-8")
    (wt_path / ".env.prod").write_text("P=1\n", encoding="utf-8")
    (wt_path / ".vscode").mkdir()
    (wt_path / ".vscode" / "settings.json").write_text("{}\n", encoding="utf-8")
    (wt_path / ".vscode" / "launch.json").write_text("{}\n", encoding="utf-8")
    assert copied_config_candidates(wt_path) == [
        ".env",
        ".env.prod",
        ".vscode/launch.json",
        ".vscode/settings.json",
    ]


def test_candidates_ignore_example_and_non_env(tmp_path: Path) -> None:
    """.env.example templates and unrelated files are not candidates."""
    _, wt_path = _make_repos(tmp_path)
    (wt_path / ".env.example").write_text("A=\n", encoding="utf-8")
    (wt_path / "config.txt").write_text("x\n", encoding="utf-8")
    assert copied_config_candidates(wt_path) == []


def test_candidates_skip_unlinked_vscode(tmp_path: Path) -> None:
    """A .vscode file new_worktree never links (e.g. tasks.json) is not a candidate."""
    _, wt_path = _make_repos(tmp_path)
    (wt_path / ".vscode").mkdir()
    (wt_path / ".vscode" / "tasks.json").write_text("{}\n", encoding="utf-8")
    assert copied_config_candidates(wt_path) == []


def test_candidates_skip_symlinks(tmp_path: Path) -> None:
    """A symlinked copy shares the main repo file, so it is not a candidate."""
    main_repo, wt_path = _make_repos(tmp_path)
    src = main_repo / ".env"
    src.write_text("A=1\n", encoding="utf-8")
    try:
        (wt_path / ".env").symlink_to(src)
    except OSError:
        pytest.skip("symlinks not available on this platform/privilege level")
    assert copied_config_candidates(wt_path) == []


# --- diverged_copies ---------------------------------------------------------


def test_diverged_identical_copy_is_clean(tmp_path: Path) -> None:
    """A copy matching the main repo is not flagged."""
    main_repo, wt_path = _make_repos(tmp_path)
    (main_repo / ".env").write_text("A=1\n", encoding="utf-8")
    (wt_path / ".env").write_text("A=1\n", encoding="utf-8")
    assert diverged_copies(main_repo, wt_path, [".env"]) == []


def test_diverged_modified_copy_is_flagged(tmp_path: Path) -> None:
    """A copy edited in the worktree is reported as differing."""
    main_repo, wt_path = _make_repos(tmp_path)
    (main_repo / ".env").write_text("A=1\n", encoding="utf-8")
    (wt_path / ".env").write_text("A=2\n", encoding="utf-8")
    assert diverged_copies(main_repo, wt_path, [".env"]) == [(".env", "differs from main repo")]


def test_diverged_absent_in_main_is_flagged(tmp_path: Path) -> None:
    """A worktree-only copy (none in the main repo) is reported as absent."""
    main_repo, wt_path = _make_repos(tmp_path)
    (wt_path / ".env.local").write_text("SECRET=x\n", encoding="utf-8")
    assert diverged_copies(main_repo, wt_path, [".env.local"]) == [
        (".env.local", "absent from main repo")
    ]


def test_diverged_vscode_subpath_is_compared(tmp_path: Path) -> None:
    """A .vscode/ subpath is compared against the matching main-repo file."""
    main_repo, wt_path = _make_repos(tmp_path)
    (main_repo / ".vscode").mkdir()
    (main_repo / ".vscode" / "settings.json").write_text("{}\n", encoding="utf-8")
    (wt_path / ".vscode").mkdir()
    (wt_path / ".vscode" / "settings.json").write_text('{"changed": true}\n', encoding="utf-8")
    assert diverged_copies(main_repo, wt_path, [".vscode/settings.json"]) == [
        (".vscode/settings.json", "differs from main repo")
    ]


def test_diverged_preserves_input_order(tmp_path: Path) -> None:
    """Divergent copies are reported in the order of the input paths."""
    main_repo, wt_path = _make_repos(tmp_path)
    (main_repo / ".env").write_text("A=1\n", encoding="utf-8")
    (wt_path / ".env").write_text("A=2\n", encoding="utf-8")
    (wt_path / ".env.prod").write_text("P=1\n", encoding="utf-8")
    assert diverged_copies(main_repo, wt_path, [".env", ".env.prod"]) == [
        (".env", "differs from main repo"),
        (".env.prod", "absent from main repo"),
    ]


# --- parse_args ----------------------------------------------------------------------


def test_parse_args_defaults_to_remote_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without --no-remote the teardown pulls and prunes against origin."""
    monkeypatch.setattr(sys, "argv", ["remove_worktree.py", "issue-42"])
    args = parse_args()
    assert args.slug == "issue-42"
    assert args.no_remote is False


def test_parse_args_accepts_no_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    """--no-remote is accepted alongside a slug."""
    monkeypatch.setattr(sys, "argv", ["remove_worktree.py", "issue-42", "--no-remote"])
    assert parse_args().no_remote is True


def test_parse_args_still_requires_a_slug_with_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    """-y without a slug is an error; --no-remote does not change that."""
    monkeypatch.setattr(sys, "argv", ["remove_worktree.py", "-y", "--no-remote"])
    with pytest.raises(SystemExit):
        parse_args()
