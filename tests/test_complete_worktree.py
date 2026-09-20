"""Unit tests for the pure helpers in scripts/complete_worktree.py.

The scripts folder is not a package, so the module is imported by adding the
folder to sys.path, mirroring how the scripts import their shared _cli module.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import _cli
from complete_worktree import (
    dirty_status_lines,
    main_worktree_path,
    notes_ref,
    parse_args,
    parse_front_matter,
    render_note,
)

pytestmark = pytest.mark.unit


def test_clean_tree_returns_no_lines() -> None:
    """An empty status means a clean tree regardless of the exempt path."""
    assert dirty_status_lines([], "PR.md") == []
    assert dirty_status_lines([], None) == []


def test_blank_lines_are_ignored() -> None:
    """Blank or whitespace-only lines do not count as dirty entries."""
    assert dirty_status_lines(["", "   "], None) == []


def test_untracked_exempt_file_is_filtered() -> None:
    """An untracked PR body file does not make the tree dirty."""
    assert dirty_status_lines(["?? PR.md"], "PR.md") == []


def test_modified_exempt_file_is_filtered() -> None:
    """A tracked-but-modified PR body file does not make the tree dirty."""
    assert dirty_status_lines([" M PR.md"], "PR.md") == []


def test_other_changes_are_reported() -> None:
    """Changes to any non-exempt file are returned verbatim."""
    lines = [" M src/app.py", "?? PR.md", "?? notes.txt"]
    assert dirty_status_lines(lines, "PR.md") == [" M src/app.py", "?? notes.txt"]


def test_no_exempt_path_keeps_everything() -> None:
    """With no exempt path (body file outside the worktree), nothing is filtered."""
    assert dirty_status_lines(["?? PR.md"], None) == ["?? PR.md"]


def test_exempt_path_is_compared_as_posix_relative_path() -> None:
    """The exempt path must match git's repo-relative POSIX path exactly."""
    assert dirty_status_lines(["?? docs/PR.md"], "PR.md") == ["?? docs/PR.md"]
    assert dirty_status_lines(["?? docs/PR.md"], "docs/PR.md") == []


def test_quoted_porcelain_path_matches_exempt() -> None:
    """Git quotes unusual paths; the quotes are stripped before comparison."""
    assert dirty_status_lines(['?? "PR.md"'], "PR.md") == []


def test_parse_front_matter_pr_body_title_only() -> None:
    """A PR.md with a title-only fence yields the title and the trailing body."""
    content = "---\ntitle: feat(auth): add SSO\n---\nBody line 1\nBody line 2"
    assert parse_front_matter(content) == (None, "feat(auth): add SSO", "Body line 1\nBody line 2")


def test_parse_front_matter_note_base_and_title() -> None:
    """A note fence carries both base and title; the body excludes the fences."""
    note = "---\nbase: develop\ntitle: feat: add SSO\n---\nBody line 1\nBody line 2"
    assert parse_front_matter(note) == ("develop", "feat: add SSO", "Body line 1\nBody line 2")


def test_parse_front_matter_no_leading_fence_is_all_body() -> None:
    """Content that does not open with a '---' fence has no front-matter."""
    content = "just a plain body\nwith two lines"
    assert parse_front_matter(content) == (None, None, content)


def test_parse_front_matter_thematic_break_in_body_is_not_front_matter() -> None:
    """A body '---' rule is not mistaken for front-matter without a leading fence."""
    content = "Adds SSO support.\n\n---\n\nSee #42"
    assert parse_front_matter(content) == (None, None, content)


def test_parse_front_matter_unterminated_fence_is_all_body() -> None:
    """A leading fence with no closing fence is treated as having no front-matter."""
    content = "---\ntitle: x\nnever closed"
    assert parse_front_matter(content) == (None, None, content)


def test_parse_front_matter_missing_title_defaults_to_none() -> None:
    """Front-matter present but without a title returns title None."""
    assert parse_front_matter("---\nbase: develop\n---\nbody") == ("develop", None, "body")


def test_parse_front_matter_empty_body_after_fence() -> None:
    """A closing fence with nothing after it yields an empty body, not an error."""
    assert parse_front_matter("---\ntitle: x\n---") == (None, "x", "")


def test_parse_front_matter_strips_field_whitespace() -> None:
    """Extra spaces after the field colon are trimmed."""
    assert parse_front_matter("---\nbase:   develop  \n---\nbody") == ("develop", None, "body")


def test_parse_front_matter_trims_leading_blank_body_lines() -> None:
    """A blank line between the closing fence and the body is trimmed off."""
    assert parse_front_matter("---\ntitle: x\n---\n\nBody") == (None, "x", "Body")


def test_render_note_round_trips_through_parse() -> None:
    """render_note output parses back to the same base, title, and body."""
    note = render_note("develop", "feat: add SSO", "Body line 1\nBody line 2")
    assert note.startswith("---\n")
    assert parse_front_matter(note) == ("develop", "feat: add SSO", "Body line 1\nBody line 2")


def test_notes_ref_uses_per_slug_suffix() -> None:
    """The note ref is namespaced per slug so concurrent PRs never collide."""
    assert notes_ref("issue-42") == "pr-body-issue-42"


def test_notes_ref_flattens_slashes() -> None:
    """A slug with slashes stays a single ref path segment."""
    assert notes_ref("fix/login") == "pr-body-fix-login"


# --- parse_args ----------------------------------------------------------------------


def test_parse_args_defaults_to_remote_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without --no-remote the script pushes and opens a PR."""
    monkeypatch.setattr(sys, "argv", ["complete_worktree.py"])
    assert parse_args().no_remote is False


def test_parse_args_accepts_no_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    """--no-remote switches the flow to a local merge."""
    monkeypatch.setattr(sys, "argv", ["complete_worktree.py", "--no-remote"])
    assert parse_args().no_remote is True


# --- main_worktree_path --------------------------------------------------------------


def test_main_worktree_path_returns_first_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """git lists the main worktree first, so its path is the one to merge in."""
    porcelain = (
        "worktree C:/dev/repo\nHEAD abc\nbranch refs/heads/develop\n\n"
        "worktree C:/dev/repo-wt/issue-42\nHEAD def\nbranch refs/heads/wt/issue-42\n"
    )
    # complete_worktree does `import _cli as cli`, so this is the same object.
    monkeypatch.setattr(_cli, "capture", lambda *a, **k: porcelain)
    assert main_worktree_path() == "C:/dev/repo"
