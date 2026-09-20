"""Unit tests for scripts/template_setup/remove_private_repo_deps.py.

The template_setup folder is not a package, so the module is imported by
adding the folder to sys.path, mirroring how the setup scripts import their
shared _common module.

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/remove_private_repo_deps.py and deletes it along with
the rest of the scaffolding, so it never lingers in a project started from
the template.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

import remove_private_repo_deps

WORKFLOW_WITH_BLOCK = (
    "      - name: Install uv\n"
    "        uses: astral-sh/setup-uv@v7\n"
    "        with:\n"
    "          enable-cache: true\n"
    '          version: "0.11.x"\n'
    "\n"
    "      # <private-repo-deps>\n"
    "      # FIXME uncomment if using Github app tokens to access private repos\n"
    "      # - name: Mint a token for private git deps\n"
    "      #   id: app-token\n"
    "      # </private-repo-deps>\n"
    "\n"
    "      - name: Sync dependencies\n"
    "        run: uv sync --locked --all-groups\n"
)

WORKFLOW_STRIPPED = (
    "      - name: Install uv\n"
    "        uses: astral-sh/setup-uv@v7\n"
    "        with:\n"
    "          enable-cache: true\n"
    '          version: "0.11.x"\n'
    "\n"
    "      - name: Sync dependencies\n"
    "        run: uv sync --locked --all-groups\n"
)

WORKFLOW_WITHOUT_BLOCK = (
    "      - name: Install uv\n"
    "        uses: astral-sh/setup-uv@v7\n"
    "\n"
    "      - name: Sync dependencies\n"
    "        run: uv sync --locked --all-groups\n"
)


@pytest.mark.unit
def test_strip_workflow_removes_block_and_leading_blank() -> None:
    """The marked block and its preceding blank line are removed; a single blank remains."""
    new_text, removed = remove_private_repo_deps._strip_workflow(WORKFLOW_WITH_BLOCK)
    assert new_text == WORKFLOW_STRIPPED
    assert removed


@pytest.mark.unit
def test_strip_workflow_without_block_is_unchanged() -> None:
    """A workflow that never had the block is left untouched."""
    new_text, removed = remove_private_repo_deps._strip_workflow(WORKFLOW_WITHOUT_BLOCK)
    assert new_text == WORKFLOW_WITHOUT_BLOCK
    assert removed == []


@pytest.mark.unit
def test_plan_edits_covers_only_existing_workflows_with_the_block(tmp_path: Path) -> None:
    """Only workflow files that exist and still carry the block are planned."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(WORKFLOW_WITH_BLOCK, encoding="utf-8")
    (workflows / "audit.yml").write_text(WORKFLOW_WITHOUT_BLOCK, encoding="utf-8")
    # docs.yml deliberately absent.

    edits = remove_private_repo_deps.plan_edits(tmp_path)
    assert [path.name for path, _new, _removed in edits] == ["ci.yml"]


@pytest.mark.integration
@pytest.mark.functional
def test_run_returns_zero_when_nothing_matches(tmp_path: Path) -> None:
    """A project with no workflow files is a no-op success."""
    assert remove_private_repo_deps.run(tmp_path, assume_yes=True) == 0


@pytest.mark.integration
@pytest.mark.functional
def test_run_dry_run_changes_nothing(tmp_path: Path) -> None:
    """A dry run neither writes nor strips anything."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    ci_path = workflows / "ci.yml"
    ci_path.write_text(WORKFLOW_WITH_BLOCK, encoding="utf-8")

    assert remove_private_repo_deps.run(tmp_path, assume_yes=True, dry_run=True) == 0
    assert ci_path.read_text(encoding="utf-8") == WORKFLOW_WITH_BLOCK


@pytest.mark.integration
@pytest.mark.functional
def test_run_strips_the_block_from_every_workflow_that_has_it(tmp_path: Path) -> None:
    """A real run rewrites every workflow file that still carries the block."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    ci_path = workflows / "ci.yml"
    audit_path = workflows / "audit.yml"
    ci_path.write_text(WORKFLOW_WITH_BLOCK, encoding="utf-8")
    audit_path.write_text(WORKFLOW_WITH_BLOCK, encoding="utf-8")

    assert remove_private_repo_deps.run(tmp_path, assume_yes=True) == 0
    assert ci_path.read_text(encoding="utf-8") == WORKFLOW_STRIPPED
    assert audit_path.read_text(encoding="utf-8") == WORKFLOW_STRIPPED
