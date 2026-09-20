"""Unit tests for the pure helpers in scripts/template_setup/remove_mkdocs.py.

The template_setup folder is not a package, so the module is imported by
adding the folder to sys.path, mirroring how the setup scripts import their
shared _common module.

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/remove_mkdocs.py and deletes it along with the rest of
the scaffolding, so it never lingers in a project started from the template.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

import remove_mkdocs

PYPROJECT = (
    "[dependency-groups]\n"
    "docs = [\n"
    '    "mkdocs>=1.6,<2",\n'
    '    "mkdocs-material>=9.7,<10",\n'
    '    "mkdocstrings[python]>=1.0,<2",\n'
    "]\n"
    "test = [\n"
    '    "pytest>=9.0,<10",\n'
    "]\n"
    "dev = [\n"
    '    {include-group = "docs"},\n'
    '    {include-group = "test"},\n'
    '    "ruff>=0.15,<1",\n'
    "]\n"
)

GITIGNORE = "/coverage\n\n# mkdocs documentation\n/site\n\n# mypy\n.mypy_cache/\n"

README_PAGES = (
    "uv run pre-commit autoupdate\n"
    "```\n"
    "\n"
    "**If using mkdocs, enable GitHub Pages for docs**\n"
    "\n"
    "- In the GitHub repo settings, set Pages source to the `gh-pages` branch.\n"
    "- Then deploy:\n"
    "```bash\n"
    "uv run mkdocs gh-deploy --force\n"
    "```\n"
    "\n"
    "The GitHub Actions workflow in `.github/workflows/docs.yml` keeps it updated.\n"
    "\n"
    "---\n"
    "\n"
    "**Initialize the secrets baseline**\n"
)

README_FULL = (
    "- **ruff** for linting and formatting.\n"
    "- **mkdocs** for documentation. Integrates easily with GitHub Pages.\n"
    "- **pytest** for testing.\n"
    "\n" + README_PAGES + "\n"
    "| Feature | Delete | Remove from config |\n"
    "| --- | --- | --- |\n"
    "| **MkDocs docs** | `docs/`, `mkdocs.yml` | the `docs` group |\n"
    "| **Release script** | `push_new_tag_to_main.py` | -- |\n"
)

CONTRIBUTING = (
    "uv run pytest -m integration\n"
    "\n"
    "# Docs (live preview at http://127.0.0.1:8000)\n"
    "uv run mkdocs serve\n"
    "\n"
    "# or build static HTML once\n"
    "uv run mkdocs build --strict\n"
    "\n"
    "# deploy to GitHub Pages\n"
    "uv run mkdocs gh-deploy --force\n"
    "```\n"
    "\n"
    "### Code structure\n"
    "\n"
    "- `src/pkg/` -- library source\n"
    "- `tests/` -- pytest test suite\n"
    "- `docs/` -- MkDocs documentation source\n"
)

AGENTS_RELEASING = (
    "## Update precommit\n"
    "```\n"
    "uv run pre-commit autoupdate\n"
    "```\n"
    "\n"
    "## Update docs\n"
    "```\n"
    "uv run mkdocs build --strict          # build docs, fail on warnings\n"
    "```\n"
    "- Review all .md files in the root of the docs folder.\n"
    "- Don't review or modify files in docs/reference. (built by mkdocs)\n"
    "\n"
    "## Review/Update README.md\n"
)


@pytest.mark.unit
def test_strip_pyproject_removes_group_and_include() -> None:
    """The docs group and its dev include are removed; siblings stay."""
    new_text, removed = remove_mkdocs._strip_pyproject(PYPROJECT)
    assert "mkdocs" not in new_text
    assert "docs = [" not in new_text
    assert '{include-group = "docs"}' not in new_text
    # The other groups and includes are intact.
    assert "test = [" in new_text
    assert '{include-group = "test"},' in new_text
    assert '"ruff>=0.15,<1",' in new_text
    # [dependency-groups] sits directly above the next group, no stray blank.
    assert "[dependency-groups]\ntest = [" in new_text
    assert removed


@pytest.mark.unit
def test_strip_gitignore_removes_site_block() -> None:
    """The mkdocs ignore block and its preceding blank are removed."""
    new_text, _removed = remove_mkdocs._strip_gitignore(GITIGNORE)
    assert "mkdocs" not in new_text
    assert "/site" not in new_text
    assert "/coverage\n\n# mypy\n" in new_text


@pytest.mark.unit
def test_strip_readme_removes_bullet_pages_and_table_row() -> None:
    """The tool bullet, Pages step, and table row are all removed."""
    new_text, _removed = remove_mkdocs._strip_readme(README_FULL)
    assert "mkdocs" not in new_text.lower()
    assert "MkDocs" not in new_text
    # Surrounding content is preserved.
    assert "- **ruff** for linting and formatting." in new_text
    assert "- **pytest** for testing." in new_text
    assert "**Initialize the secrets baseline**" in new_text
    assert "| **Release script**" in new_text


@pytest.mark.unit
def test_strip_readme_pages_leaves_single_blank_before_rule() -> None:
    """Removing the Pages step leaves one blank line before the '---' rule."""
    new_text, _removed = remove_mkdocs._strip_readme(README_PAGES)
    assert "mkdocs" not in new_text
    assert "uv run pre-commit autoupdate\n```\n\n---\n" in new_text


@pytest.mark.unit
def test_strip_contributing_removes_commands_and_structure_bullet() -> None:
    """The docs commands and the docs/ structure bullet are removed."""
    new_text, _removed = remove_mkdocs._strip_contributing(CONTRIBUTING)
    assert "mkdocs" not in new_text.lower()
    assert "MkDocs" not in new_text
    # The integration test command and the closing code fence are kept.
    assert "uv run pytest -m integration\n```\n" in new_text
    assert "- `tests/` -- pytest test suite" in new_text


@pytest.mark.unit
def test_strip_agents_releasing_removes_update_docs_section() -> None:
    """The 'Update docs' section is removed; neighbours stay."""
    new_text, _removed = remove_mkdocs._strip_agents_releasing(AGENTS_RELEASING)
    assert "mkdocs" not in new_text
    assert "## Update docs" not in new_text
    assert "## Update precommit" in new_text
    assert "## Review/Update README.md" in new_text
    # One blank line separates the kept sections.
    assert "```\n\n## Review/Update README.md\n" in new_text


@pytest.mark.unit
def test_plan_deletions_lists_only_existing_paths(tmp_path: Path) -> None:
    """Only mkdocs paths that exist on disk are scheduled for deletion."""
    assert remove_mkdocs.plan_deletions(tmp_path) == []
    (tmp_path / "mkdocs.yml").write_text("site_name: x\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    deletions = remove_mkdocs.plan_deletions(tmp_path)
    names = {path.name for path in deletions}
    assert names == {"mkdocs.yml", "docs"}


@pytest.mark.integration
@pytest.mark.functional
def test_run_returns_zero_when_nothing_matches(tmp_path: Path) -> None:
    """An empty project has no mkdocs artifacts and is a no-op success."""
    assert remove_mkdocs.run(tmp_path, assume_yes=True) == 0


@pytest.mark.integration
@pytest.mark.functional
def test_run_dry_run_changes_nothing(tmp_path: Path) -> None:
    """A dry run neither deletes files nor rewrites them."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(PYPROJECT, encoding="utf-8")
    mkdocs_yml = tmp_path / "mkdocs.yml"
    mkdocs_yml.write_text("site_name: x\n", encoding="utf-8")

    assert remove_mkdocs.run(tmp_path, assume_yes=True, dry_run=True) == 0
    assert mkdocs_yml.exists()
    assert pyproject.read_text(encoding="utf-8") == PYPROJECT


@pytest.mark.integration
@pytest.mark.functional
def test_run_deletes_and_rewrites(tmp_path: Path) -> None:
    """A real run deletes the artifacts and strips the references."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(PYPROJECT, encoding="utf-8")
    mkdocs_yml = tmp_path / "mkdocs.yml"
    mkdocs_yml.write_text("site_name: x\n", encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "index.md").write_text("# Home\n", encoding="utf-8")

    assert remove_mkdocs.run(tmp_path, assume_yes=True) == 0
    assert not mkdocs_yml.exists()
    assert not docs.exists()
    assert "mkdocs" not in pyproject.read_text(encoding="utf-8")
