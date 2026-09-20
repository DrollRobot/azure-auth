"""Unit tests for the config-driven orchestrator in scripts/template_setup/setup_new_project.py.

The template_setup folder is not a package, so the module is imported by
adding the folder to sys.path, mirroring how the setup scripts import their
shared _common module.

This file is itself a dev-script test: cleanup.py matches it to
scripts/template_setup/setup_new_project.py and deletes it along with the
rest of the scaffolding, so it never lingers in a project started from the
template.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "template_setup"))

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
import setup_new_project
import strip_template_headers

VALID_TOML = """
[project]
name = "my-project"
github_user = "someone"
python_version = "3.14"
version = "0.1.0"

[license]
key = "mit"
year = "2026"
name = "Ada Lovelace"
company = ""

[features]
mkdocs = true
config_system = true
secret_storage = true
keyring = true
keyvault = true
private_repo_deps = true
remote_disposable_scripts = true
security_policy = true
contributing_guide = true

[git]
reinit = false
branch = "main"
"""


def _valid_raw() -> dict[str, Any]:
    """Return a fresh, valid parsed-TOML dict matching VALID_TOML."""
    return {
        "project": {
            "name": "my-project",
            "github_user": "someone",
            "python_version": "3.14",
            "version": "0.1.0",
        },
        "license": {"key": "mit", "year": "2026", "name": "Ada Lovelace", "company": ""},
        "features": {
            "mkdocs": True,
            "config_system": True,
            "secret_storage": True,
            "keyring": True,
            "keyvault": True,
            "private_repo_deps": True,
            "remote_disposable_scripts": True,
            "security_policy": True,
            "contributing_guide": True,
        },
        "git": {"reinit": False, "branch": "main"},
    }


def _make_config(**overrides: Any) -> setup_new_project.Config:
    """Build a valid Config, overriding individual fields for a specific test."""
    fields: dict[str, Any] = {
        "name": "my-project",
        "github_user": "someone",
        "python_version": "3.14",
        "version": "0.1.0",
        "license_key": "mit",
        "license_year": "2026",
        "license_name": "Ada Lovelace",
        "license_company": "",
        "mkdocs": True,
        "config_system": True,
        "secret_storage": True,
        "keyring": True,
        "keyvault": True,
        "private_repo_deps": True,
        "remote_disposable_scripts": True,
        "security_policy": True,
        "contributing_guide": True,
        "reinit": False,
        "branch": "main",
    }
    fields.update(overrides)
    return setup_new_project.Config(**fields)


def _recording_run(calls: list[dict[str, Any]], exit_code: int = 0) -> Any:
    """Return a stand-in for a sub-script run() that records its arguments."""

    def run(*args: Any, **kwargs: Any) -> int:
        calls.append({"args": args, "kwargs": kwargs})
        return exit_code

    return run


# ---------------------------------------------------------------------------
# _load_toml
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_load_toml_missing_file_returns_error(tmp_path: Path) -> None:
    """A missing config file is reported, not raised."""
    raw, error = setup_new_project._load_toml(tmp_path / "missing.toml")
    assert raw == {}
    assert error is not None
    assert "not found" in error


@pytest.mark.unit
def test_load_toml_valid_file_returns_parsed_dict(tmp_path: Path) -> None:
    """A well-formed file parses with no error."""
    path = tmp_path / "template_setup.toml"
    path.write_text(VALID_TOML, encoding="utf-8")
    raw, error = setup_new_project._load_toml(path)
    assert error is None
    assert raw["project"]["name"] == "my-project"


@pytest.mark.unit
def test_load_toml_malformed_file_returns_error(tmp_path: Path) -> None:
    """Invalid TOML syntax is reported, not raised."""
    path = tmp_path / "template_setup.toml"
    path.write_text("this is not [ valid toml", encoding="utf-8")
    raw, error = setup_new_project._load_toml(path)
    assert raw == {}
    assert error is not None
    assert "not valid TOML" in error


# ---------------------------------------------------------------------------
# validate_config
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_validate_config_all_valid_returns_config_and_no_problems(tmp_path: Path) -> None:
    """A fully valid config produces a Config and an empty problem list."""
    config, problems = setup_new_project.validate_config(tmp_path, _valid_raw())
    assert problems == []
    assert config is not None
    assert config.name == "my-project"
    assert config.license_key == "mit"


@pytest.mark.unit
def test_validate_config_missing_table_reports_problem(tmp_path: Path) -> None:
    """A missing top-level table is reported and no Config is built."""
    raw = _valid_raw()
    del raw["project"]
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("[project]" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_missing_key_reports_problem(tmp_path: Path) -> None:
    """A missing key within a present table is reported."""
    raw = _valid_raw()
    del raw["project"]["name"]
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("[project].name" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_invalid_name_reports_problem(tmp_path: Path) -> None:
    """A name that can't derive valid package identifiers is reported."""
    raw = _valid_raw()
    raw["project"]["name"] = "???"
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("[project].name" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_invalid_python_version_reports_problem(tmp_path: Path) -> None:
    """An invalid Python version string is reported."""
    raw = _valid_raw()
    raw["project"]["python_version"] = "not-a-version"
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("[project].python_version" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_invalid_version_reports_problem(tmp_path: Path) -> None:
    """An invalid project version string is reported."""
    raw = _valid_raw()
    raw["project"]["version"] = "not-a-version"
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("[project].version" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_invalid_license_key_reports_problem(tmp_path: Path) -> None:
    """A license key outside the four candidates is reported."""
    raw = _valid_raw()
    raw["license"]["key"] = "wtfpl"
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("[license].key" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_license_gnu_skips_holder_requirement(tmp_path: Path) -> None:
    """The GNU license needs no year/name/company."""
    raw = _valid_raw()
    raw["license"] = {"key": "gnu", "year": "", "name": "", "company": ""}
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert problems == []
    assert config is not None
    assert config.license_key == "gnu"


@pytest.mark.unit
def test_validate_config_license_mit_requires_year_and_name(tmp_path: Path) -> None:
    """MIT requires both a copyright year and holder name."""
    raw = _valid_raw()
    raw["license"] = {"key": "mit", "year": "", "name": "", "company": ""}
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("year" in problem for problem in problems)
    assert any("name" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_proprietary_requires_company(tmp_path: Path) -> None:
    """Proprietary additionally requires a company name."""
    raw = _valid_raw()
    raw["license"] = {"key": "proprietary", "year": "2026", "name": "Ada", "company": ""}
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("company" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_empty_branch_reports_problem(tmp_path: Path) -> None:
    """A blank branch name is reported."""
    raw = _valid_raw()
    raw["git"]["branch"] = "   "
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("[git].branch" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_non_bool_feature_flag_reports_problem(tmp_path: Path) -> None:
    """A string where a boolean is expected is reported, not silently truthy."""
    raw = _valid_raw()
    raw["features"]["mkdocs"] = "true"
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("[features].mkdocs" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_backend_without_config_system_reports_problem(tmp_path: Path) -> None:
    """Keeping a backend while removing the whole config package is contradictory."""
    raw = _valid_raw()
    raw["features"]["config_system"] = False
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("[features].secret_storage=true" in problem for problem in problems)
    assert any("[features].keyring=true" in problem for problem in problems)
    assert any("[features].keyvault=true" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_backend_without_secret_storage_reports_problem(tmp_path: Path) -> None:
    """Keeping a backend while removing the secret machinery is contradictory."""
    raw = _valid_raw()
    raw["features"]["secret_storage"] = False
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("[features].keyring=true" in problem for problem in problems)
    assert any("[features].keyvault=true" in problem for problem in problems)


@pytest.mark.unit
def test_validate_config_declining_config_system_with_backends_false_passes(
    tmp_path: Path,
) -> None:
    """config_system=false is valid once the nested feature flags are false too."""
    raw = _valid_raw()
    raw["features"]["config_system"] = False
    raw["features"]["secret_storage"] = False
    raw["features"]["keyring"] = False
    raw["features"]["keyvault"] = False
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert problems == []
    assert config is not None
    assert config.config_system is False


@pytest.mark.unit
def test_validate_config_declining_secret_storage_with_backends_false_passes(
    tmp_path: Path,
) -> None:
    """secret_storage=false is valid once both backend flags are false too."""
    raw = _valid_raw()
    raw["features"]["secret_storage"] = False
    raw["features"]["keyring"] = False
    raw["features"]["keyvault"] = False
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert problems == []
    assert config is not None
    assert config.secret_storage is False


@pytest.mark.unit
def test_validate_config_reinit_true_pristine_clone_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """reinit=true is accepted when the pristine-clone guard passes."""
    monkeypatch.setattr(reinit_git, "_is_pristine_template_clone", lambda root: True)
    raw = _valid_raw()
    raw["git"]["reinit"] = True
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert problems == []
    assert config is not None
    assert config.reinit is True


@pytest.mark.unit
def test_validate_config_reinit_true_not_pristine_reports_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """reinit=true is rejected -- with zero changes made -- when the guard fails."""
    monkeypatch.setattr(reinit_git, "_is_pristine_template_clone", lambda root: False)
    raw = _valid_raw()
    raw["git"]["reinit"] = True
    config, problems = setup_new_project.validate_config(tmp_path, raw)
    assert config is None
    assert any("pristine template clone" in problem for problem in problems)


# ---------------------------------------------------------------------------
# build_steps
# ---------------------------------------------------------------------------

_ALWAYS_ON_KEYS = [
    "strip_template_headers",
    "reset_readme",
    "rename_project",
    "set_github_user",
    "set_python_version",
    "set_version",
    "reset_changelog",
    "choose_license",
]


@pytest.mark.unit
def test_build_steps_canonical_order_all_kept() -> None:
    """With every feature kept and reinit off, only the always-on steps run."""
    steps = setup_new_project.build_steps(_make_config())
    assert [step.key for step in steps] == _ALWAYS_ON_KEYS


@pytest.mark.unit
def test_build_steps_includes_remove_mkdocs_when_declined() -> None:
    """mkdocs=false adds the remove_mkdocs step at the end."""
    steps = setup_new_project.build_steps(_make_config(mkdocs=False))
    assert steps[-1].key == "remove_mkdocs"


@pytest.mark.unit
def test_build_steps_includes_remove_keyring_when_declined() -> None:
    """keyring=false adds the remove_keyring step."""
    steps = setup_new_project.build_steps(_make_config(keyring=False))
    assert steps[-1].key == "remove_keyring"


@pytest.mark.unit
def test_build_steps_includes_remove_keyvault_when_declined() -> None:
    """keyvault=false adds the remove_keyvault step."""
    steps = setup_new_project.build_steps(_make_config(keyvault=False))
    assert steps[-1].key == "remove_keyvault"


@pytest.mark.unit
def test_build_steps_orders_both_backend_removals() -> None:
    """Both backends declined: keyring is removed before keyvault."""
    steps = setup_new_project.build_steps(_make_config(keyring=False, keyvault=False))
    assert [step.key for step in steps[-2:]] == ["remove_keyring", "remove_keyvault"]


@pytest.mark.unit
def test_build_steps_secret_storage_declined_replaces_backend_steps() -> None:
    """secret_storage=false adds only remove_secret_storage -- the machinery
    removal already covers both backends."""
    steps = setup_new_project.build_steps(
        _make_config(secret_storage=False, keyring=False, keyvault=False)
    )
    keys = [step.key for step in steps]
    assert steps[-1].key == "remove_secret_storage"
    assert "remove_keyring" not in keys
    assert "remove_keyvault" not in keys


@pytest.mark.unit
def test_build_steps_config_system_declined_replaces_backend_steps() -> None:
    """config_system=false adds only remove_config_system -- the package
    removal already covers the secret machinery and both backends."""
    steps = setup_new_project.build_steps(
        _make_config(config_system=False, secret_storage=False, keyring=False, keyvault=False)
    )
    keys = [step.key for step in steps]
    assert steps[-1].key == "remove_config_system"
    assert "remove_secret_storage" not in keys
    assert "remove_keyring" not in keys
    assert "remove_keyvault" not in keys


@pytest.mark.unit
def test_build_steps_includes_remove_private_repo_deps_when_declined() -> None:
    """private_repo_deps=false adds the remove_private_repo_deps step."""
    steps = setup_new_project.build_steps(_make_config(private_repo_deps=False))
    assert steps[-1].key == "remove_private_repo_deps"


@pytest.mark.unit
def test_build_steps_includes_remove_remote_disposable_scripts_when_declined() -> None:
    """remote_disposable_scripts=false adds the remove_remote_disposable_scripts step."""
    steps = setup_new_project.build_steps(_make_config(remote_disposable_scripts=False))
    assert steps[-1].key == "remove_remote_disposable_scripts"


@pytest.mark.unit
def test_build_steps_includes_remove_security_policy_when_declined() -> None:
    """security_policy=false adds the remove_security_policy step."""
    steps = setup_new_project.build_steps(_make_config(security_policy=False))
    assert steps[-1].key == "remove_security_policy"


@pytest.mark.unit
def test_build_steps_includes_remove_contributing_guide_when_declined() -> None:
    """contributing_guide=false adds the remove_contributing_guide step."""
    steps = setup_new_project.build_steps(_make_config(contributing_guide=False))
    assert steps[-1].key == "remove_contributing_guide"


@pytest.mark.unit
def test_build_steps_orders_both_community_doc_removals() -> None:
    """Both community docs declined: SECURITY.md is removed before CONTRIBUTING.md."""
    steps = setup_new_project.build_steps(
        _make_config(security_policy=False, contributing_guide=False)
    )
    assert [step.key for step in steps[-2:]] == [
        "remove_security_policy",
        "remove_contributing_guide",
    ]


@pytest.mark.unit
def test_build_steps_includes_reinit_when_requested() -> None:
    """reinit=true adds the destructive reinit_git step last."""
    steps = setup_new_project.build_steps(_make_config(reinit=True))
    assert steps[-1].key == "reinit_git"
    assert steps[-1].destructive is True


@pytest.mark.unit
def test_build_steps_find_fixmes_never_included() -> None:
    """find_fixmes is never part of the built step list -- it runs separately."""
    steps = setup_new_project.build_steps(_make_config(mkdocs=False, reinit=True))
    assert "find_fixmes" not in [step.key for step in steps]


# ---------------------------------------------------------------------------
# Step binders forward assume_yes=True and the right arguments
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_step_rename_forwards_name_and_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(rename_project, "run", _recording_run(calls))
    step = setup_new_project.build_steps(_make_config(name="other-name"))[
        _ALWAYS_ON_KEYS.index("rename_project")
    ]
    assert step.key == "rename_project"
    step.call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path, "other-name")
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_github_user_forwards_username(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(set_github_user, "run", _recording_run(calls))
    step = setup_new_project.build_steps(_make_config(github_user="octocat"))[
        _ALWAYS_ON_KEYS.index("set_github_user")
    ]
    step.call(tmp_path, True)
    assert calls[0]["args"] == (tmp_path, "octocat")
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": True}


@pytest.mark.unit
def test_step_python_version_forwards_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(set_python_version, "run", _recording_run(calls))
    step = setup_new_project.build_steps(_make_config(python_version="3.13"))[
        _ALWAYS_ON_KEYS.index("set_python_version")
    ]
    step.call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path, "3.13")


@pytest.mark.unit
def test_step_version_forwards_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(set_version, "run", _recording_run(calls))
    step = setup_new_project.build_steps(_make_config(version="1.2.3"))[
        _ALWAYS_ON_KEYS.index("set_version")
    ]
    step.call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path, "1.2.3")


@pytest.mark.unit
def test_step_strip_headers_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(strip_template_headers, "run", _recording_run(calls))
    step = setup_new_project.build_steps(_make_config())[
        _ALWAYS_ON_KEYS.index("strip_template_headers")
    ]
    step.call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_reset_readme_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(reset_readme, "run", _recording_run(calls))
    step = setup_new_project.build_steps(_make_config())[_ALWAYS_ON_KEYS.index("reset_readme")]
    step.call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_reset_changelog_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(reset_changelog, "run", _recording_run(calls))
    step = setup_new_project.build_steps(_make_config())[_ALWAYS_ON_KEYS.index("reset_changelog")]
    step.call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)


@pytest.mark.unit
def test_step_license_forwards_all_fields(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(choose_license, "run", _recording_run(calls))
    config = _make_config(
        license_key="proprietary",
        license_year="2026",
        license_name="Ada",
        license_company="Acme",
    )
    step = setup_new_project.build_steps(config)[_ALWAYS_ON_KEYS.index("choose_license")]
    step.call(tmp_path, False)
    assert calls[0]["kwargs"]["key"] == "proprietary"
    assert calls[0]["kwargs"]["year"] == "2026"
    assert calls[0]["kwargs"]["name"] == "Ada"
    assert calls[0]["kwargs"]["company"] == "Acme"
    assert calls[0]["kwargs"]["assume_yes"] is True


@pytest.mark.unit
def test_step_remove_mkdocs_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(remove_mkdocs, "run", _recording_run(calls))
    steps = setup_new_project.build_steps(_make_config(mkdocs=False))
    steps[-1].call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_remove_keyring_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(remove_keyring, "run", _recording_run(calls))
    steps = setup_new_project.build_steps(_make_config(keyring=False))
    steps[-1].call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_remove_keyvault_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(remove_keyvault, "run", _recording_run(calls))
    steps = setup_new_project.build_steps(_make_config(keyvault=False))
    steps[-1].call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_remove_secret_storage_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(remove_secret_storage, "run", _recording_run(calls))
    steps = setup_new_project.build_steps(
        _make_config(secret_storage=False, keyring=False, keyvault=False)
    )
    steps[-1].call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_remove_config_system_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(remove_config_system, "run", _recording_run(calls))
    steps = setup_new_project.build_steps(
        _make_config(config_system=False, secret_storage=False, keyring=False, keyvault=False)
    )
    steps[-1].call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_remove_private_repo_deps_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(remove_private_repo_deps, "run", _recording_run(calls))
    steps = setup_new_project.build_steps(_make_config(private_repo_deps=False))
    steps[-1].call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_remove_remote_disposable_scripts_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(remove_remote_disposable_scripts, "run", _recording_run(calls))
    steps = setup_new_project.build_steps(_make_config(remote_disposable_scripts=False))
    steps[-1].call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_remove_security_policy_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(remove_security_policy, "run", _recording_run(calls))
    steps = setup_new_project.build_steps(_make_config(security_policy=False))
    steps[-1].call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_remove_contributing_guide_forwards_assume_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(remove_contributing_guide, "run", _recording_run(calls))
    steps = setup_new_project.build_steps(_make_config(contributing_guide=False))
    steps[-1].call(tmp_path, False)
    assert calls[0]["args"] == (tmp_path,)
    assert calls[0]["kwargs"] == {"assume_yes": True, "dry_run": False}


@pytest.mark.unit
def test_step_reinit_git_forwards_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(reinit_git, "run", _recording_run(calls))
    steps = setup_new_project.build_steps(_make_config(reinit=True, branch="develop"))
    steps[-1].call(tmp_path, False)
    assert calls[0]["kwargs"]["branch"] == "develop"
    assert calls[0]["kwargs"]["assume_yes"] is True


# ---------------------------------------------------------------------------
# preview_steps / apply_steps
# ---------------------------------------------------------------------------


def _fake_planned_step(
    key: str, log: list[str], *, exit_code: int = 0
) -> setup_new_project.PlannedStep:
    """Build a PlannedStep whose call() records its invocation in log."""

    def call(root: Path, dry_run: bool) -> int:
        log.append(f"{key}:{dry_run}")
        return exit_code

    return setup_new_project.PlannedStep(key, key, call)


@pytest.mark.unit
def test_preview_steps_calls_every_step_with_dry_run_true(tmp_path: Path) -> None:
    log: list[str] = []
    steps = (_fake_planned_step("a", log), _fake_planned_step("b", log))
    setup_new_project.preview_steps(tmp_path, steps)
    assert log == ["a:True", "b:True"]


@pytest.mark.unit
def test_apply_steps_calls_every_step_with_dry_run_false_in_order(tmp_path: Path) -> None:
    log: list[str] = []
    steps = (_fake_planned_step("a", log), _fake_planned_step("b", log))
    failed = setup_new_project.apply_steps(tmp_path, steps)
    assert log == ["a:False", "b:False"]
    assert failed == []


@pytest.mark.unit
def test_apply_steps_collects_failures_without_stopping(tmp_path: Path) -> None:
    log: list[str] = []
    steps = (
        _fake_planned_step("a", log),
        _fake_planned_step("b", log, exit_code=1),
        _fake_planned_step("c", log),
    )
    failed = setup_new_project.apply_steps(tmp_path, steps)
    assert failed == ["b"]
    assert log == ["a:False", "b:False", "c:False"]


# ---------------------------------------------------------------------------
# run_setup
# ---------------------------------------------------------------------------


def _patch_all_steps(monkeypatch: pytest.MonkeyPatch, calls: list[str], exit_code: int = 0) -> None:
    """Monkeypatch every step module's run() to record its call and dry_run value."""
    modules = [
        strip_template_headers,
        reset_readme,
        rename_project,
        set_github_user,
        set_python_version,
        set_version,
        reset_changelog,
        choose_license,
        remove_mkdocs,
        remove_keyring,
        remove_keyvault,
        remove_secret_storage,
        remove_config_system,
        remove_private_repo_deps,
        remove_remote_disposable_scripts,
        remove_security_policy,
        remove_contributing_guide,
        reinit_git,
    ]
    for module in modules:

        def make_run(name: str) -> Any:
            def run(*args: Any, **kwargs: Any) -> int:
                calls.append(f"{name}:dry_run={kwargs.get('dry_run')}")
                return exit_code

            return run

        monkeypatch.setattr(module, "run", make_run(module.__name__))

    def fake_find_fixmes_run(root: Path) -> int:
        calls.append("find_fixmes")
        return 0

    monkeypatch.setattr(find_fixmes, "run", fake_find_fixmes_run)


@pytest.mark.integration
@pytest.mark.functional
def test_run_setup_missing_config_returns_two(tmp_path: Path) -> None:
    """A missing config file returns 2 without attempting validation."""
    assert setup_new_project.run_setup(tmp_path, tmp_path / "missing.toml") == 2


@pytest.mark.integration
@pytest.mark.functional
def test_run_setup_invalid_config_returns_one_and_calls_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An invalid config aborts before any step's run() is ever called."""
    calls: list[str] = []
    _patch_all_steps(monkeypatch, calls)
    config_path = tmp_path / "template_setup.toml"
    config_path.write_text(VALID_TOML.replace('key = "mit"', 'key = "bogus"'), encoding="utf-8")

    assert setup_new_project.run_setup(tmp_path, config_path, assume_yes=True) == 1
    assert calls == []


@pytest.mark.integration
@pytest.mark.functional
def test_run_setup_dry_run_calls_every_step_with_dry_run_true_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dry run previews every step and applies nothing."""
    calls: list[str] = []
    _patch_all_steps(monkeypatch, calls)
    config_path = tmp_path / "template_setup.toml"
    config_path.write_text(VALID_TOML, encoding="utf-8")

    assert setup_new_project.run_setup(tmp_path, config_path, dry_run=True) == 0
    assert calls
    assert all("dry_run=True" in call for call in calls)
    assert "find_fixmes" not in calls


@pytest.mark.integration
@pytest.mark.functional
def test_run_setup_confirmed_apply_runs_steps_then_find_fixmes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A confirmed apply previews, then applies for real, then reports FIXMEs."""
    calls: list[str] = []
    _patch_all_steps(monkeypatch, calls)
    config_path = tmp_path / "template_setup.toml"
    config_path.write_text(VALID_TOML, encoding="utf-8")

    assert setup_new_project.run_setup(tmp_path, config_path, assume_yes=True) == 0
    assert calls[-1] == "find_fixmes"
    assert any("dry_run=True" in call for call in calls)
    assert any("dry_run=False" in call for call in calls)


@pytest.mark.integration
@pytest.mark.functional
def test_run_setup_step_failure_continues_and_returns_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One failing step does not block the rest; the overall result is still 1."""
    calls: list[str] = []
    _patch_all_steps(monkeypatch, calls, exit_code=1)
    config_path = tmp_path / "template_setup.toml"
    config_path.write_text(VALID_TOML, encoding="utf-8")

    assert setup_new_project.run_setup(tmp_path, config_path, assume_yes=True) == 1
    assert calls[-1] == "find_fixmes"


@pytest.mark.integration
@pytest.mark.functional
def test_run_setup_declined_confirmation_returns_one_and_applies_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Declining the confirmation applies nothing for real."""
    calls: list[str] = []
    _patch_all_steps(monkeypatch, calls)
    monkeypatch.setattr(_common, "confirm", lambda *a, **k: False)
    config_path = tmp_path / "template_setup.toml"
    config_path.write_text(VALID_TOML, encoding="utf-8")

    assert setup_new_project.run_setup(tmp_path, config_path, assume_yes=False) == 1
    assert all("dry_run=True" in call for call in calls)
