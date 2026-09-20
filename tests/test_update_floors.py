"""Unit tests for the pure helpers in scripts/update_floors.py.

The scripts folder is not a package, so the module is imported by adding the
folder to sys.path, mirroring how the scripts import their shared _cli module.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from update_floors import (
    apply_bumps,
    build_bumps,
    floor_version,
    iter_dependencies,
    locked_versions,
    normalize_name,
    raise_floor,
    requirement_name,
)

pytestmark = pytest.mark.unit

# --- normalize_name ------------------------------------------------------------------


def test_normalize_name_lowercases_and_collapses_separators() -> None:
    assert normalize_name("Mkdocs-Material") == "mkdocs-material"
    assert normalize_name("azure_keyvault.secrets") == "azure-keyvault-secrets"
    assert normalize_name("A__B..C--D") == "a-b-c-d"


# --- requirement_name ----------------------------------------------------------------


def test_requirement_name_strips_extras_and_specifier() -> None:
    assert requirement_name("mkdocs>=1.6,<2") == "mkdocs"
    assert requirement_name("mkdocstrings[python]>=1.0.4,<2") == "mkdocstrings"
    assert requirement_name("tomli>=2.0.1; python_version < '3.11'") == "tomli"


def test_requirement_name_none_for_garbage() -> None:
    assert requirement_name("") is None
    assert requirement_name(">=1.0") is None


# --- floor_version -------------------------------------------------------------------


def test_floor_version_reads_first_lower_bound() -> None:
    assert floor_version("mkdocs>=1.6,<2") == "1.6"
    assert floor_version("mkdocstrings[python]>=1.0.4,<2") == "1.0.4"
    assert floor_version("pkg>= 3.2 ,<4") == "3.2"


def test_floor_version_none_without_lower_bound() -> None:
    assert floor_version("requests") is None
    assert floor_version("pkg==1.2.3") is None
    assert floor_version("pkg<2") is None


# --- raise_floor ---------------------------------------------------------------------


def test_raise_floor_preserves_cap_extras_and_marker() -> None:
    assert raise_floor("mkdocs>=1.6,<2", "1.6.1") == "mkdocs>=1.6.1,<2"
    assert (
        raise_floor("mkdocstrings[python]>=1.0.4,<2", "1.5.0") == "mkdocstrings[python]>=1.5.0,<2"
    )
    assert (
        raise_floor("tomli>=2.0.1; python_version < '3.11'", "2.2.0")
        == "tomli>=2.2.0; python_version < '3.11'"
    )


def test_raise_floor_only_touches_first_lower_bound() -> None:
    # A contrived double lower bound: only the first >= is rewritten.
    assert raise_floor("pkg>=1.0,>=1.0", "2.0") == "pkg>=2.0,>=1.0"


def test_raise_floor_noop_without_lower_bound() -> None:
    assert raise_floor("requests", "2.0") == "requests"


# --- iter_dependencies ---------------------------------------------------------------


def test_iter_dependencies_reads_project_and_groups_ignoring_includes() -> None:
    data = {
        "project": {"dependencies": ["requests>=2.0", 123]},
        "dependency-groups": {
            "docs": ["mkdocs>=1.6,<2"],
            "dev": [{"include-group": "docs"}, "ruff>=0.15,<1"],
        },
    }
    assert iter_dependencies(data) == ["requests>=2.0", "mkdocs>=1.6,<2", "ruff>=0.15,<1"]


def test_iter_dependencies_reads_optional_dependency_extras() -> None:
    data = {
        "project": {
            "dependencies": ["requests>=2.0"],
            "optional-dependencies": {
                "keyring": ["keyring>=25.0,<26"],
                "keyvault": ["azure-identity>=1.25,<2", 123],
            },
        },
    }
    assert iter_dependencies(data) == [
        "requests>=2.0",
        "keyring>=25.0,<26",
        "azure-identity>=1.25,<2",
    ]


def test_iter_dependencies_tolerates_missing_tables() -> None:
    assert iter_dependencies({}) == []


# --- locked_versions -----------------------------------------------------------------


def test_locked_versions_maps_normalized_names() -> None:
    lock = {
        "package": [
            {"name": "MkDocs", "version": "1.6.1"},
            {"name": "azure_identity", "version": "1.19.0"},
            {"name": "no-version"},
            "not-a-table",
        ]
    }
    assert locked_versions(lock) == {"mkdocs": "1.6.1", "azure-identity": "1.19.0"}


def test_locked_versions_empty_without_packages() -> None:
    assert locked_versions({}) == {}


# --- build_bumps ---------------------------------------------------------------------


def test_build_bumps_raises_only_changed_floors() -> None:
    deps = ["mkdocs>=1.6,<2", "ruff>=0.15,<1"]
    locked = {"mkdocs": "1.6.1", "ruff": "0.15"}  # ruff already at floor
    bumps, skipped = build_bumps(deps, locked)
    assert skipped == [("ruff", "already at latest allowed (0.15)")]
    assert [(b.name, b.old_floor, b.new_floor, b.updated) for b in bumps] == [
        ("mkdocs", "1.6", "1.6.1", "mkdocs>=1.6.1,<2")
    ]


def test_build_bumps_records_skip_reasons() -> None:
    deps = ["requests", "tomli>=2.0.1; python_version < '3.11'", ">=1.0"]
    bumps, skipped = build_bumps(deps, locked={})
    assert bumps == []
    assert skipped == [
        ("requests", "no >= lower bound"),
        ("tomli", "not in uv.lock (marker-gated or a source dependency)"),
        (">=1.0", "unrecognized requirement"),
    ]


def test_build_bumps_dedupes_repeated_requirement() -> None:
    deps = ["pytest>=9.0,<10", "pytest>=9.0,<10"]
    bumps, _ = build_bumps(deps, {"pytest": "9.0.3"})
    assert len(bumps) == 1


# --- apply_bumps ---------------------------------------------------------------------


def test_apply_bumps_rewrites_every_occurrence_preserving_comments() -> None:
    text = (
        "docs = [\n"
        '    "mkdocs>=1.6,<2",\n'
        "]\n"
        "extra = [\n"
        '    "mkdocs>=1.6,<2",  # duplicated on purpose\n'
        "]\n"
    )
    bumps, _ = build_bumps(["mkdocs>=1.6,<2"], {"mkdocs": "1.6.1"})
    result = apply_bumps(text, bumps)
    assert '"mkdocs>=1.6.1,<2"' in result
    assert "mkdocs>=1.6,<2" not in result
    assert "# duplicated on purpose" in result


def test_apply_bumps_matches_single_quoted_requirement() -> None:
    text = "deps = [\n    'ruff>=0.15,<1',\n]\n"
    bumps, _ = build_bumps(["ruff>=0.15,<1"], {"ruff": "0.15.2"})
    assert apply_bumps(text, bumps) == "deps = [\n    'ruff>=0.15.2,<1',\n]\n"
