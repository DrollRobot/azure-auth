"""Unit tests for the Azure Key Vault credential backend.

Nothing here reaches a real vault: the backend validates its configuration
before it builds a client, and the read-only hint is a module constant.

This module imports the Key Vault backend at module scope, so it is deleted
along with the backend when a project drops it.
"""

from __future__ import annotations

import pytest
from azure_auth.config import keyvault_backend
from azure_auth.config.schema import ConfigError

# Version of this test module. It ships to projects generated from this
# template, so bump on every change to let scripts/compare_to_template.py
# flag stale copies.
__version__ = "2.0.0"

pytestmark = pytest.mark.unit


def test_keyvault_requires_vault_url() -> None:
    with pytest.raises(ConfigError, match="keyvault_url"):
        keyvault_backend.get("token", "svc", {})


def test_keyvault_declares_its_vault_url_key() -> None:
    """keyvault_url is legal in config.toml only because this module declares it."""
    assert "keyvault_url" in keyvault_backend.RESERVED_KEYS


def test_keyvault_is_read_only_and_names_the_azure_route() -> None:
    # The dispatcher repeats this hint when a write is attempted; it is the
    # only place a user is told how to update a Key Vault secret.
    assert not hasattr(keyvault_backend, "set")
    assert not hasattr(keyvault_backend, "delete")
    assert "az keyvault secret set" in keyvault_backend.READ_ONLY_HINT
