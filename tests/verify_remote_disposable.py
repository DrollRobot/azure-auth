"""Confirm the Entra tenant this project points at has been marked disposable.

``tests/conftest.py`` runs this as a subprocess before any ``destructive_remote`` test is
allowed to execute, and refuses to run one unless this exits 0. See AGENTS.TESTING.md.

The marker lives on the tenant, never in a local file or environment variable: pointing the
configuration at a different tenant has to fail closed on its own, and a local flag would
travel to whatever target the configuration named next.

The marker says nothing about which project is testing
-----------------------------------------------------

A disposable tenant is disposable for everyone. The marker is deliberately generic, so that
any project can mark a throwaway tenant once and every other project's destructive-test gate
recognises it without knowing anything about its neighbours. It is the address in
:data:`SENTINEL` -- a statement about the tenant, with no project name in it -- placed in the
organization's ``marketingNotificationEmails``.

It mirrors the ``DISPOSABLE_ENVIRONMENT=1`` variable this same framework uses to gate
``destructive_local`` tests: one says *this machine* is throwaway, the other says *this
tenant* is.

``marketingNotificationEmails`` is used because reading it needs only ``Organization.Read.All``
-- a permission a test app registration is likely to hold already, so a project does not have
to be granted anything extra merely to check. The address uses the reserved ``.invalid``
top-level domain (RFC 2606), so it can never resolve and can never receive mail.

Put the marker there with ``scripts/mark_remote_disposable.py``, which a human runs. **Agents
must never run that script or mark a tenant disposable.**

Authentication is app-only, with a certificate from the Windows certificate store, configured
through the environment variables below. That is deliberate: a gate must not depend on the
kind of access the tests it guards might revoke.

Exit codes:

* ``0`` -- the tenant carries the marker and may be mutated.
* ``1`` -- it does not, or the check could not be completed. Fails closed.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# Running this file as a script puts its own directory first on sys.path, and tests/http.py
# there shadows the standard library's `http` package. msal imports `http.server`, would get
# that file instead, and would fall back to its Python 2 import and crash. Drop this directory
# before importing anything that is not standard library.
sys.path[:] = [entry for entry in sys.path if not entry or Path(entry).resolve() != _HERE]
sys.path.insert(0, str(_HERE.parent / "src"))

from azure_auth import AuthContext, GraphClient  # noqa: E402  (sys.path fixed up above)

# Bump on every change so scripts/compare_to_template.py can flag copies in other repos:
# patch = bugfix, minor = new behaviour, major = a change to the marker other repos read.
__version__ = "1.0.0"

# Any tenant carrying this address in marketingNotificationEmails is declared throwaway, by
# whichever project put it there. Nothing in it names a project, on purpose: see the module
# docstring. Changing this value breaks every other repo using the same convention, so it is a
# major version bump, not an edit.
SENTINEL = "disposable-environment@example.invalid"


async def check() -> bool:
    """Read the organization and look for the sentinel.

    Returns:
        ``True`` only if the tenant is positively marked disposable.
    """
    tenant = os.environ.get("AZURE_AUTH_TEST_TENANT_ID", "")
    client_id = os.environ.get("AZURE_AUTH_TEST_APP_CLIENT_ID", "")
    thumbprint = os.environ.get("AZURE_AUTH_TEST_CERT_THUMBPRINT", "")
    if not (tenant and client_id and thumbprint):
        print(
            "verify_remote_disposable: AZURE_AUTH_TEST_TENANT_ID, _APP_CLIENT_ID and "
            "_CERT_THUMBPRINT must all be set (run pytest via 'uv run --env-file .env').",
            file=sys.stderr,
        )
        return False

    auth = AuthContext(tenant, client_id=client_id, certificate_thumbprint=thumbprint)
    async with GraphClient(auth) as graph:
        organizations = await graph.get_all(
            "/organization", params={"$select": "id,displayName,marketingNotificationEmails"}
        )

    for organization in organizations:
        marks = [str(mark).lower() for mark in organization.get("marketingNotificationEmails", [])]
        if SENTINEL.lower() in marks:
            name = organization.get("displayName", tenant)
            print(f"verify_remote_disposable: '{name}' is marked disposable.")
            return True

    print(
        f"verify_remote_disposable: tenant {tenant} is NOT marked disposable. No "
        f"'{SENTINEL}' in the organization's marketingNotificationEmails. A human can mark a "
        "throwaway tenant with scripts/mark_remote_disposable.py.",
        file=sys.stderr,
    )
    return False


def main() -> int:
    """Entry point.

    Returns:
        ``0`` when the tenant is marked disposable, ``1`` otherwise.
    """
    try:
        return 0 if asyncio.run(check()) else 1
    except Exception as error:
        print(f"verify_remote_disposable: check failed ({error}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
