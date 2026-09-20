"""Mark an Entra tenant as disposable, so destructive tests are allowed to run against it.

**For human use only, during setup. Agents must never run this script, and must never mark a
tenant disposable by any other means.** Marking a tenant declares it throwaway: test suites
may then mutate it, deleting and changing objects. Running this against a tenant anyone
depends on will let tests damage it.

What it changes, exactly: it appends one address to the organization's
``marketingNotificationEmails`` list, leaving any existing entries alone::

    disposable-environment@example.invalid

That is the whole marker; nothing else about the tenant is touched. ``--unmark`` removes that
one address and leaves the rest of the list as it was.
``tests/verify_remote_disposable.py`` defines the value as ``SENTINEL`` and this script
imports it from there, so the writer and the reader cannot drift apart.

The marker is generic on purpose. A disposable tenant is disposable for every project that
uses it, so nothing in the address names a project: mark a throwaway tenant once, and any
other repository carrying this same script pair recognises it without having to know anything
about its neighbours. It is the remote counterpart of the ``DISPOSABLE_ENVIRONMENT=1``
variable that gates ``destructive_local`` tests -- one says *this machine* is throwaway, this
one says *this tenant* is.

``marketingNotificationEmails`` is used because reading it back needs only
``Organization.Read.All``, which a test app registration is likely to hold already, so no
project needs an extra permission merely to check. The address uses the reserved ``.invalid``
top-level domain (RFC 2606), so it can never resolve and can never receive mail.

The marker lives on the tenant rather than in a local file so that pointing a project at a
different tenant fails closed by itself, with nothing local left armed.

Signing in needs ``Organization.ReadWrite.All``, which in practice means a Global
Administrator. Usage::

    uv run --env-file .env python scripts/mark_remote_disposable.py           # mark
    uv run --env-file .env python scripts/mark_remote_disposable.py --status  # just look
    uv run --env-file .env python scripts/mark_remote_disposable.py --unmark  # remove it
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _cli

from azure_auth import AuthContext, GraphClient
from tests.verify_remote_disposable import SENTINEL

__version__ = "1.0.0"

SCOPES = ["Organization.ReadWrite.All"]


def parse_args() -> argparse.Namespace:
    """Read the command line.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--status", action="store_true", help="Report the marker and stop.")
    group.add_argument("--unmark", action="store_true", help="Remove the marker.")
    return parser.parse_args()


async def run(args: argparse.Namespace) -> int:
    """Read, add or remove the disposability marker.

    Args:
        args: Parsed command line.

    Returns:
        Process exit code.
    """
    tenant = os.environ.get("AZURE_AUTH_TEST_TENANT_ID", "")
    username = os.environ.get("AZURE_AUTH_TEST_USERNAME", "")
    if not (tenant and username):
        _cli.die("Set AZURE_AUTH_TEST_TENANT_ID and AZURE_AUTH_TEST_USERNAME.")

    auth = AuthContext(tenant, username=username)
    async with GraphClient(auth, scopes=SCOPES) as graph:
        organizations = await graph.get_all(
            "/organization", params={"$select": "id,displayName,marketingNotificationEmails"}
        )
        organization = organizations[0]
        org_id = str(organization["id"])
        marks = [str(mark) for mark in organization.get("marketingNotificationEmails", [])]
        marked = SENTINEL.lower() in [mark.lower() for mark in marks]

        others = [mark for mark in marks if mark.lower() != SENTINEL.lower()]
        _cli.section("Tenant")
        _cli.info("display name", str(organization.get("displayName", "")))
        _cli.info("tenant id", org_id)
        _cli.info("field", "organization.marketingNotificationEmails")
        _cli.info("marker looked for", SENTINEL)
        _cli.info("disposable", "YES" if marked else "no")
        _cli.info("other addresses", ", ".join(others) if others else "(none)")
        sys.stdout.flush()

        if args.status:
            return 0 if marked else 1

        if args.unmark:
            if not marked:
                _cli.success("Not marked; nothing to remove.")
                return 0
            _cli.section("Remove the marker")
            print(f"  removing '{SENTINEL}' from organization.marketingNotificationEmails")
            print(f"  leaving:  {', '.join(others) if others else '(nothing else)'}")
            if not _cli.confirm("Remove the disposability marker?"):
                _cli.warn("Unchanged.")
                return 1
            await graph.patch(f"/organization/{org_id}", {"marketingNotificationEmails": others})
            _cli.success("Marker removed. Destructive tests will now refuse to run.")
            return 0

        if marked:
            _cli.success("Already marked disposable. Nothing to do.")
            return 0

        _cli.section("Mark as disposable")
        print(f"  appending '{SENTINEL}'")
        print("  to:       organization.marketingNotificationEmails")
        print(f"  keeping:  {', '.join(others) if others else '(list is currently empty)'}")
        print()
        _cli.warn(
            f"This declares '{organization.get('displayName', tenant)}' a THROWAWAY tenant.\n"
            "The test suite will then be allowed to mutate it: delete consent grants and\n"
            "change objects. Do not do this to a tenant anyone depends on."
        )
        if not _cli.confirm("Is this tenant genuinely disposable?"):
            _cli.warn("Unchanged.")
            return 1

        await graph.patch(
            f"/organization/{org_id}", {"marketingNotificationEmails": [*marks, SENTINEL]}
        )
        _cli.success(f"Marked. Destructive tests may now run against {org_id}.")
        return 0


def main() -> int:
    """Entry point.

    Returns:
        Process exit code.
    """
    args = parse_args()
    print(f"mark_remote_disposable.py {__version__}")
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        _cli.warn("\nInterrupted.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
