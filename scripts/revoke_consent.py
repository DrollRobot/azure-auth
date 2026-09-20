"""Remove the OAuth2 consent grants of an application, to reset a tenant before testing.

For human use only, during test setup. This mutates a live tenant: every delegated permission
grant belonging to the target application is deleted, so the next sign-in has to consent
again. That is the point -- the consent retry in :meth:`AuthContext._consent` only runs when
consent is genuinely missing, and a tenant where the application is already consented cannot
exercise it.

Point this at a tenant you are willing to break. It is not a test and nothing runs it
automatically.

It signs in as a user. An administrator revoking consent is the ordinary way this is done,
it needs nothing set up on an app registration, and revoking is reversible: the grants are
only records, so signing in and consenting again recreates them. Consenting again grants
whatever scopes are asked for at that moment, not necessarily the exact set that was there
before.

The signed-in user needs these delegated scopes, which the sign-in will ask for:

* ``DelegatedPermissionGrant.ReadWrite.All`` -- to list and delete the grants. The ``Read``
  variant only enumerates; deleting needs ``ReadWrite``.
* ``Application.Read.All`` -- to resolve the target application's service principal, whose
  object id the grant filter needs.

``--app-only`` authenticates with the certificate instead, for an unattended reset. Think
before using it. It needs those two as **application** permissions on the app registration,
and an application holding ``DelegatedPermissionGrant.ReadWrite.All`` can create and delete
consent grants for any application including itself, which is a well known privilege
escalation path -- Microsoft classes it among the most dangerous application permissions,
alongside ``AppRoleAssignment.ReadWrite.All``. Signing in as a user avoids putting a
permission like that on a long-lived credential, which is why it is the default here.

Usage::

    # as the signed-in user
    uv run --env-file .env python scripts/revoke_consent.py

    # list what would go, change nothing
    uv run --env-file .env python scripts/revoke_consent.py --dry-run

    # another application, and no confirmation prompt
    uv run --env-file .env python scripts/revoke_consent.py --client-id <guid> --yes

    # unattended, with the certificate; read the warning above first
    uv run --env-file .env python scripts/revoke_consent.py --app-only

Environment (the same names the live tests use, so ``.env`` covers it):
``AZURE_AUTH_TEST_TENANT_ID`` and ``AZURE_AUTH_TEST_USERNAME``; ``--app-only`` needs
``AZURE_AUTH_TEST_APP_CLIENT_ID`` and ``AZURE_AUTH_TEST_CERT_THUMBPRINT`` instead.
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

from azure_auth import AuthContext, GraphClient, ResourceError
from tests import consent_reset

__version__ = "1.0.0"

# Microsoft Graph PowerShell. The default because it is what the user-flow clients sign in as.
GRAPH_POWERSHELL = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

# Scopes the signed-in user needs. Deleting a grant needs the first (the Read variant only
# enumerates); resolving the target's service principal needs the second.
DELEGATED_SCOPES = ["DelegatedPermissionGrant.ReadWrite.All", "Application.Read.All"]


def parse_args() -> argparse.Namespace:
    """Read the command line.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--client-id",
        default=GRAPH_POWERSHELL,
        help=f"Application whose grants are deleted. Default: Graph PowerShell "
        f"({GRAPH_POWERSHELL}).",
    )
    parser.add_argument(
        "--app-only",
        action="store_true",
        help="Use the certificate instead of signing in, for an unattended reset. Needs "
        "DelegatedPermissionGrant.ReadWrite.All as an application permission, which lets an "
        "app rewrite consent for any app including itself. See the module docstring.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Delete every grant, including your own. By default your own grant survives, so "
        "the next run does not have to re-consent just to restore tooling access.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List the grants that would be deleted, then stop.",
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Do not ask for confirmation.")
    return parser.parse_args()


def build_auth(app_only: bool) -> AuthContext:
    """Create the authentication context the script will use.

    Args:
        app_only: Use the certificate rather than signing in as a user.

    Returns:
        A context for the tenant named in the environment.
    """
    tenant = os.environ.get("AZURE_AUTH_TEST_TENANT_ID", "")
    if not tenant:
        _cli.die("Set AZURE_AUTH_TEST_TENANT_ID (use: uv run --env-file .env python ...).")

    if not app_only:
        username = os.environ.get("AZURE_AUTH_TEST_USERNAME", "")
        if not username:
            _cli.die("Set AZURE_AUTH_TEST_USERNAME, or pass --app-only to use the certificate.")
        return AuthContext(tenant, username=username)

    client_id = os.environ.get("AZURE_AUTH_TEST_APP_CLIENT_ID", "")
    thumbprint = os.environ.get("AZURE_AUTH_TEST_CERT_THUMBPRINT", "")
    if not (client_id and thumbprint):
        _cli.die(
            "--app-only needs AZURE_AUTH_TEST_APP_CLIENT_ID and AZURE_AUTH_TEST_CERT_THUMBPRINT."
        )
    return AuthContext(tenant, client_id=client_id, certificate_thumbprint=thumbprint)


async def resource_name(graph: GraphClient, resource_id: str, cache: dict[str, str]) -> str:
    """Return the display name of a resource service principal, remembering the answer.

    Args:
        graph: The Graph client to ask.
        resource_id: Object id of the resource service principal.
        cache: Lookups already made, updated in place.

    Returns:
        The display name, or the raw id if it cannot be read.
    """
    if resource_id not in cache:
        try:
            resource = await graph.get(f"/servicePrincipals/{resource_id}?$select=displayName")
            cache[resource_id] = str(resource.get("displayName", resource_id))
        except ResourceError:
            cache[resource_id] = resource_id
    return cache[resource_id]


async def keep_principal(graph: GraphClient, keep_me: bool) -> str | None:
    """Return the object id of the signed-in user, when their own grant should survive.

    Args:
        graph: The Graph client to ask.
        keep_me: Whether to spare the signed-in user's own grant.

    Returns:
        The object id, or ``None`` to delete every grant.
    """
    if not keep_me:
        return None
    me = await graph.get("/me", params={"$select": "id"})
    return str(me["id"])


async def run(args: argparse.Namespace) -> int:
    """Find and delete the target application's consent grants.

    Args:
        args: Parsed command line.

    Returns:
        Process exit code.
    """
    auth = build_auth(args.app_only)
    scopes = None if args.app_only else DELEGATED_SCOPES

    async with GraphClient(auth, scopes=scopes) as graph:
        _cli.section("Target")
        _cli.info("tenant", auth.tenant_id)
        _cli.info("sign-in", "certificate (app-only)" if args.app_only else "user (delegated)")
        _cli.info("application", args.client_id)
        # stdout is block-buffered when piped, and _cli.die writes to stderr; flush so the
        # target above still appears before any error about it.
        sys.stdout.flush()

        try:
            principal = await consent_reset.service_principal(graph, args.client_id)
        except ResourceError as error:
            if error.status == 404:
                _cli.die(f"No service principal for {args.client_id} in this tenant.")
            _cli.die(f"Could not read the service principal: {error}")

        principal_id = str(principal["id"])
        _cli.info("display name", str(principal.get("displayName", "")))
        _cli.info("object id", principal_id)

        _cli.section("Grants")
        try:
            grants = await consent_reset.find_grants(graph, principal_id)
            spare = await keep_principal(graph, not args.all)
        except ResourceError as error:
            _cli.die(
                f"Could not list the grants: {error}\n"
                "The identity needs DelegatedPermissionGrant.ReadWrite.All."
            )

        if not grants:
            _cli.success("No consent grants. Nothing to do; the tenant is already reset.")
            return 0

        names: dict[str, str] = {}
        doomed = 0
        for grant in grants:
            resource = await resource_name(graph, str(grant["resourceId"]), names)
            kept = (
                spare is not None
                and grant.get("consentType") != "AllPrincipals"
                and str(grant.get("principalId", "")) == spare
            )
            doomed += 0 if kept else 1
            suffix = "  [kept: your own grant]" if kept else ""
            print(f"  {resource}  ({consent_reset.describe(grant)}){suffix}")

        if args.dry_run:
            _cli.warn(f"\n--dry-run: nothing deleted. {doomed} of {len(grants)} would go.")
            return 0

        if not doomed:
            _cli.success("Only your own grant is present. Already at the baseline.")
            return 0

        _cli.section("Delete")
        _cli.warn(
            f"About to delete {doomed} consent grant(s) in tenant {auth.tenant_id}.\n"
            "Every user who relies on them loses access through this application until "
            "consent is granted again."
        )
        if args.yes:
            _cli.set_assume_yes(True)
        if not _cli.confirm("Delete them?"):
            _cli.warn("Nothing was deleted.")
            return 1

        result = await consent_reset.reset_to_baseline(
            graph, client_id=args.client_id, keep_principal_id=spare
        )
        for grant_id in result.deleted:
            print(f"  deleted {grant_id}")
        for grant_id, reason in result.failed.items():
            _cli.warn(f"  could not delete {grant_id}: {reason}")

        _cli.success(f"\nDeleted {len(result.deleted)}, kept {len(result.kept)}.")
        return 0 if result.ok else 1


def main() -> int:
    """Entry point.

    Returns:
        Process exit code.
    """
    args = parse_args()
    print(f"revoke_consent.py {__version__}")
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        _cli.warn("\nInterrupted.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
