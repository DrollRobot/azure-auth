"""Thin client for Microsoft Graph."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import time
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any, ClassVar, Literal

import httpx
from azure.core.credentials import AccessTokenInfo

from azure_auth.auth.context import AuthContext
from azure_auth.auth.errors import AuthError, ConsentRequired, InteractionRequired
from azure_auth.clients.base import ResourceClient
from azure_auth.clients.errors import GraphError, ResourceError
from azure_auth.constants import GRAPH_APP_ID, GRAPH_CLI_CLIENT_ID

_LOGGER = logging.getLogger(__name__)

BATCH_LIMIT = 20

# The delegated permission that lets an application change its own consent grants in a tenant.
GRANT_SCOPE = "DelegatedPermissionGrant.ReadWrite.All"
# Entra kept refusing a scope for 50 s after it was added to the grant and honoured it at 60 s
# (measured once, 2026-10-17). The poll allows three times that.
GRANT_SETTLE_SECONDS = 180.0
GRANT_POLL_SECONDS = 10.0
# Entra puts these in a grant by itself; they are never missing and never granted here.
_OIDC_SCOPES = frozenset({"openid", "profile", "email", "offline_access"})


def _short(scope: str) -> str:
    """Return a scope's short name: ``User.Read`` for ``https://graph.microsoft.com/User.Read``.

    Args:
        scope: A scope, qualified with its resource or not.

    Returns:
        The name after the last slash.
    """
    return scope.rsplit("/", 1)[-1]


def _scopes_in(token: str) -> frozenset[str] | None:
    """Return the scope names an access token carries, from its ``scp`` claim.

    An access token is meant for the resource, and Microsoft may change its format. This
    reads one claim of a token for Microsoft Graph and nothing else, without validating it.
    MSAL's own scope list cannot stand in: it is absent when a token comes from the cache
    (msal 1.39, ``_acquire_token_silent_from_cache_and_possibly_refresh_it``).

    Args:
        token: The access token.

    Returns:
        The scope names as the token spells them, or ``None`` when the token is not a
        readable JWT or has no ``scp`` claim: then nobody can tell what it carries.
    """
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError, UnicodeDecodeError, binascii.Error):
        return None
    if not isinstance(claims, dict) or "scp" not in claims:
        return None
    return frozenset(str(claims["scp"]).split())


class GraphClient(ResourceClient):
    """Authenticated requests to Microsoft Graph.

    User flows default to the Microsoft Graph PowerShell client id. That application works
    by dynamic consent, so pass the delegated ``scopes`` you need; without them the token
    only carries what was consented to in the tenant before. App flows always use
    ``.default``. Requests go to the Graph host of the context's cloud.

    Example:
        >>> graph = GraphClient(auth, scopes=["User.Read.All"])  # doctest: +SKIP
        >>> users = await graph.get_all("/users")  # doctest: +SKIP
    """

    DEFAULT_CLIENT_ID: ClassVar[str] = GRAPH_CLI_CLIENT_ID
    ERROR_CLASS: ClassVar[type[ResourceError]] = GraphError

    def __init__(
        self,
        auth: AuthContext,
        *,
        client_id: str | None = None,
        scopes: Sequence[str] | None = None,
        api_version: Literal["v1.0", "beta"] = "v1.0",
        timeout: float = 100.0,
        max_retries: int = 3,
        max_retry_wait: float = 120.0,
        transport: httpx.AsyncBaseTransport | None = None,
        grant_when_possible: bool = False,
        wait_for_grant: bool = True,
    ) -> None:
        """Create the client. No network call is made.

        Args:
            auth: The authentication context to get tokens from.
            client_id: Client id for this client; see :class:`ResourceClient`.
            scopes: Delegated scopes for a user flow, such as ``["User.Read.All"]``. Before
                asking for them, the client checks what the tenant has granted (see
                :meth:`_token`): a context from
                :meth:`~azure_auth.AuthContext.get_tenant_context` that lacks some raises
                :class:`ConsentRequired` naming them, without asking Entra for them.
            api_version: ``v1.0`` (default) or ``beta``.
            timeout: Timeout for each HTTP request, in seconds.
            max_retries: How often a throttled request is retried.
            max_retry_wait: Longest wait before one retry, in seconds.
            transport: Custom ``httpx`` transport, mainly for tests.
            grant_when_possible: When the tenant has not granted some of ``scopes``, add the
                missing ones to the application's tenant-wide grant there, provided the
                application already holds ``DelegatedPermissionGrant.ReadWrite.All`` in that
                tenant, and wait for a token that carries them (``wait_for_grant``). Without
                that permission, or when the grant cannot be read or changed, the
                :class:`ConsentRequired` is raised exactly as it is with this off. The grant
                is tenant-wide: every user of the application in that tenant gets the scopes,
                each still bounded by their own roles. Engages only where no consent screen
                can appear: contexts that may not prompt, such as those from
                :meth:`~azure_auth.AuthContext.get_tenant_context`. Off by default.
            wait_for_grant: After the grant is changed, ask for the token every ten seconds
                until Entra issues one carrying the new scopes, about a minute, or three
                minutes pass. The change reaches only tokens Entra issues afterwards, and
                Graph reads a token's scopes from the token itself (measured 2026-10-17), so
                the wait is for a new token, not for the grant. On by default. ``False``
                makes the grant, requests the token once, and raises the refusal when that
                token does not carry the scopes yet; a request a minute or so later does.
        """
        super().__init__(
            auth,
            resource=auth.tenant.cloud.graph,
            base_url=f"{auth.tenant.cloud.graph}/{api_version}",
            client_id=client_id,
            scopes=scopes,
            timeout=timeout,
            max_retries=max_retries,
            max_retry_wait=max_retry_wait,
            transport=transport,
        )
        self._grant_when_possible = grant_when_possible
        self._wait_for_grant = wait_for_grant
        # For the client that reads and changes the grant, with the application's ``.default``.
        self._client_args: dict[str, Any] = {
            "api_version": api_version,
            "timeout": timeout,
            "max_retries": max_retries,
            "max_retry_wait": max_retry_wait,
            "transport": transport,
        }

    @property
    def grant_when_possible(self) -> bool:
        """Whether refused scopes are added to the application's grant where that is possible."""
        return self._grant_when_possible

    async def login(self, *, pick_account: bool = False, fresh: bool = False) -> None:
        """Sign in now instead of at the first request.

        Without ``pick_account`` this is the first request's token, so the check of what the tenant
        has granted (see :meth:`granted_scopes`) runs here too.

        Args:
            pick_account: Show the account picker, even when a cached token or account
                exists or the broker or browser could sign in by itself. Someone other than
                the configured user is refused.
            fresh: After the sign-in and the check, ask Entra for a new token even when a
                usable one is cached; see :meth:`ResourceClient.login`.
        """
        if pick_account:
            await super().login(pick_account=True, fresh=fresh)
            return
        await self._token()
        if fresh:
            await self._token(force_refresh=True)

    async def granted_scopes(self) -> frozenset[str]:
        """Return the Graph scopes the tenant has granted this client's application.

        Asks Entra silently for a fresh ``.default`` token, which carries exactly the scopes
        the application holds in the tenant now, and reads them from it. A cached token is not
        used: it carries what was granted when it was issued, up to its lifetime ago. Never
        prompts and asks for nothing more, so a caller looping over tenants can check them all
        before any work starts. Costs one request to Entra per call.

        Returns:
            Short scope names, such as ``User.Read``, without the OpenID Connect ones. Empty
            when the application has no consent in the tenant at all.

        Raises:
            ValueError: In an app flow, whose tokens carry roles, not delegated scopes.
            InteractionRequired: If the user has not signed in yet.
            AuthError: If the token's scopes cannot be read, or for any other failure.
        """
        if self._auth.is_app_flow:
            raise ValueError("App flows hold application roles, not delegated scopes")
        granted = await self._granted(fresh=True)
        if granted is None:
            raise AuthError("The .default token's scopes cannot be read: it is not a JWT")
        return granted

    async def _granted(self, *, fresh: bool = False) -> frozenset[str] | None:
        """Ask silently for ``.default`` and return the scopes its token carries.

        Args:
            fresh: Ask Entra instead of taking a cached token, which carries what was granted
                when it was issued.

        Returns:
            Short scope names without the OpenID Connect ones; empty when the tenant has
            granted the application nothing; ``None`` when the token cannot be read.

        Raises:
            InteractionRequired: If the user has not signed in yet.
        """
        default = [f"{self._resource}/.default"]
        try:
            held = await self._credential.acquire_token_silently(
                default, client_id=self._client_id, force_refresh=fresh
            )
        except ConsentRequired:
            # AADSTS65001 for .default itself: the application holds nothing there.
            return frozenset()
        scopes = _scopes_in(held.token)
        if scopes is None:
            return None
        return frozenset(scope for scope in scopes if scope.lower() not in _OIDC_SCOPES)

    async def _token(
        self, *, claims: str | None = None, force_refresh: bool = False
    ) -> AccessTokenInfo:
        """Acquire this client's token, checking first what the tenant has granted.

        The check runs for user flows that name scopes, when no token for them is cached and
        no claims challenge or forced refresh is being answered. It asks silently for
        ``.default`` and compares. A cached ``.default`` token answers first, at no cost; when
        it lacks a requested scope, Entra is asked for a fresh one before anything is decided,
        because a cached token carries what was granted when it was issued and may predate a
        grant. A cached token that holds every scope is trusted: should one have been taken out
        since, Graph still accepts the cached tokens that carry it until they expire.

        - Every scope granted, or the token unreadable: the named request, as without it.
        - Some missing, and the context may prompt: the named sign-in, which shows Entra's
          consent screen to someone who can consent.
        - Some missing, and the context may not prompt (one from ``get_tenant_context()``):
          with ``grant_when_possible`` and ``DelegatedPermissionGrant.ReadWrite.All`` among
          the granted scopes, the grant; otherwise :class:`ConsentRequired` at once, saying
          what is granted and missing.
        - Not signed in yet: as without the check; a context that may prompt signs in.

        Args:
            claims: Claims challenge to satisfy, as a JSON string.
            force_refresh: Skip cached access tokens.

        Returns:
            The token with its expiry time and type.

        Raises:
            ConsentRequired: When a context that may not prompt lacks scopes it cannot be
                granted; or when they were granted and no token carried them in time.
            InteractionRequired: When a context that may not prompt has no sign-in to use:
                for one from ``get_tenant_context()``, its home has not signed in.
        """
        default = [f"{self._resource}/.default"]
        if (
            self._auth.is_app_flow
            or self._scopes == default
            or claims
            or force_refresh
            or self._auth._recent_token(self._scopes, self._client_id) is not None
        ):
            return await super()._token(claims=claims, force_refresh=force_refresh)
        try:
            granted = await self._granted()
            missing = self._missing(granted)
            if missing:
                # The cached token may predate a grant; only Entra's word is final.
                granted = await self._granted(fresh=True)
                missing = self._missing(granted)
        except InteractionRequired:
            if not self._auth._can_prompt:
                raise
            return await super()._token()
        if granted is None:
            return await super()._token()
        held = {scope.lower() for scope in granted}
        if not missing or self._auth._can_prompt:
            return await super()._token()
        refusal = self._refusal(granted, missing)
        if not (self._grant_when_possible and GRANT_SCOPE.lower() in held):
            raise refusal
        await self._grant(missing, refusal)
        return await self._token_carrying(missing, refusal)

    def _missing(self, granted: frozenset[str] | None) -> list[str]:
        """Return the requested scopes that ``granted`` lacks, as short names.

        Args:
            granted: What a ``.default`` token carries, or ``None`` when it cannot be read.

        Returns:
            The missing short names; empty when nothing is missing or nobody can tell.
        """
        if granted is None:
            return []
        held = {scope.lower() for scope in granted}
        return [
            _short(scope)
            for scope in self._scopes
            if _short(scope).lower() not in held and _short(scope).lower() not in _OIDC_SCOPES
        ]

    def _refusal(self, granted: frozenset[str], missing: Sequence[str]) -> ConsentRequired:
        """Build the error for a context that may not prompt and lacks scopes.

        Args:
            granted: Short names of the scopes the tenant has granted.
            missing: Short names of the requested scopes it has not.

        Returns:
            The error, naming the application, the tenant, what is granted and what is not.
        """
        tenant = self._auth.tenant.id
        if granted:
            message = (
                f"Tenant {tenant} has not granted {', '.join(missing)} to application "
                f"{self._client_id}; it has granted {len(granted)} other Graph scopes."
            )
        else:
            message = (
                f"Application {self._client_id} has no consent in tenant {tenant} at all, so "
                f"{', '.join(missing)} cannot be issued."
            )
        message += (
            " This context was made by get_tenant_context() and cannot show a consent screen; "
            "an administrator in that tenant has to grant the scopes."
        )
        if GRANT_SCOPE.lower() in {scope.lower() for scope in granted}:
            if not self._grant_when_possible:
                message += (
                    f" The application holds {GRANT_SCOPE} there, and could grant itself the "
                    "requested scopes."
                )
        elif self._grant_when_possible:
            message += f" grant_when_possible needs {GRANT_SCOPE} there, which is not granted."
        return ConsentRequired(
            message,
            tenant_id=tenant,
            scopes=self._scopes,
            granted=sorted(granted),
            missing=missing,
        )

    async def _grant(self, missing: Sequence[str], refusal: ConsentRequired) -> None:
        """Add the missing scopes to the application's tenant-wide grant.

        Args:
            missing: Short names of the scopes to add.
            refusal: Raised whenever the grant cannot be made, so the caller sees what it
                would see with ``grant_when_possible`` off.

        Raises:
            ConsentRequired: ``refusal``, when the grant cannot be read or changed.
        """
        async with GraphClient(self._auth, client_id=self._client_id, **self._client_args) as graph:
            try:
                grant = await graph._tenant_grant()
                if grant is None:
                    raise refusal
                before = str(grant.get("scope", "")).split()
                have = {scope.lower() for scope in before}
                after = before + [scope for scope in missing if scope.lower() not in have]
                await graph.patch(
                    f"/oauth2PermissionGrants/{grant['id']}", {"scope": " ".join(after)}
                )
            except GraphError:
                raise refusal from None
        _LOGGER.info(
            "Added %s to the tenant-wide grant of application %s in tenant %s",
            ", ".join(missing),
            self._client_id,
            self._auth.tenant.id,
        )

    async def _tenant_grant(self) -> dict[str, Any] | None:
        """Return this application's tenant-wide grant for Microsoft Graph, if it has one.

        Looked up with this client's own token, so call it on a client whose scopes the
        tenant has granted: the application's ``.default``.

        Returns:
            The ``oauth2PermissionGrant`` with ``consentType`` ``AllPrincipals`` and Graph as
            its resource, or ``None``.
        """
        graph_principal = await self.get_all(
            "/servicePrincipals", params={"$filter": f"appId eq '{GRAPH_APP_ID}'", "$select": "id"}
        )
        own_principal = await self.get_all(
            "/servicePrincipals",
            params={"$filter": f"appId eq '{self._client_id}'", "$select": "id"},
        )
        if not graph_principal or not own_principal:
            return None
        grants = await self.get_all(
            "/oauth2PermissionGrants", params={"$filter": f"clientId eq '{own_principal[0]['id']}'"}
        )
        return next(
            (
                dict(grant)
                for grant in grants
                if grant.get("consentType") == "AllPrincipals"
                and grant.get("resourceId") == graph_principal[0]["id"]
            ),
            None,
        )

    async def _token_carrying(
        self, added: Sequence[str], refusal: ConsentRequired
    ) -> AccessTokenInfo:
        """Request the token again until it carries the scopes just added, or time runs out.

        Entra honours a change to a grant only in tokens it issues afterwards, about a minute
        later, and Graph reads a token's scopes from the token itself: a token issued before
        the change stays refused however long one waits (measured 2026-10-17). A request
        naming a scope that no cached token holds reaches Entra every time, so plain silent
        requests are enough to get the new token. Without ``wait_for_grant`` there is one
        request, and its refusal is raised.

        Args:
            added: Short names of the scopes just added to the grant.
            refusal: The refusal the grant answered, for what it says was granted and missing.

        Returns:
            A token carrying the scopes.

        Raises:
            ConsentRequired: When no token carried the scopes within ``GRANT_SETTLE_SECONDS``,
                or at the first refusal without ``wait_for_grant``.
        """
        deadline = time.monotonic() + GRANT_SETTLE_SECONDS
        while True:
            try:
                return await super()._token()
            except ConsentRequired as still:
                if self._wait_for_grant and time.monotonic() < deadline:
                    await asyncio.sleep(GRANT_POLL_SECONDS)
                    continue
                waited = (
                    f"within {GRANT_SETTLE_SECONDS:.0f} s"
                    if self._wait_for_grant
                    else "yet, and no wait was asked for (wait_for_grant=False)"
                )
                raise ConsentRequired(
                    f"{', '.join(added)} added to the grant of {self._client_id} in tenant "
                    f"{self._auth.tenant.id}, but no token carried them {waited}: {still}",
                    tenant_id=refusal.tenant_id,
                    scopes=refusal.scopes,
                    granted=refusal.granted,
                    missing=refusal.missing,
                ) from still

    async def get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """Send a GET request.

        Args:
            path: Path such as ``/users``, or an absolute Graph URL.
            params: Query parameters such as ``{"$top": 5}``.
            headers: Extra request headers such as ``ConsistencyLevel``.

        Returns:
            The parsed JSON body.
        """
        return self._json(await self.request("GET", path, params=params, headers=headers))

    async def post(
        self,
        path: str,
        json: Any = None,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """Send a POST request.

        Args:
            path: Path such as ``/users``.
            json: Request body.
            params: Query parameters.
            headers: Extra request headers.

        Returns:
            The parsed JSON body, or ``None`` when the response has none.
        """
        response = await self.request("POST", path, params=params, json=json, headers=headers)
        return self._json(response)

    async def patch(
        self,
        path: str,
        json: Any = None,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """Send a PATCH request.

        Args:
            path: Path such as ``/users/{id}``.
            json: Request body.
            params: Query parameters.
            headers: Extra request headers.

        Returns:
            The parsed JSON body, or ``None`` when the response has none.
        """
        response = await self.request("PATCH", path, params=params, json=json, headers=headers)
        return self._json(response)

    async def put(
        self,
        path: str,
        json: Any = None,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """Send a PUT request.

        Args:
            path: Path of the resource.
            json: Request body.
            params: Query parameters.
            headers: Extra request headers.

        Returns:
            The parsed JSON body, or ``None`` when the response has none.
        """
        response = await self.request("PUT", path, params=params, json=json, headers=headers)
        return self._json(response)

    async def delete(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """Send a DELETE request.

        Args:
            path: Path of the resource.
            params: Query parameters.
            headers: Extra request headers.

        Returns:
            The parsed JSON body, or ``None`` when the response has none.
        """
        return self._json(await self.request("DELETE", path, params=params, headers=headers))

    async def iter_pages(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield every page of a collection, following ``@odata.nextLink``.

        Args:
            path: Path of the collection.
            params: Query parameters for the first page; next links carry their own.
            headers: Extra request headers, sent with every page.

        Yields:
            Each page as returned by Graph.
        """
        url: str | None = path
        while url:
            page = await self.get(url, params=params, headers=headers)
            yield page
            url, params = page.get("@odata.nextLink"), None

    async def get_all(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> list[Any]:
        """Return every item of a collection, following ``@odata.nextLink``.

        Args:
            path: Path of the collection.
            params: Query parameters for the first page.
            headers: Extra request headers, sent with every page.

        Returns:
            The items of all pages, in order.
        """
        items: list[Any] = []
        async for page in self.iter_pages(path, params=params, headers=headers):
            items.extend(page.get("value", []))
        return items

    async def batch(self, requests: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Send requests through ``$batch``, twenty per call.

        Args:
            requests: Batch request objects with ``method`` and ``url`` and optionally
                ``id``, ``body`` and ``headers``. Missing ids are filled in. A request with
                a body and no content type is sent as JSON.

        Returns:
            One response object per request, in the order of ``requests``. Failed requests
            are returned with their error status, not raised.
        """
        prepared: list[dict[str, Any]] = []
        for index, request in enumerate(requests):
            item = dict(request)
            item["id"] = str(item.get("id", index))
            if "body" in item and "headers" not in item:
                item["headers"] = {"Content-Type": "application/json"}
            prepared.append(item)

        responses: dict[str, dict[str, Any]] = {}
        for start in range(0, len(prepared), BATCH_LIMIT):
            chunk = prepared[start : start + BATCH_LIMIT]
            result = await self.post("/$batch", {"requests": chunk})
            responses.update({str(item["id"]): item for item in result.get("responses", [])})
        return [responses[item["id"]] for item in prepared]

    async def list_customers(self) -> list[dict[str, Any]]:
        """List this home tenant's GDAP customers, as Graph describes them.

        Call this on a client for the home tenant. It needs the delegated or application
        permission ``DelegatedAdminRelationship.Read.All``.

        Each customer is the object Graph returns from
        ``GET /tenantRelationships/delegatedAdminCustomers``, unchanged: ``tenantId``,
        ``displayName``, and whatever else Graph adds. A customer reached through several
        relationships is listed once, by its first appearance.

        Returns:
            One object per customer tenant, in Graph's order.
        """
        customers: dict[str, dict[str, Any]] = {}
        for customer in await self.get_all("/tenantRelationships/delegatedAdminCustomers"):
            customers.setdefault(str(customer["tenantId"]), customer)
        return list(customers.values())
