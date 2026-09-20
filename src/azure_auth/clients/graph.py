"""Thin client for Microsoft Graph."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any, ClassVar, Literal

import httpx

from azure_auth.auth.context import AuthContext
from azure_auth.clients.base import ResourceClient
from azure_auth.clients.errors import GraphError, ResourceError
from azure_auth.constants import GRAPH_CLI_CLIENT_ID, GRAPH_RESOURCE

BATCH_LIMIT = 20


class GraphClient(ResourceClient):
    """Authenticated requests to Microsoft Graph.

    User flows default to the Microsoft Graph PowerShell client id. That application works
    by dynamic consent, so pass the delegated ``scopes`` you need; without them the token
    only carries what was consented to in the tenant before. App flows always use
    ``https://graph.microsoft.com/.default``.

    Example:
        >>> graph = GraphClient(auth, scopes=["User.Read.All"])  # doctest: +SKIP
        >>> users = await graph.get_all("/users")  # doctest: +SKIP
    """

    DEFAULT_CLIENT_ID: ClassVar[str] = GRAPH_CLI_CLIENT_ID
    RESOURCE: ClassVar[str] = GRAPH_RESOURCE
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
    ) -> None:
        """Create the client. No network call is made.

        Args:
            auth: The authentication context to get tokens from.
            client_id: Client id for this client; see :class:`ResourceClient`.
            scopes: Delegated scopes for a user flow, such as ``["User.Read.All"]``.
            api_version: ``v1.0`` (default) or ``beta``.
            timeout: Timeout for each HTTP request, in seconds.
            max_retries: How often a throttled request is retried.
            max_retry_wait: Longest wait before one retry, in seconds.
            transport: Custom ``httpx`` transport, mainly for tests.
        """
        super().__init__(
            auth,
            base_url=f"{GRAPH_RESOURCE}/{api_version}",
            client_id=client_id,
            scopes=scopes,
            timeout=timeout,
            max_retries=max_retries,
            max_retry_wait=max_retry_wait,
            transport=transport,
        )

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

    async def list_customer_tenant_ids(self) -> list[str]:
        """List the tenants this partner tenant has a GDAP relationship with.

        Call this on a client for the partner tenant. It needs the delegated or application
        permission ``DelegatedAdminRelationship.Read.All``.

        Returns:
            The customer tenant ids.
        """
        customers = await self.get_all("/tenantRelationships/delegatedAdminCustomers")
        return [str(customer["tenantId"]) for customer in customers]
