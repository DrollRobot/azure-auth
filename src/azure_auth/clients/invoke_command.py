"""Cmdlet invocation over the Exchange admin REST API.

Exchange Online and Security & Compliance PowerShell both talk to an undocumented REST
endpoint, ``/adminapi/beta/<tenant id>/InvokeCommand``. The request shape used here was
read from the ExchangeOnlineManagement module (3.10.1). Because the endpoint is
undocumented, everything that knows about it lives in this module.

``beta`` is the only version that answers ``InvokeCommand``. The module also has an
``/adminapi/v1.0`` base URI, but only for its own REST-backed ``Get-EXO*`` cmdlets;
``InvokeCommand`` under ``v1.0`` is answered 405 (measured 2026-09-25).
"""

from __future__ import annotations

import base64
import binascii
import json as json_module
import uuid
from collections.abc import AsyncIterator, Sequence
from typing import Any, ClassVar

import httpx

from azure_auth.auth.context import AuthContext
from azure_auth.clients.base import ResourceClient
from azure_auth.clients.errors import InvokeCommandError, ResourceError
from azure_auth.constants import EXCHANGE_POWERSHELL_CLIENT_ID

# The arbitration mailbox Exchange uses to route requests that are not made by a mailbox
# user of the tenant: app-only access and delegated (GDAP) access.
SYSTEM_MAILBOX = "SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}"


def tenant_id_from_token(token: str) -> str | None:
    """Read the ``tid`` claim of an access token, without validating the token.

    Args:
        token: A JWT access token.

    Returns:
        The tenant id (GUID), or ``None`` when the token cannot be decoded.
    """
    parts = token.split(".")
    if len(parts) < 2:  # a JWT is header.payload[.signature]
        return None
    try:
        payload = json_module.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (binascii.Error, ValueError):
        return None
    tenant = payload.get("tid") if isinstance(payload, dict) else None
    return str(tenant) if tenant else None


def cmdlet_error_details(body: Any) -> list[str]:
    """Pull the cmdlet's own error text out of an ``InvokeCommand`` error body.

    The service wraps every cmdlet failure the same way: ``error.message`` is a generic
    ``"Error executing cmdlet"`` or ``"Invalid Operation"``, and the reason a person wants
    is in ``error.details[*].message``, prefixed with an error id and an exception type::

        Ex6F9304|Microsoft.Exchange...ManagementObjectNotFoundException|The operation ...

    Only the last, human-readable segment is kept; the whole body stays on the exception.

    Args:
        body: The decoded response body, of any shape.

    Returns:
        The reasons, in order, without their prefixes; empty when the body has none.
    """
    error = body.get("error") if isinstance(body, dict) else None
    details = error.get("details") if isinstance(error, dict) else None
    reasons: list[str] = []
    for detail in details if isinstance(details, list) else []:
        message = detail.get("message") if isinstance(detail, dict) else None
        if not isinstance(message, str):
            continue
        text = message.rsplit("|", 1)[-1].strip()
        if text:
            reasons.append(text)
    return reasons


def _is_blank(body: Any) -> bool:
    """Tell whether an error body says nothing at all.

    Args:
        body: The decoded response body, or ``None`` when it could not be decoded.

    Returns:
        ``True`` for no body, an empty one, or one that is only NUL bytes and whitespace.
    """
    return body is None or (isinstance(body, str) and not body.strip("\x00 \t\r\n"))


class InvokeCommandClient(ResourceClient):
    """Base class for clients that run cmdlets through ``InvokeCommand``.

    Attributes:
        HOST: Host name of the service.
        last_warnings: Warnings the service returned for the most recent cmdlet.
    """

    DEFAULT_CLIENT_ID: ClassVar[str] = EXCHANGE_POWERSHELL_CLIENT_ID
    ERROR_CLASS: ClassVar[type[ResourceError]] = InvokeCommandError
    HOST: ClassVar[str]

    def __init__(
        self,
        auth: AuthContext,
        *,
        client_id: str | None = None,
        scopes: Sequence[str] | None = None,
        anchor_mailbox: str | None = None,
        page_size: int = 1000,
        timeout: float = 300.0,
        max_retries: int = 3,
        max_retry_wait: float = 120.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Create the client. No network call is made.

        Args:
            auth: The authentication context to get tokens from.
            client_id: Client id for this client; see :class:`ResourceClient`.
            scopes: Scopes to request. Defaults to ``https://<host>/.default``.
            anchor_mailbox: Value of the ``X-AnchorMailbox`` routing header. Defaults to the
                signed-in user for a user flow in its own tenant, and to the tenant's system
                mailbox for app flows and for sibling (GDAP) contexts.
            page_size: Preferred number of results per page.
            timeout: Timeout for each HTTP request, in seconds. Cmdlets can be slow.
            max_retries: How often a throttled request is retried.
            max_retry_wait: Longest wait before one retry, in seconds.
            transport: Custom ``httpx`` transport, mainly for tests.
        """
        super().__init__(
            auth,
            base_url=f"https://{self.HOST}",
            client_id=client_id,
            scopes=scopes,
            timeout=timeout,
            max_retries=max_retries,
            max_retry_wait=max_retry_wait,
            transport=transport,
        )
        self._anchor_mailbox = anchor_mailbox
        self._page_size = page_size
        self._connection_id = str(uuid.uuid4())
        self._tenant_guid: str | None = None
        self.last_warnings: list[str] = []

    def _is_trusted_host(self, host: str) -> bool:
        """Accept the service host and its regional sub-hosts.

        Args:
            host: Host name of the request URL.

        Returns:
            ``True`` for ``HOST`` and for ``<region>.HOST``.
        """
        lowered = host.lower()
        return lowered == self.HOST or lowered.endswith(f".{self.HOST}")

    async def _tenant(self) -> str:
        """Return the tenant GUID for the request path.

        The service wants the GUID, and the context may have been given a domain name, so
        the GUID is read from the ``tid`` claim of the access token.

        Returns:
            The tenant GUID, or the context's tenant id when the token cannot be decoded.
        """
        if self._tenant_guid is None:
            token = await self._tokens.acquire_token(self._scopes, client_id=self._client_id)
            self._tenant_guid = tenant_id_from_token(token.token) or self._auth.tenant_id
        return self._tenant_guid

    def _anchor(self, tenant: str) -> str:
        """Build the ``X-AnchorMailbox`` routing header.

        Args:
            tenant: Tenant GUID.

        Returns:
            The configured anchor, else the user's mailbox for a user flow in its own tenant,
            else the tenant's system mailbox.
        """
        if self._anchor_mailbox:
            return self._anchor_mailbox
        if self._auth.is_app_flow or self._auth.is_sibling:
            return f"APP:{SYSTEM_MAILBOX}@{tenant}"
        return f"UPN:{self._auth.username}"

    async def _post(self, url: str, payload: dict[str, Any], cmdlet: str) -> httpx.Response:
        """Send one ``InvokeCommand`` request, following a regional redirect by hand.

        ``httpx`` drops the ``Authorization`` header when a redirect changes the host, and
        Security & Compliance answers the first call with a redirect to a regional host. So
        the redirect is read here, the regional host becomes the new base URL, and the
        request is sent again with its token.

        Args:
            url: Request URL or path.
            payload: The request body.
            cmdlet: Name of the cmdlet, for the diagnostic header.

        Returns:
            The successful response.
        """
        tenant = await self._tenant()
        # X-CmdletName and X-ResponseFormat are not in the PowerShell module. Measured
        # 2026-09-25: the service answers the same with either or both absent, so they are
        # kept only as diagnostics -- _error reads the cmdlet name back out of the request.
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json;odata.metadata=minimal",
            "Prefer": f"odata.maxpagesize={self._page_size}",
            "X-AnchorMailbox": self._anchor(tenant),
            "X-CmdletName": cmdlet,
            "X-ResponseFormat": "json",
            "connection-id": self._connection_id,
            "client-request-id": str(uuid.uuid4()),
        }
        response = await self.request("POST", url, json=payload, headers=headers)
        location = response.headers.get("Location")
        if response.status_code == httpx.codes.FOUND and location:
            region = httpx.URL(location).host.split(".", 1)[0]
            if region and not self._base_url.host.startswith(f"{region}."):
                self._base_url = httpx.URL(f"https://{region}.{self.HOST}/")
                target = httpx.URL(url) if "://" in url else None
                retry_url = str(target.copy_with(host=self._base_url.host)) if target else url
                response = await self.request("POST", retry_url, json=payload, headers=headers)
        if response.is_redirect:
            # A redirect that could not be followed must not look like an empty result.
            raise self._error(response)
        return response

    def _error(
        self, response: httpx.Response, *, undecodable: Exception | None = None
    ) -> ResourceError:
        """Build the exception for a failed cmdlet, with the cmdlet's own reason up front.

        The base message is the HTTP summary and the service's generic ``error.message``;
        the text a person needs is in ``error.details`` (see :func:`cmdlet_error_details`).
        An unknown cmdlet is a special case: Exchange answers 403 with a body of NUL bytes
        declared as gzip (measured 2026-09-25), so there is nothing to quote and the message
        says what that answer means instead.

        Args:
            response: The error response.
            undecodable: The decoding error, when the body could not be read at all.

        Returns:
            An :class:`InvokeCommandError`.
        """
        error = super()._error(response, undecodable=undecodable)
        cmdlet = response.request.headers.get("X-CmdletName", "The cmdlet")
        reasons = cmdlet_error_details(error.body)
        if reasons:
            reason = " ".join(reasons)
        elif error.status == httpx.codes.FORBIDDEN and _is_blank(error.body):
            reason = (
                "Exchange sent no error body, which is how it refuses a cmdlet it does not "
                "know; check the cmdlet name."
            )
        else:
            reason = "the service rejected it."
        return self.ERROR_CLASS(
            f"{cmdlet} failed: {reason} ({error})",
            status=error.status,
            code=error.code,
            request_id=error.request_id,
            body=error.body,
        )

    async def iter_pages(self, cmdlet: str, **parameters: Any) -> AsyncIterator[dict[str, Any]]:
        """Run a cmdlet and yield each page of its output.

        Args:
            cmdlet: Cmdlet name such as ``Get-Mailbox``.
            **parameters: Cmdlet parameters. Use ``True`` for switch parameters.

        Yields:
            Each response page; the results are under ``value``.
        """
        payload = {"CmdletInput": {"CmdletName": cmdlet, "Parameters": parameters}}
        tenant = await self._tenant()
        url: str | None = f"/adminapi/beta/{tenant}/InvokeCommand"
        self.last_warnings = []
        while url:
            response = await self._post(url, payload, cmdlet)
            page = self._json(response) or {}
            # The PowerShell module reads warnings from the X-Warnings header. Every live
            # response also carries them in the body, as "@adminapi.warnings" (measured
            # 2026-09-25, empty), so both are collected.
            header = response.headers.get("X-Warnings")
            if header:
                self.last_warnings.append(header)
            in_body = page.get("@adminapi.warnings")
            if isinstance(in_body, list):
                self.last_warnings.extend(str(warning) for warning in in_body if warning)
            yield page
            url = page.get("@odata.nextLink")

    async def run(self, cmdlet: str, **parameters: Any) -> list[dict[str, Any]]:
        """Run a cmdlet and return all of its output.

        Args:
            cmdlet: Cmdlet name such as ``Get-Mailbox``.
            **parameters: Cmdlet parameters. Use ``True`` for switch parameters.

        Returns:
            Every output object, as dictionaries. There is no server-side limit: a cmdlet
            with a large result set is paged through in full. ``ResultSize`` does not change
            this, because the PowerShell module applies it client side rather than sending
            it, so ``InvokeCommand`` ignores it. To stop early, use :meth:`iter_pages`.

        Raises:
            InvokeCommandError: If the service rejects the cmdlet.
        """
        results: list[dict[str, Any]] = []
        async for page in self.iter_pages(cmdlet, **parameters):
            results.extend(page.get("value", []))
        return results
