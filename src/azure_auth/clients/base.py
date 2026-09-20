"""Shared behaviour of every resource client: tokens, retries and errors."""

from __future__ import annotations

import asyncio
import base64
import binascii
import datetime
import email.utils
import re
from collections.abc import Mapping, Sequence
from types import TracebackType
from typing import Any, ClassVar, Self

import httpx

from azure_auth.auth.context import AuthContext
from azure_auth.clients.errors import ResourceError

_OIDC_SCOPES = frozenset({"openid", "profile", "offline_access", "email"})
_RETRY_STATUSES = frozenset({429, 503})
_CLAIMS_PATTERN = re.compile(r'claims="([^"]+)"')
_REQUEST_ID_HEADERS = ("request-id", "x-ms-request-id", "client-request-id")
_MAX_BACKOFF_SECONDS = 30.0


def claims_from_challenge(header: str | None) -> str | None:
    """Extract the claims challenge from a ``WWW-Authenticate`` header.

    Resources that support continuous access evaluation answer 401 with a base64-encoded
    claims value. MSAL wants it decoded.

    Args:
        header: The ``WWW-Authenticate`` header value, if any.

    Returns:
        The claims as a JSON string, or ``None`` when the header carries no usable claims.
    """
    match = _CLAIMS_PATTERN.search(header or "")
    if match is None:
        return None
    encoded = match.group(1)
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        return decoded.decode("utf-8") or None
    except binascii.Error, UnicodeDecodeError:
        return None


def retry_delay(response: httpx.Response, attempt: int, max_wait: float) -> float:
    """Decide how long to wait before retrying a throttled request.

    Args:
        response: The throttled response; its ``Retry-After`` header wins when present.
        attempt: Number of the retry about to be made, starting at 1.
        max_wait: Upper bound for the delay, in seconds.

    Returns:
        The delay in seconds.
    """
    header = response.headers.get("Retry-After", "").strip()
    delay = min(2.0**attempt, _MAX_BACKOFF_SECONDS)
    if header:
        try:
            delay = float(header)
        except ValueError:
            try:
                when = email.utils.parsedate_to_datetime(header)
            except ValueError:
                pass
            else:
                delay = (when - datetime.datetime.now(datetime.UTC)).total_seconds()
    return max(0.0, min(delay, max_wait))


class ResourceClient:
    """Base class: an authenticated HTTP client for one resource.

    Subclasses set the class attributes and add resource-specific verbs.

    Attributes:
        DEFAULT_CLIENT_ID: First-party client id used for user flows when neither the client
            nor the context names one.
        RESOURCE: Resource identifier; ``<RESOURCE>/.default`` is the default scope.
        ERROR_CLASS: Exception type raised for error responses.
    """

    DEFAULT_CLIENT_ID: ClassVar[str]
    RESOURCE: ClassVar[str]
    ERROR_CLASS: ClassVar[type[ResourceError]] = ResourceError

    def __init__(
        self,
        auth: AuthContext,
        *,
        base_url: str,
        client_id: str | None = None,
        scopes: Sequence[str] | None = None,
        timeout: float = 100.0,
        max_retries: int = 3,
        max_retry_wait: float = 120.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Create the client. No network call is made.

        Args:
            auth: The authentication context to get tokens from.
            base_url: Base URL that relative request paths are joined to.
            client_id: Client id for this client. Defaults to the context's client id, then
                (user flows only) to ``DEFAULT_CLIENT_ID``.
            scopes: Delegated scopes to request in a user flow; short names are qualified
                with the resource. Defaults to ``<RESOURCE>/.default``. App flows always use
                ``.default``.
            timeout: Timeout for each HTTP request, in seconds.
            max_retries: How often a throttled request (429, 503) is retried.
            max_retry_wait: Longest wait before one retry, in seconds.
            transport: Custom ``httpx`` transport, mainly for tests.

        Raises:
            ValueError: If an app flow has no client id, or is given delegated scopes.
        """
        self._auth = auth
        self._tokens = auth.aio
        self._client_id = self._resolve_client_id(client_id)
        self._scopes = self._resolve_scopes(scopes)
        self._base_url = httpx.URL(base_url.rstrip("/") + "/")
        self._max_retries = max_retries
        self._max_retry_wait = max_retry_wait
        self._http = httpx.AsyncClient(timeout=timeout, transport=transport)

    # ------------------------------------------------------------------ configuration

    @property
    def auth(self) -> AuthContext:
        """The authentication context behind this client."""
        return self._auth

    @property
    def client_id(self) -> str:
        """The client id this client requests tokens with."""
        return self._client_id

    @property
    def scopes(self) -> tuple[str, ...]:
        """The scopes this client requests."""
        return tuple(self._scopes)

    @property
    def base_url(self) -> str:
        """The base URL that relative request paths are joined to."""
        return str(self._base_url).rstrip("/")

    def _resolve_client_id(self, client_id: str | None) -> str:
        """Apply the client id precedence rule.

        Args:
            client_id: Client id given to this client, if any.

        Returns:
            The client's id, else the context's, else (user flows) the resource default.
        """
        resolved = client_id or self._auth.client_id
        if resolved:
            return resolved
        if self._auth.is_app_flow:
            raise ValueError(
                "App flows need a client_id on the AuthContext or on the client; "
                "first-party client ids cannot be used with a secret or certificate"
            )
        return self.DEFAULT_CLIENT_ID

    def _resolve_scopes(self, scopes: Sequence[str] | None) -> list[str]:
        """Work out which scopes to request.

        Args:
            scopes: Scopes given to this client, if any.

        Returns:
            Fully qualified scopes.
        """
        default = [f"{self.RESOURCE}/.default"]
        if not scopes:
            return default
        qualified = [
            scope if "://" in scope or scope in _OIDC_SCOPES else f"{self.RESOURCE}/{scope}"
            for scope in scopes
        ]
        if self._auth.is_app_flow and qualified != default:
            raise ValueError(f"App flows always request {default[0]}; do not pass scopes")
        return qualified

    # ------------------------------------------------------------------ lifecycle

    async def login(self, *, force: bool = False) -> None:
        """Sign in now instead of at the first request.

        Args:
            force: Prompt even when a cached token or account exists.
        """
        await self._tokens.login(client_id=self._client_id, scopes=self._scopes, force=force)

    async def aclose(self) -> None:
        """Close the underlying HTTP connections."""
        await self._http.aclose()

    async def __aenter__(self) -> Self:
        """Enter the context manager.

        Returns:
            This client.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        """Close the client when leaving the context manager."""
        await self.aclose()

    # ------------------------------------------------------------------ requests

    def _url(self, url: str) -> httpx.URL:
        """Resolve a request URL and make sure the token may be sent to it.

        Args:
            url: A path relative to the base URL, or an absolute URL such as a next link.

        Returns:
            The absolute URL.

        Raises:
            ValueError: If the URL points at a host this client does not trust.
        """
        target = self._base_url.join(url.lstrip("/") if "://" not in url else url)
        trusted = target.scheme == "https" and self._is_trusted_host(target.host)
        # Credentials in the URL would make httpx replace the bearer token with basic auth.
        if not trusted or target.userinfo:
            raise ValueError(f"Refusing to send a token for {self.RESOURCE} to {target}")
        return target

    def _is_trusted_host(self, host: str) -> bool:
        """Decide whether a host may receive this client's token.

        Args:
            host: Host name of the request URL.

        Returns:
            ``True`` when the host is the base URL's host.
        """
        return host.lower() == self._base_url.host.lower()

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        """Send an authenticated request and return the successful response.

        Throttled requests (429, 503) are retried, honouring ``Retry-After``. A 401 is
        retried once: with the claims from the challenge when the resource sent one, else
        with a freshly acquired token.

        Args:
            method: HTTP method.
            url: Path relative to the base URL, or an absolute URL on the same host.
            params: Query parameters.
            json: Request body, serialised as JSON.
            headers: Extra request headers.

        Returns:
            The response, whose status is below 400.

        Raises:
            ResourceError: (the subclass in ``ERROR_CLASS``) for an error response.
        """
        target = self._url(url)
        retries = 0
        challenged = False
        claims: str | None = None
        force_refresh = False
        while True:
            token = await self._tokens.acquire_token(
                self._scopes, client_id=self._client_id, claims=claims, force_refresh=force_refresh
            )
            claims, force_refresh = None, False
            response = await self._http.request(
                method,
                target,
                params=params,
                json=json,
                headers={**(headers or {}), "Authorization": f"Bearer {token.token}"},
            )
            if response.status_code == httpx.codes.UNAUTHORIZED and not challenged:
                challenged = True
                claims = claims_from_challenge(response.headers.get("WWW-Authenticate"))
                force_refresh = claims is None
                continue
            if response.status_code in _RETRY_STATUSES and retries < self._max_retries:
                retries += 1
                await asyncio.sleep(retry_delay(response, retries, self._max_retry_wait))
                continue
            if response.status_code >= httpx.codes.BAD_REQUEST:
                raise self._error(response)
            return response

    def _error(self, response: httpx.Response) -> ResourceError:
        """Build the exception for an error response.

        Args:
            response: The error response.

        Returns:
            An instance of ``ERROR_CLASS``.
        """
        body: Any
        try:
            body = response.json()
        except ValueError:
            body = response.text
        error = body.get("error") if isinstance(body, dict) else None
        code = message = None
        if isinstance(error, dict):
            code, message = error.get("code"), error.get("message")
        elif isinstance(error, str):
            code, message = error, body.get("error_description")
        request_id = next(
            (response.headers[name] for name in _REQUEST_ID_HEADERS if name in response.headers),
            None,
        )
        summary = f"{response.request.method} {response.request.url} -> {response.status_code}"
        detail = ": ".join(str(part) for part in (code, message) if part)
        return self.ERROR_CLASS(
            f"{summary} {detail}".rstrip(),
            status=response.status_code,
            code=str(code) if code else None,
            request_id=request_id,
            body=body,
        )

    @staticmethod
    def _json(response: httpx.Response) -> Any:
        """Decode a response body.

        Args:
            response: A successful response.

        Returns:
            The parsed JSON, or ``None`` when the response has no body.
        """
        return response.json() if response.content else None
