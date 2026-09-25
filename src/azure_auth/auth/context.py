"""The authentication context shared by every resource client.

An :class:`AuthContext` holds one tenant, one set of credentials, one token cache and (for
user flows) one account. It creates MSAL applications on demand, one per client id, because
the Microsoft first-party client ids differ per resource.

The context implements the Azure SDK ``TokenCredential`` protocol, and its :attr:`aio`
attribute implements ``AsyncTokenCredential``, so any ``azure-*`` SDK client accepts it as
``credential=``.
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
import threading
import time
from collections.abc import Iterable, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import msal
from azure.core.credentials import AccessToken, AccessTokenInfo, TokenRequestOptions
from msal import BrowserInteractionTimeoutError

from azure_auth.auth import cng
from azure_auth.auth.cache import CacheKind, build_cache
from azure_auth.auth.credentials import (
    AppCredential,
    CertStoreCredential,
    PemCertificateCredential,
    SecretCredential,
)
from azure_auth.auth.errors import (
    AccountSelectionRequired,
    AuthError,
    BrokerUnavailable,
    InteractionRequired,
    error_from_msal_result,
)
from azure_auth.constants import AZURE_POWERSHELL_CLIENT_ID, DEFAULT_AUTHORITY_HOST

_LOGGER = logging.getLogger(__name__)

# A cached token is reused until it is this close to expiry.
_REFRESH_MARGIN_SECONDS = 300

# How long a browser sign-in waits for the person before it is abandoned, unless the context
# is given ``interactive_timeout``. Without a limit, a closed browser window leaves MSAL
# waiting for a redirect that never arrives.
_DEFAULT_INTERACTIVE_TIMEOUT_SECONDS = 120

_TokenKey = tuple[str, frozenset[str]]


def _broker_installed() -> bool:
    """Report whether the Windows authentication broker runtime can be used.

    Returns:
        ``True`` on Windows with the ``broker`` extra installed.
    """
    return sys.platform == "win32" and importlib.util.find_spec("pymsalruntime") is not None


def _as_text(value: str | bytes | None) -> str | None:
    """Decode PEM material given as bytes.

    Args:
        value: Text, bytes or ``None``.

    Returns:
        The value as text, or ``None``.
    """
    if isinstance(value, bytes):
        return value.decode("ascii")
    return value


def _build_credential(
    *,
    client_secret: str | None,
    certificate_thumbprint: str | None,
    certificate_store: cng.StoreLocation,
    certificate_pem: str | bytes | None,
    private_key_pem: str | bytes | None,
    certificate_pfx: bytes | str | Path | None,
    certificate_password: str | None,
) -> AppCredential | None:
    """Turn the constructor's credential arguments into one credential object.

    Args:
        client_secret: A client secret.
        certificate_thumbprint: SHA-1 thumbprint of a certificate in the Windows store.
        certificate_store: ``CurrentUser`` or ``LocalMachine``.
        certificate_pem: A certificate in PEM format.
        private_key_pem: The private key for ``certificate_pem``.
        certificate_pfx: A PKCS#12 archive, as bytes or a path.
        certificate_password: Password for ``private_key_pem`` or ``certificate_pfx``.

    Returns:
        The credential, or ``None`` when no credential was given (a user flow).

    Raises:
        ValueError: If more than one kind of credential was given, or a PEM pair is
            incomplete.
    """
    kinds = [
        client_secret is not None,
        certificate_thumbprint is not None,
        certificate_pem is not None or private_key_pem is not None,
        certificate_pfx is not None,
    ]
    if sum(kinds) > 1:
        raise ValueError(
            "Give only one of client_secret, certificate_thumbprint, "
            "certificate_pem/private_key_pem or certificate_pfx"
        )
    if client_secret is not None:
        return SecretCredential(client_secret)
    if certificate_thumbprint is not None:
        return CertStoreCredential(certificate_thumbprint, certificate_store)
    if certificate_pfx is not None:
        return PemCertificateCredential.from_pfx(certificate_pfx, certificate_password)
    if certificate_pem is not None or private_key_pem is not None:
        certificate_text = _as_text(certificate_pem)
        private_key_text = _as_text(private_key_pem)
        if certificate_text is None or private_key_text is None:
            raise ValueError("certificate_pem and private_key_pem must be given together")
        return PemCertificateCredential(certificate_text, private_key_text, certificate_password)
    return None


class AuthContext:
    """Credentials, cache and account for one tenant.

    A context runs either a *user flow* (``username`` given, no credential) or an *app flow*
    (``client_id`` plus a secret or certificate). Authentication is lazy: nothing happens
    until the first token is requested.

    Example:
        >>> auth = AuthContext("contoso.onmicrosoft.com", username="admin@contoso.com")
        >>> token = auth.get_token("https://management.azure.com/.default")  # doctest: +SKIP
    """

    def __init__(
        self,
        tenant_id: str,
        *,
        client_id: str | None = None,
        username: str | None = None,
        client_secret: str | None = None,
        certificate_thumbprint: str | None = None,
        certificate_store: cng.StoreLocation = "CurrentUser",
        certificate_pem: str | bytes | None = None,
        private_key_pem: str | bytes | None = None,
        certificate_pfx: bytes | str | Path | None = None,
        certificate_password: str | None = None,
        cache: CacheKind = "memory",
        cache_path: str | Path | None = None,
        broker: bool = False,
        broker_fallback: bool = True,
        authority_host: str = DEFAULT_AUTHORITY_HOST,
        interactive_timeout: float = _DEFAULT_INTERACTIVE_TIMEOUT_SECONDS,
    ) -> None:
        """Configure the context. No network call is made.

        Args:
            tenant_id: Tenant id (GUID) or verified domain name.
            client_id: Application (client) id. App flows need one, here or on the resource
                client. For user flows it overrides the first-party default of every
                resource client.
            username: User principal name. Required for user flows; selects the cached
                account and pre-fills the sign-in page. Not allowed for app flows.
            client_secret: Client secret for an app flow.
            certificate_thumbprint: SHA-1 thumbprint of a certificate in the Windows
                certificate store (``My``). The private key may be non-exportable.
            certificate_store: ``CurrentUser`` (default) or ``LocalMachine``.
            certificate_pem: Certificate in PEM format, used with ``private_key_pem``.
            private_key_pem: Private key in PEM format.
            certificate_pfx: PKCS#12 archive as bytes or a path.
            certificate_password: Password for ``private_key_pem`` or ``certificate_pfx``.
            cache: ``memory`` (default) or ``disk`` for an encrypted cache file.
            cache_path: Location of the disk cache. Defaults to the per-user cache directory.
            broker: Use the Windows authentication broker (WAM) for user sign-in. Needs the
                ``broker`` extra.
            broker_fallback: When the broker cannot be used, fall back to the browser
                (default) instead of raising :class:`BrokerUnavailable`.
            authority_host: Entra ID authority host, for sovereign clouds.
            interactive_timeout: Seconds a browser sign-in waits for the person before it
                fails with :class:`AuthError` (default 120). A closed window would otherwise
                wait for ever.

        Raises:
            ValueError: If the arguments do not describe exactly one flow.
            CacheEncryptionUnavailable: If ``cache='disk'`` cannot be encrypted here.
            CertificateUnavailable: If a PFX archive cannot be read.
        """
        if not tenant_id:
            raise ValueError("tenant_id is required")
        credential = _build_credential(
            client_secret=client_secret,
            certificate_thumbprint=certificate_thumbprint,
            certificate_store=certificate_store,
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem,
            certificate_pfx=certificate_pfx,
            certificate_password=certificate_password,
        )
        if credential is None and not username:
            raise ValueError("username is required for user flows")
        if credential is not None:
            if username:
                raise ValueError("username is not used for app flows")
            if broker:
                raise ValueError("broker is only available for user flows")

        self._tenant_id = tenant_id
        self._client_id = client_id
        self._username = username
        self._credential = credential
        self._cache = build_cache(cache, cache_path)
        self._broker = broker
        self._broker_fallback = broker_fallback
        self._authority_host = authority_host.rstrip("/")
        self._interactive_timeout = interactive_timeout
        self._interactive_allowed = True
        self._init_state()

    def _init_state(self) -> None:
        """Create the per-context mutable state."""
        self._apps: dict[tuple[str, bool], Any] = {}
        self._locks: dict[_TokenKey, threading.Lock] = {}
        self._tokens: dict[_TokenKey, AccessTokenInfo] = {}
        self._siblings: dict[str, AuthContext] = {}
        self._guard = threading.Lock()
        self._aio: AsyncAuthContext | None = None

    def __repr__(self) -> str:
        """Describe the context without revealing credentials.

        Returns:
            A short description.
        """
        flow = "app" if self.is_app_flow else "user"
        return f"AuthContext(tenant_id={self._tenant_id!r}, flow={flow!r})"

    # ------------------------------------------------------------------ properties

    @property
    def tenant_id(self) -> str:
        """The tenant this context authenticates against."""
        return self._tenant_id

    @property
    def client_id(self) -> str | None:
        """The client id given to this context, if any."""
        return self._client_id

    @property
    def username(self) -> str | None:
        """The user principal name of a user flow, or ``None`` for an app flow."""
        return self._username

    @property
    def is_app_flow(self) -> bool:
        """Whether this context authenticates as an application."""
        return self._credential is not None

    @property
    def is_sibling(self) -> bool:
        """Whether this context was created by :meth:`for_tenant` and so never prompts."""
        return not self._interactive_allowed

    @property
    def authority(self) -> str:
        """The authority URL for this tenant."""
        return f"{self._authority_host}/{self._tenant_id}"

    @property
    def token_endpoint(self) -> str:
        """The v2.0 token endpoint for this tenant."""
        return f"{self.authority}/oauth2/v2.0/token"

    @property
    def aio(self) -> AsyncAuthContext:
        """The asynchronous view of this context (an ``AsyncTokenCredential``)."""
        if self._aio is None:
            self._aio = AsyncAuthContext(self)
        return self._aio

    # ------------------------------------------------------------------ tenants

    def for_tenant(self, tenant_id: str) -> AuthContext:
        """Return a sibling context for another tenant.

        The sibling shares this context's credentials, cache and username, so a partner user
        with GDAP access obtains customer-tenant tokens from the one sign-in. No network call
        is made. A sibling never opens a browser: when a token cannot be obtained silently it
        raises :class:`InteractionRequired` or :class:`ConsentRequired` carrying the tenant
        id.

        Args:
            tenant_id: Tenant id (GUID) or verified domain name of the other tenant.

        Returns:
            The sibling context. Repeated calls return the same object.
        """
        if tenant_id.lower() == self._tenant_id.lower():
            return self
        with self._guard:
            sibling = self._siblings.get(tenant_id.lower())
            if sibling is None:
                sibling = AuthContext.__new__(AuthContext)
                sibling._tenant_id = tenant_id
                sibling._client_id = self._client_id
                sibling._username = self._username
                sibling._credential = self._credential
                sibling._cache = self._cache
                sibling._broker = self._broker
                sibling._broker_fallback = self._broker_fallback
                sibling._authority_host = self._authority_host
                sibling._interactive_timeout = self._interactive_timeout
                sibling._interactive_allowed = False
                sibling._init_state()
                self._siblings[tenant_id.lower()] = sibling
            return sibling

    # ------------------------------------------------------------------ public token API

    def get_token(
        self,
        *scopes: str,
        claims: str | None = None,
        tenant_id: str | None = None,
        enable_cae: bool = False,
        **kwargs: Any,
    ) -> AccessToken:
        """Request an access token (Azure SDK ``TokenCredential`` protocol).

        Args:
            *scopes: Scopes to request, normally one ``<resource>/.default`` value.
            claims: Claims challenge returned by a resource, as a JSON string.
            tenant_id: Tenant to request the token from. A tenant other than this context's
                is served by :meth:`for_tenant`.
            enable_cae: Accepted for protocol compatibility and ignored.
            **kwargs: Ignored.

        Returns:
            The token and its expiry time.
        """
        context = self.for_tenant(tenant_id or self._tenant_id)
        info = context.acquire_token(scopes, claims=claims)
        return AccessToken(info.token, info.expires_on)

    def get_token_info(
        self, *scopes: str, options: TokenRequestOptions | None = None
    ) -> AccessTokenInfo:
        """Request an access token (Azure SDK ``SupportsTokenInfo`` protocol).

        Args:
            *scopes: Scopes to request, normally one ``<resource>/.default`` value.
            options: ``claims`` and ``tenant_id`` are honoured; ``enable_cae`` is ignored.

        Returns:
            The token with its expiry time and type.
        """
        options = options or {}
        context = self.for_tenant(options.get("tenant_id") or self._tenant_id)
        return context.acquire_token(scopes, claims=options.get("claims"))

    def acquire_token(
        self,
        scopes: Iterable[str],
        *,
        client_id: str | None = None,
        claims: str | None = None,
        force_refresh: bool = False,
    ) -> AccessTokenInfo:
        """Acquire a token, signing in first when that is needed and allowed.

        This is what resource clients call. Concurrent calls for the same client id and
        scopes are serialised, so a cold start opens one browser window, not many.

        Args:
            scopes: Scopes to request.
            client_id: Client id to use. Defaults to the context's client id, then (user
                flows only) to the Azure PowerShell client id.
            claims: Claims challenge to satisfy, as a JSON string.
            force_refresh: Skip cached access tokens.

        Returns:
            The token with its expiry time and type.

        Raises:
            InteractionRequired: If the user must sign in and this context may not prompt.
            ConsentRequired: If consent is missing in the tenant.
            AuthError: For any other failure.
        """
        return self._acquire(scopes, client_id, claims, force_refresh, force_interactive=False)

    def login(self, *, client_id: str, scopes: Iterable[str], force: bool = False) -> None:
        """Sign in now instead of at the first request.

        Resource clients call this from their own ``login()`` with their client id and
        scopes. Calling it is optional, because the first token request signs in anyway.

        Args:
            client_id: Client id to sign in to.
            scopes: Scopes to request.
            force: Prompt even when a cached token or account exists. Ignored by app flows.

        Raises:
            InteractionRequired: If this is a sibling context and the user must sign in.
        """
        self._acquire(scopes, client_id, None, force, force_interactive=force)

    # ------------------------------------------------------------------ internals

    def resolve_client_id(self, client_id: str | None = None) -> str:
        """Apply the client id precedence rule for a bare token request.

        Args:
            client_id: Client id chosen by the caller, if any.

        Returns:
            ``client_id``, else the context's client id, else (user flows) the Azure
            PowerShell client id.

        Raises:
            ValueError: If an app flow has no client id.
        """
        resolved = client_id or self._client_id
        if resolved:
            return resolved
        if self.is_app_flow:
            raise ValueError("App flows need a client_id; first-party client ids cannot be used")
        return AZURE_POWERSHELL_CLIENT_ID

    def cached_token(self, scopes: Iterable[str], client_id: str | None) -> AccessTokenInfo | None:
        """Return a still-fresh token from the in-process memo, without locking.

        Args:
            scopes: Scopes the token was requested for.
            client_id: Client id the token was requested with.

        Returns:
            The token, or ``None`` when there is none or it is close to expiry.
        """
        key = (self.resolve_client_id(client_id), frozenset(scopes))
        info = self._tokens.get(key)
        if info is not None and info.expires_on - time.time() > _REFRESH_MARGIN_SECONDS:
            return info
        return None

    def _acquire(
        self,
        scopes: Iterable[str],
        client_id: str | None,
        claims: str | None,
        force_refresh: bool,
        *,
        force_interactive: bool,
    ) -> AccessTokenInfo:
        """Acquire a token under the single-flight lock for its key.

        Args:
            scopes: Scopes to request.
            client_id: Client id chosen by the caller, if any.
            claims: Claims challenge to satisfy.
            force_refresh: Skip cached access tokens.
            force_interactive: Prompt even when a silent token is available.

        Returns:
            The token with its expiry time and type.
        """
        scope_list = list(dict.fromkeys(scopes))
        if not scope_list:
            raise ValueError("At least one scope is required")
        resolved = self.resolve_client_id(client_id)
        key: _TokenKey = (resolved, frozenset(scope_list))
        with self._guard:
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:
            if not (claims or force_refresh or force_interactive):
                cached = self.cached_token(scope_list, resolved)
                if cached is not None:
                    return cached
            if self.is_app_flow:
                result = self._acquire_for_app(resolved, scope_list, claims, force_refresh)
            else:
                result = self._acquire_for_user(
                    resolved, scope_list, claims, force_refresh, force_interactive
                )
            info = AccessTokenInfo(
                str(result["access_token"]),
                int(time.time()) + int(result.get("expires_in", 0)),
                token_type=str(result.get("token_type", "Bearer")),
            )
            self._tokens[key] = info
            return info

    def _app(self, client_id: str, *, use_broker: bool = False) -> Any:
        """Return the memoised MSAL application for a client id.

        Args:
            client_id: Client id of the application.
            use_broker: Whether the application should use the Windows broker.

        Returns:
            An ``msal.PublicClientApplication`` or ``msal.ConfidentialClientApplication``.
        """
        key = (client_id, use_broker)
        app = self._apps.get(key)
        if app is None:
            if self._credential is not None:
                app = msal.ConfidentialClientApplication(
                    client_id,
                    client_credential=self._credential.msal_client_credential(
                        client_id=client_id, token_endpoint=self.token_endpoint
                    ),
                    authority=self.authority,
                    token_cache=self._cache,
                )
            elif use_broker:
                app = msal.PublicClientApplication(
                    client_id,
                    authority=self.authority,
                    token_cache=self._cache,
                    enable_broker_on_windows=True,
                )
            else:
                app = msal.PublicClientApplication(
                    client_id, authority=self.authority, token_cache=self._cache
                )
            with self._guard:
                app = self._apps.setdefault(key, app)
        return app

    def _acquire_for_app(
        self, client_id: str, scopes: list[str], claims: str | None, force_refresh: bool
    ) -> dict[str, Any]:
        """Run the client credentials flow.

        Args:
            client_id: Client id of the application.
            scopes: Scopes to request; ``<resource>/.default`` for this flow.
            claims: Claims challenge to satisfy.
            force_refresh: Drop cached tokens for this client first.

        Returns:
            The successful MSAL result.
        """
        app = self._app(client_id)
        if force_refresh:
            app.remove_tokens_for_client()
        result = app.acquire_token_for_client(scopes, claims_challenge=claims)
        if "access_token" not in result:
            raise error_from_msal_result(result, tenant_id=self._tenant_id, scopes=scopes)
        return dict(result)

    def _broker_usable(self) -> bool:
        """Decide whether to use the Windows broker for this context.

        Returns:
            ``True`` when the broker was requested and can be used.

        Raises:
            BrokerUnavailable: If the broker was requested, cannot be used, and
                ``broker_fallback`` is off.
        """
        if not self._broker:
            return False
        if _broker_installed():
            return True
        if not self._broker_fallback:
            raise BrokerUnavailable(
                "The authentication broker needs Windows and the 'broker' extra "
                "(pip install azure-auth[broker])"
            )
        _LOGGER.warning("Authentication broker unavailable; falling back to the browser")
        return False

    def _acquire_for_user(
        self,
        client_id: str,
        scopes: list[str],
        claims: str | None,
        force_refresh: bool,
        force_interactive: bool,
    ) -> dict[str, Any]:
        """Get a user token: silently if possible, interactively if allowed.

        Args:
            client_id: Client id of the public client application.
            scopes: Scopes to request.
            claims: Claims challenge to satisfy.
            force_refresh: Skip cached access tokens.
            force_interactive: Prompt even when a silent token is available.

        Returns:
            The successful MSAL result.
        """
        use_broker = self._broker_usable()
        app = self._app(client_id, use_broker=use_broker)
        result: dict[str, Any] | None = None
        if not force_interactive:
            accounts = app.get_accounts(username=self._username)
            if len(accounts) > 1:
                raise AccountSelectionRequired(
                    f"{len(accounts)} cached accounts match {self._username!r}"
                )
            if accounts:
                result = app.acquire_token_silent_with_error(
                    scopes,
                    account=accounts[0],
                    claims_challenge=claims,
                    force_refresh=force_refresh,
                )
            if result and "access_token" in result:
                return dict(result)

        if not self._interactive_allowed:
            error = error_from_msal_result(result, tenant_id=self._tenant_id, scopes=scopes)
            if isinstance(error, InteractionRequired):
                raise InteractionRequired(
                    f"{error} Sibling contexts never prompt; call login() on a client of the "
                    "root context first.",
                    tenant_id=self._tenant_id,
                    scopes=scopes,
                )
            raise error

        # Entra puts up its own consent screen when an application has not been granted the
        # scopes being asked for, so consent is handled by the ordinary sign-in and needs
        # nothing from this package. A retry with prompt=consent was tried here and removed:
        # measured against a live tenant on 2026-09-20, a user who may not consent is shown
        # "Need admin approval" and leaving that page returns a bare access_denied, which no
        # retry can fix. Pressing Cancel on the consent screen returns consent_required with
        # AADSTS65004 (measured 2026-09-25), which is the user's decision. Reopening the
        # browser on either would be wrong, and the retry could never fire in the case it was
        # written for.
        result = self._interactive(client_id, scopes, claims, use_broker=use_broker)
        if "access_token" not in result:
            raise error_from_msal_result(result, tenant_id=self._tenant_id, scopes=scopes)
        self._check_signed_in_user(result)
        return result

    def _interactive(
        self, client_id: str, scopes: list[str], claims: str | None, *, use_broker: bool
    ) -> dict[str, Any]:
        """Prompt the user, through the broker when enabled, else in the browser.

        Args:
            client_id: Client id of the public client application.
            scopes: Scopes to request.
            claims: Claims challenge to satisfy.
            use_broker: Whether to try the Windows broker first.

        Returns:
            The MSAL result, successful or not.

        Raises:
            BrokerUnavailable: If the broker fails and ``broker_fallback`` is off.
        """
        if use_broker:
            broker_app = self._app(client_id, use_broker=True)
            try:
                result = broker_app.acquire_token_interactive(
                    scopes,
                    login_hint=self._username,
                    claims_challenge=claims,
                    parent_window_handle=broker_app.CONSOLE_WINDOW_HANDLE,
                )
            except Exception as exc:
                if not self._broker_fallback:
                    raise BrokerUnavailable(f"The authentication broker failed: {exc}") from exc
                _LOGGER.warning("Authentication broker failed (%s); using the browser", exc)
            else:
                if "access_token" in result or result.get("error") != "broker_error":
                    return dict(result)
                if not self._broker_fallback:
                    raise BrokerUnavailable(
                        f"The authentication broker failed: {result.get('error_description')}"
                    )
                _LOGGER.warning("Authentication broker failed; using the browser")

        app = self._app(client_id, use_broker=False)
        try:
            result = app.acquire_token_interactive(
                scopes,
                login_hint=self._username,
                claims_challenge=claims,
                timeout=self._interactive_timeout,
            )
        except BrowserInteractionTimeoutError as exc:
            raise AuthError(
                f"The browser sign-in was not completed within {self._interactive_timeout:g} "
                "seconds. The window was probably closed, or nobody was there to answer it."
            ) from exc
        return dict(result)

    def _check_signed_in_user(self, result: dict[str, Any]) -> None:
        """Make sure the person who signed in is the configured user.

        Args:
            result: A successful MSAL result.

        Raises:
            AuthError: If somebody else signed in. Their tokens would never be found again,
                because cached accounts are selected by username.
        """
        signed_in = (result.get("id_token_claims") or {}).get("preferred_username")
        if signed_in and self._username and signed_in.lower() != self._username.lower():
            raise AuthError(
                f"Signed in as {signed_in!r}, but this context is configured for {self._username!r}"
            )


class AsyncAuthContext:
    """Asynchronous view of an :class:`AuthContext` (an ``AsyncTokenCredential``).

    MSAL is synchronous, so token requests run in a worker thread. Tokens that are still
    fresh are returned without leaving the event loop.
    """

    def __init__(self, sync_context: AuthContext) -> None:
        """Wrap a synchronous context.

        Args:
            sync_context: The context that does the work.
        """
        self._sync = sync_context

    @property
    def sync(self) -> AuthContext:
        """The synchronous context behind this view."""
        return self._sync

    def for_tenant(self, tenant_id: str) -> AsyncAuthContext:
        """Return the asynchronous view of a sibling context.

        Args:
            tenant_id: Tenant id (GUID) or verified domain name of the other tenant.

        Returns:
            The sibling's asynchronous view.
        """
        return self._sync.for_tenant(tenant_id).aio

    async def get_token(
        self,
        *scopes: str,
        claims: str | None = None,
        tenant_id: str | None = None,
        enable_cae: bool = False,
        **kwargs: Any,
    ) -> AccessToken:
        """Request an access token (Azure SDK ``AsyncTokenCredential`` protocol).

        Args:
            *scopes: Scopes to request, normally one ``<resource>/.default`` value.
            claims: Claims challenge returned by a resource, as a JSON string.
            tenant_id: Tenant to request the token from.
            enable_cae: Accepted for protocol compatibility and ignored.
            **kwargs: Ignored.

        Returns:
            The token and its expiry time.
        """
        view = self.for_tenant(tenant_id or self._sync.tenant_id)
        info = await view.acquire_token(scopes, claims=claims)
        return AccessToken(info.token, info.expires_on)

    async def get_token_info(
        self, *scopes: str, options: TokenRequestOptions | None = None
    ) -> AccessTokenInfo:
        """Request an access token (Azure SDK ``AsyncSupportsTokenInfo`` protocol).

        Args:
            *scopes: Scopes to request, normally one ``<resource>/.default`` value.
            options: ``claims`` and ``tenant_id`` are honoured; ``enable_cae`` is ignored.

        Returns:
            The token with its expiry time and type.
        """
        options = options or {}
        view = self.for_tenant(options.get("tenant_id") or self._sync.tenant_id)
        return await view.acquire_token(scopes, claims=options.get("claims"))

    async def acquire_token(
        self,
        scopes: Sequence[str],
        *,
        client_id: str | None = None,
        claims: str | None = None,
        force_refresh: bool = False,
    ) -> AccessTokenInfo:
        """Acquire a token; see :meth:`AuthContext.acquire_token`.

        Args:
            scopes: Scopes to request.
            client_id: Client id to use.
            claims: Claims challenge to satisfy, as a JSON string.
            force_refresh: Skip cached access tokens.

        Returns:
            The token with its expiry time and type.
        """
        if not (claims or force_refresh):
            cached = self._sync.cached_token(scopes, client_id)
            if cached is not None:
                return cached
        return await asyncio.to_thread(
            self._sync.acquire_token,
            scopes,
            client_id=client_id,
            claims=claims,
            force_refresh=force_refresh,
        )

    async def login(self, *, client_id: str, scopes: Sequence[str], force: bool = False) -> None:
        """Sign in now; see :meth:`AuthContext.login`.

        Args:
            client_id: Client id to sign in to.
            scopes: Scopes to request.
            force: Prompt even when a cached token or account exists.
        """
        await asyncio.to_thread(self._sync.login, client_id=client_id, scopes=scopes, force=force)

    async def close(self) -> None:
        """Do nothing; present for the ``AsyncTokenCredential`` protocol."""

    async def __aenter__(self) -> Self:
        """Enter the context manager.

        Returns:
            This object.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        """Leave the context manager."""
        await self.close()
