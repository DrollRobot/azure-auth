"""The authentication context shared by every resource client.

An :class:`AuthContext` holds one tenant (with its cloud), one set of credentials, one token
cache and (for user flows) one account. It creates MSAL applications on demand, one per client id,
because the Microsoft first-party client ids differ per resource. A managed identity context
holds no credential at all: the Azure host it runs on issues its tokens.

The context implements the Azure SDK ``TokenCredential`` protocol, and its :attr:`aio`
attribute implements ``AsyncTokenCredential``, so any ``azure-*`` SDK client accepts it as
``credential=``.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import importlib.util
import json
import logging
import sys
import threading
import time
import webbrowser
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import msal
import requests
from azure.core.credentials import AccessToken, AccessTokenInfo, TokenRequestOptions
from msal import BrowserInteractionTimeoutError, TokenCache
from msal import managed_identity as msal_managed_identity
from msal.exceptions import MsalServiceError

# Not exported from msal. The only way to choose a browser per sign-in on Windows, where
# acquire_token_interactive always uses the default; see .local/DECISIONS.md.
from msal.oauth2cli.authcode import AuthCodeReceiver
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from azure_auth.auth import cng
from azure_auth.auth.cache import CacheKind, DiskTokenCache, build_cache
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
    ManagedIdentityUnavailable,
    broker_status,
    entra_error_codes,
    error_from_msal_result,
    with_entra_answer,
)
from azure_auth.auth.tenant import MULTI_TENANT_AUTHORITIES, Tenant, as_guid
from azure_auth.clouds import Cloud, get_cloud
from azure_auth.constants import AZURE_POWERSHELL_CLIENT_ID
from azure_auth.errors import network_error

_LOGGER = logging.getLogger(__name__)

# A cached token is reused until it is this close to expiry.
_REFRESH_MARGIN_SECONDS = 300

# What every MSAL application tells Entra it can do. ``CP1`` means "I handle claims
# challenges": the clients answer a 401 that carries one by signing in again with its claims
# (clients/base.py). Without it no resource ever sends a challenge, and a token simply runs
# until it expires. With it, Graph and Exchange issue long-lived tokens and revoke them within
# minutes of an account being disabled, a password change or a forced sign-out: continuous
# access evaluation.
_CLIENT_CAPABILITIES = ["CP1"]

# How long a browser sign-in waits for the person before it is abandoned, unless the context
# is given ``browser_timeout``. Without a limit, a closed browser window leaves MSAL
# waiting for a redirect that never arrives.
_DEFAULT_BROWSER_TIMEOUT_SECONDS = 120

_TokenKey = tuple[str, frozenset[str]]

# The client id a managed identity's tokens are remembered under. The identity endpoint takes
# no client id for a system-assigned identity, and a user-assigned identity's is fixed, so one
# key serves the flow.
_MANAGED_IDENTITY_KEY = "managed-identity"

# The identity endpoint is on the host itself (``localhost``, or the link-local instance
# metadata address), so it answers at once or not at all: a short wait to connect tells a host
# without an endpoint from one with. The read timeout covers the endpoint asking Entra ID.
_IDENTITY_CONNECT_TIMEOUT_SECONDS = 2.0
_IDENTITY_READ_TIMEOUT_SECONDS = 10.0
_IMDS_HOST = "169.254.169.254"

# What each of msal's identity endpoints is called in messages.
_IDENTITY_SOURCES: dict[int, str] = {
    id(msal_managed_identity.APP_SERVICE): "App Service (IDENTITY_ENDPOINT)",
    id(msal_managed_identity.SERVICE_FABRIC): "Service Fabric (IDENTITY_ENDPOINT)",
    id(msal_managed_identity.MACHINE_LEARNING): "Azure Machine Learning (MSI_ENDPOINT)",
    id(msal_managed_identity.AZURE_ARC): "Azure Arc",
    id(msal_managed_identity.CLOUD_SHELL): "Cloud Shell",
    id(msal_managed_identity.DEFAULT_TO_VM): f"instance metadata ({_IMDS_HOST})",
}

# MSAL's ``token_source`` for a token Entra issued in that request, through a sign-in or the
# refresh token; the others are its cache and the Windows broker, which has a cache of its own.
_SOURCE_ENTRA = "identity_provider"

# The broker's status for a person who closed its sign-in window (seen live 2026-09-29).
_BROKER_CANCELLED_STATUS = "Status_UserCanceled"

# The names this process has registered browsers under with ``webbrowser``. Each registration
# appends to webbrowser's try order, so a command is registered once, not at every sign-in.
_registered_browsers: set[str] = set()


def _lookup_clouds(clouds: Iterable[Cloud | str] | None) -> tuple[Cloud, ...] | None:
    """Resolve ``lookup_clouds`` now, so a wrong name fails the constructor, not a lookup.

    Args:
        clouds: Clouds or cloud names, or ``None`` for every cloud.

    Returns:
        The clouds, or ``None`` for the lookup's default.

    Raises:
        ValueError: If ``clouds`` is empty or names an unknown cloud.
    """
    if clouds is None:
        return None
    resolved = tuple(get_cloud(cloud) for cloud in clouds)
    if not resolved:
        raise ValueError("lookup_clouds names no cloud whose sign-in host to ask")
    return resolved


def _browser_command(browser: str | Path | Sequence[str]) -> tuple[str, ...]:
    """Turn the ``browser`` argument into a program and its arguments.

    Args:
        browser: A program, as a name on ``PATH`` or a path, or a sequence of the program
            followed by its arguments.

    Returns:
        The program followed by its arguments.

    Raises:
        ValueError: If no program is named.
    """
    command = (str(browser),) if isinstance(browser, str | Path) else tuple(browser)
    if not command or not command[0]:
        raise ValueError("browser must name a program")
    return command


def _register_browser(command: tuple[str, ...]) -> str:
    """Register a browser command with ``webbrowser``, leaving the default browser alone.

    Args:
        command: The program followed by its arguments.

    Returns:
        The name the command is registered under, for MSAL's ``browser_name``. It never
        contains ``%s``, which ``webbrowser.get`` would read as a command line.
    """
    digest = hashlib.sha256("\0".join(command).encode()).hexdigest()[:16]
    name = f"azure-auth-{digest}"
    if name not in _registered_browsers:
        # Not preferred, so it goes to the end of the try order and the default stays first.
        # "%s" is where webbrowser puts the sign-in address.
        webbrowser.register(name, None, webbrowser.BackgroundBrowser([*command, "%s"]))
        _registered_browsers.add(name)
    return name


def _broker_installed() -> bool:
    """Report whether the Windows authentication broker runtime can be used.

    Returns:
        ``True`` on Windows with the ``broker`` extra installed.
    """
    return sys.platform == "win32" and importlib.util.find_spec("pymsalruntime") is not None


def _broker_failed(result: dict[str, Any]) -> bool:
    """Tell a broker that could not sign the person in from a person who said no.

    Args:
        result: What the broker's interactive sign-in returned.

    Returns:
        ``True`` when the broker failed, so the browser may take over. ``False`` for a token,
        for a cancel, which is the person's answer and must not open a browser, and for an
        error from Entra.
    """
    if result.get("error") != "broker_error":
        return False
    return broker_status(result) != _BROKER_CANCELLED_STATUS


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


class _IdentitySession(requests.Session):
    """The session a managed identity's token requests go through.

    msal sends through whatever session it is given and sets no timeout, and a plain
    ``requests.Session`` waits for ever; off Azure, the instance metadata address never
    answers. This session puts a timeout on every request, retries a throttled or failing
    answer twice, honouring ``Retry-After``, and never retries a connection that could not be
    made. It ignores the environment's proxy settings: the endpoint is on the host itself.
    """

    def __init__(self) -> None:
        """Create the session."""
        super().__init__()
        self.trust_env = False
        retry = Retry(
            total=2,
            connect=0,
            read=0,
            status=2,
            status_forcelist=(429, 500, 502, 503, 504),
            backoff_factor=0.5,
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        self.mount("https://", HTTPAdapter(max_retries=retry))
        self.mount("http://", HTTPAdapter(max_retries=retry))

    def request(
        self, method: str | bytes, url: str | bytes, *args: Any, **kwargs: Any
    ) -> requests.Response:
        """Send a request, with the endpoint's timeout unless the caller set one.

        Args:
            method: HTTP method.
            url: The URL.
            *args: ``requests.Session.request`` arguments.
            **kwargs: ``requests.Session.request`` arguments.

        Returns:
            The response.
        """
        kwargs.setdefault(
            "timeout", (_IDENTITY_CONNECT_TIMEOUT_SECONDS, _IDENTITY_READ_TIMEOUT_SECONDS)
        )
        return super().request(method, url, *args, **kwargs)


def _managed_identity_http_client() -> requests.Session:
    """Create the session a managed identity client sends through.

    Returns:
        An :class:`_IdentitySession`. Tests replace this function to answer the endpoint.
    """
    return _IdentitySession()


def _identity_source_name() -> str:
    """Name the identity endpoint msal would use on this host.

    Returns:
        The endpoint's name, for messages.
    """
    source = msal_managed_identity.get_managed_identity_source()
    return _IDENTITY_SOURCES.get(id(source), "managed identity")


def _resource_from_scopes(scopes: Sequence[str]) -> str:
    """Turn a token request's scopes into the resource the identity endpoint takes.

    Args:
        scopes: The scopes requested.

    Returns:
        The resource: the one scope without its ``/.default``. A trailing slash before it
        stays, so ``https://management.core.windows.net//.default`` gives the resource with
        the slash it is registered with.

    Raises:
        ValueError: If there is not exactly one scope, or it is not ``<resource>/.default``.
    """
    suffix = "/.default"
    if len(scopes) != 1 or not scopes[0].endswith(suffix) or len(scopes[0]) == len(suffix):
        raise ValueError(
            "A managed identity gets a token for one resource at a time, requested as "
            f"'<resource>/.default'; got {list(scopes)!r}"
        )
    return scopes[0][: -len(suffix)]


def _token_claims(token: str) -> dict[str, Any]:
    """Read the claims of an access token, without validating it.

    Args:
        token: A JWT access token.

    Returns:
        The payload's claims, or nothing when the token cannot be decoded.
    """
    parts = token.split(".")
    if len(parts) < 2:  # a JWT is header.payload[.signature]
        return {}
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (binascii.Error, ValueError):
        return {}
    return dict(payload) if isinstance(payload, dict) else {}


@dataclass(frozen=True)
class _Given:
    """What a context was built with, as the context uses it.

    The constructor's arguments, each in the form the rest of the context works with: the
    credential as an object, the cache built, the browser as a command. Frozen, so a context
    from :meth:`AuthContext.get_tenant_context` shares its parent's by reference: the child
    differs from the parent in its tenant and in whether it may prompt, in nothing it was
    given.

    Attributes:
        tenant: The tenant as given, a string to look up or a :class:`Tenant`; ``None`` for a
            managed identity given its cloud instead.
        cloud: The cloud as given, for a managed identity; else ``None``.
        managed_identity: Whether the context signs in as the host's managed identity.
        client_id: The client id, or ``None``.
        username: The user principal name of a user flow, or ``None``.
        credential: The app flow's credential, or ``None`` for a user flow.
        cache: The MSAL token cache every application of the context writes to.
        broker: Whether to use the Windows authentication broker.
        broker_fallback: Whether the browser may stand in for a broker that cannot be used.
        browser_timeout: Seconds a browser sign-in waits for the person.
        browser: The browser command, or ``None`` for the system default.
        before_browser_opens: Called right before each browser window opens, or ``None``.
        lookup_clouds: The clouds whose sign-in hosts lookups ask, or ``None`` for all.
    """

    tenant: str | Tenant | None
    cloud: Cloud | None
    managed_identity: bool
    client_id: str | None
    username: str | None
    credential: AppCredential | None
    cache: Any
    broker: bool
    broker_fallback: bool
    browser_timeout: float
    browser: tuple[str, ...] | None
    before_browser_opens: Callable[[], object] | None
    lookup_clouds: tuple[Cloud, ...] | None


class AuthContext:
    """Credentials, cache and account for one tenant.

    A context runs one of three flows: a *user flow* (``username`` given, no credential), an
    *app flow* (``client_id`` plus a secret or certificate), or a *managed identity flow*
    (``managed_identity=True``, on an Azure host, with no credential at all). Authentication
    is lazy: nothing happens until the first token is requested.

    Everything known about the tenant is in :attr:`tenant`, a :class:`Tenant`: its GUID, its
    cloud, a domain name and its OpenID Connect configuration. Given a GUID or domain name,
    the context looks the tenant up itself, so a tenant in any Microsoft cloud works without
    saying which. Given a :class:`Tenant`, it uses it as it is. A managed identity can be
    given its cloud instead, and learns its tenant from its first token.

    Example:
        >>> auth = AuthContext("contoso.com", username="admin@contoso.com")  # doctest: +SKIP
        >>> token = auth.get_token("https://management.azure.com/.default")  # doctest: +SKIP
    """

    def __init__(
        self,
        tenant: str | Tenant | None = None,
        *,
        cloud: Cloud | str | None = None,
        managed_identity: bool = False,
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
        browser_timeout: float = _DEFAULT_BROWSER_TIMEOUT_SECONDS,
        browser: str | Path | Sequence[str] | None = None,
        before_browser_opens: Callable[[], object] | None = None,
        lookup_clouds: Iterable[Cloud | str] | None = None,
    ) -> None:
        """Configure the context, looking the tenant up when it is given as a string.

        The lookup (:meth:`Tenant.lookup`) is one unauthenticated request to each public
        sign-in host, all three unless ``lookup_clouds`` says otherwise, made at the same
        time. Nothing else touches the network until the first token is requested.

        Args:
            tenant: Tenant id (GUID) or verified domain name, to look up; or a
                :class:`Tenant`, used as it is. Build a :class:`Tenant` by hand, with the
                GUID and the cloud, to skip the lookup; a wrong cloud then fails when used:
                an app sign-in at once, a user's at the first request. Required, except for a
                managed identity given ``cloud`` instead.
            cloud: For a managed identity only: the cloud, as a :class:`~azure_auth.Cloud`
                or its name, in place of ``tenant``. No lookup is made; the tenant's GUID is
                read from the first token. A managed identity has tokens for its own tenant
                only, so the GUID is never needed to get one; the clients need the cloud, for
                their hosts. Give ``tenant`` instead when in doubt: it works for every flow.
            managed_identity: Sign in as the managed identity of the Azure host this process
                runs on: a virtual machine, a Container Apps job, App Service, Functions,
                Azure Arc or Service Fabric. The host's identity endpoint issues the tokens;
                there is no credential to give and nothing is written to disk. ``client_id``
                names a user-assigned identity; without it, the host's system-assigned
                identity is used. Nothing is read from the environment to choose the
                identity. Tokens are requested for one resource at a time, as
                ``<resource>/.default``. Never falls back to another flow.
            client_id: Application (client) id. App flows need one, here or on the resource
                client. For user flows it overrides the first-party default of every
                resource client. For a managed identity, the client id of a user-assigned
                identity; leave it out for the system-assigned identity.
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
            cache: ``memory`` (default) or ``disk`` for an encrypted cache file, written by
                :meth:`flush_cache` and when the process exits.
            cache_path: Location of the disk cache. Defaults to the per-user cache directory.
            broker: Use the Windows authentication broker (WAM) for user sign-in. Needs the
                ``broker`` extra. Turns on the broker's PII logging, for the whole process, so
                its errors carry Entra's reason. The broker's DEBUG log records (logger
                ``msal.broker``) then carry usernames, account ids and the account record;
                tokens stay masked. Error messages carry Entra's text, which may name the user.
            broker_fallback: When the broker cannot be used, fall back to the browser
                (default) instead of raising :class:`BrokerUnavailable`.
            browser_timeout: Seconds a browser sign-in waits for the person before it
                fails with :class:`AuthError` (default 120). A closed window would otherwise
                wait for ever.
            browser: The browser for this context's browser sign-ins, in place of the
                system default: a program, as a name on ``PATH`` or (recommended) an absolute
                path, or a list of the program followed by its arguments, such as
                ``[edge_path, "--profile-directory=Profile 2"]``. The sign-in
                address is added as the last argument. Other contexts keep the default.
            before_browser_opens: A function, taking no arguments, called right before each
                browser sign-in window opens, on the thread signing in. It is not called when
                the cache or the broker answers. Its return value is ignored; an exception it
                raises fails the sign-in, and no window opens.
            lookup_clouds: The clouds whose sign-in hosts the lookups ask, here and in
                :meth:`get_tenant_context`, as :class:`~azure_auth.Cloud` constants or
                names. All of them by default. Leave out a cloud no tenant of yours is in,
                such as China from a network that cannot reach it.

        Raises:
            ValueError: If the arguments do not describe exactly one flow, ``browser`` or
                ``before_browser_opens`` is given for an app flow, ``browser`` names no
                program, ``lookup_clouds`` is empty or names an unknown cloud, ``tenant``
                is a multi-tenant authority such as ``organizations``, which has nothing to
                look up: build its :class:`Tenant` by hand; or a managed identity is given
                neither ``tenant`` nor ``cloud``, or both, or any sign-in argument, or
                ``cloud`` is given for another flow.
            CacheEncryptionUnavailable: If ``cache='disk'`` cannot be encrypted here.
            CertificateUnavailable: If a PFX archive cannot be read.
            TenantNotFound: If the lookup finds no such tenant.
            AmbiguousTenant: If the lookup finds a different tenant in each of two clouds;
                look it up with :meth:`Tenant.lookup` and the cloud of the one you mean.
            NetworkError: If the lookup finds no tenant and a sign-in host that might know it
                could not be reached.
            AuthError: If the lookup gets an answer it cannot use.
        """
        if managed_identity:
            if tenant is None and cloud is None:
                raise ValueError("A managed identity needs tenant= or cloud=")
            if tenant is not None and cloud is not None:
                raise ValueError("Give a managed identity tenant= or cloud=, not both")
            if any(
                value is not None
                for value in (
                    client_secret,
                    certificate_thumbprint,
                    certificate_pem,
                    private_key_pem,
                    certificate_pfx,
                )
            ):
                raise ValueError("A managed identity has no secret or certificate to give")
        elif cloud is not None:
            raise ValueError(
                "cloud= is only for managed_identity=True; a tenant's cloud is looked up"
            )
        elif not tenant:
            raise ValueError("tenant is required")
        if isinstance(tenant, str) and tenant.lower() in MULTI_TENANT_AUTHORITIES:
            raise ValueError(
                f"{tenant!r} names no single tenant to look up; pass Tenant({tenant!r}, cloud)"
            )
        credential = _build_credential(
            client_secret=client_secret,
            certificate_thumbprint=certificate_thumbprint,
            certificate_store=certificate_store,
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem,
            certificate_pfx=certificate_pfx,
            certificate_password=certificate_password,
        )
        if managed_identity:
            if client_id is not None and as_guid(client_id) is None:
                raise ValueError(f"A managed identity's client id is a GUID; got {client_id!r}")
            for name, value in (
                ("username", username),
                ("broker", broker),
                ("browser", browser),
                ("before_browser_opens", before_browser_opens),
            ):
                if value:
                    raise ValueError(f"{name} is not used with a managed identity")
        elif credential is None and not username:
            raise ValueError("username is required for user flows")
        elif credential is not None:
            if username:
                raise ValueError("username is not used for app flows")
            if broker:
                raise ValueError("broker is only available for user flows")
            if browser is not None:
                raise ValueError("browser is only available for user flows")
            if before_browser_opens is not None:
                raise ValueError("before_browser_opens is only available for user flows")

        self._given = _Given(
            tenant=tenant,
            cloud=None if cloud is None else get_cloud(cloud),
            managed_identity=managed_identity,
            client_id=client_id,
            username=username,
            credential=credential,
            cache=build_cache(cache, cache_path),
            broker=broker,
            broker_fallback=broker_fallback,
            browser_timeout=browser_timeout,
            browser=None if browser is None else _browser_command(browser),
            before_browser_opens=before_browser_opens,
            lookup_clouds=_lookup_clouds(lookup_clouds),
        )
        self._can_prompt = True
        self._home = self
        if isinstance(tenant, Tenant):
            self._tenant = tenant
        elif tenant is not None:
            self._tenant = Tenant.lookup(tenant, clouds=self._given.lookup_clouds)
        elif self._given.cloud is not None:
            self._tenant = Tenant(None, self._given.cloud)
        else:  # pragma: no cover (refused above; for the type checker)
            raise ValueError("tenant is required")
        self._init_state()

    def _init_state(self) -> None:
        """Create the per-context mutable state."""
        # A system-assigned identity's client id, read from its first token.
        self._identity_client_id: str | None = None
        self._apps: dict[tuple[str, bool], Any] = {}
        self._locks: dict[_TokenKey, threading.Lock] = {}
        self._recent_tokens: dict[_TokenKey, AccessTokenInfo] = {}
        # Whether the token last returned for a key came from Entra, or from a cache.
        self._from_entra: dict[_TokenKey, bool] = {}
        self._tenant_contexts: dict[str, AuthContext] = {}
        self._lookups: dict[str, Tenant] = {}
        self._guard = threading.Lock()
        self._aio: AsyncAuthContext | None = None

    def __repr__(self) -> str:
        """Describe the context without revealing credentials.

        Returns:
            A short description.
        """
        if self._given.managed_identity:
            flow = "managed_identity"
        else:
            flow = "app" if self.is_app_flow else "user"
        return f"AuthContext(tenant={self._tenant!r}, flow={flow!r})"

    # ------------------------------------------------------------------ properties

    @property
    def tenant(self) -> Tenant:
        """The tenant this context signs in to: its GUID, cloud, domain and OIDC configuration.

        For a managed identity built with ``cloud=``, the GUID is ``None`` until the first
        token names it.
        """
        return self._tenant

    @property
    def client_id(self) -> str | None:
        """The client id given to this context, if any.

        For a system-assigned managed identity, the identity's client id once its first token
        has named it; ``None`` before.
        """
        return self._given.client_id or self._identity_client_id

    @property
    def username(self) -> str | None:
        """The user principal name of a user flow, or ``None`` for an app flow."""
        return self._given.username

    @property
    def is_app_flow(self) -> bool:
        """Whether this context authenticates as an application, not a person.

        ``True`` with a secret or certificate, and for a managed identity: its tokens are
        app-only too, for ``<resource>/.default`` and never a first-party client id.
        """
        return self._given.credential is not None or self._given.managed_identity

    @property
    def is_managed_identity(self) -> bool:
        """Whether this context signs in as the Azure host's managed identity."""
        return self._given.managed_identity

    @property
    def home(self) -> AuthContext:
        """The context the user signed in on.

        For a context you built yourself, this is the context itself. For one from
        :meth:`get_tenant_context`, it points back to the context you built. Only that
        context can prompt, so ``auth.home is not auth`` tells you ``auth`` cannot sign
        anyone in, and that a sign-in has to happen on ``auth.home`` instead.
        """
        return self._home

    @property
    def authority(self) -> str:
        """The authority URL for this tenant.

        Raises:
            AuthError: If the tenant's GUID is not known yet (:attr:`Tenant.guid`).
        """
        return f"{self._tenant.cloud.authority_host.rstrip('/')}/{self._tenant.guid}"

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

    def get_tenant_context(self, tenant: str) -> AuthContext:
        """Return a context for another tenant that reuses this context's sign-in.

        The new context shares this context's credentials, cache, username and cloud, so a
        user with GDAP access obtains customer-tenant tokens from the one home-tenant sign-in.
        A GUID costs no network call; a domain name is looked up once, for its GUID, and
        remembered. The new context never opens a browser: when a token cannot be obtained
        silently it raises :class:`InteractionRequired` or :class:`ConsentRequired` carrying
        the tenant id. Its :attr:`home` is this context's :attr:`home`.

        Args:
            tenant: Tenant id (GUID) or verified domain name of the other tenant.

        Returns:
            The context for that tenant, or this context when the tenant is its own. Repeated
            calls return the same object.

        Raises:
            ValueError: If this context is a managed identity and ``tenant`` is not its own:
                an identity has tokens for its own tenant only.
            TenantNotFound, NetworkError, AuthError: From looking a domain name up, in this
                cloud.
        """
        guid = as_guid(tenant)
        if self._given.managed_identity:
            if guid is not None and guid == self._tenant.id:
                return self
            raise ValueError(
                f"A managed identity has tokens for its own tenant only ({self._tenant}); "
                f"it cannot sign in to {tenant!r}"
            )
        found = None
        if guid is None:
            found = self._lookups.get(tenant.lower())
            if found is None:
                found = self._lookups[tenant.lower()] = Tenant.lookup(
                    tenant, self._tenant.cloud, clouds=self._given.lookup_clouds
                )
            guid = found.guid
        if guid == self._tenant.id:
            return self
        with self._guard:
            context = self._tenant_contexts.get(guid)
            if context is None:
                context = AuthContext.__new__(AuthContext)
                context._tenant = found or Tenant(guid, self._tenant.cloud)
                context._given = self._given
                context._can_prompt = False
                context._home = self._home
                context._init_state()
                self._tenant_contexts[guid] = context
            elif found is not None and context._tenant.oidc is None:
                # First addressed by GUID, now by name: keep what the name's lookup found.
                context._tenant = found
            return context

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
                is served by :meth:`get_tenant_context`.
            enable_cae: Accepted for protocol compatibility. Every application declares
                continuous access evaluation, so the token is CAE-capable either way.
            **kwargs: Ignored.

        Returns:
            The token and its expiry time.

        Raises:
            AuthError: If this context is a managed identity and ``tenant_id`` names another
                tenant: an identity has tokens for its own tenant only.
        """
        context = self._context_for_sdk(tenant_id)
        info = context.acquire_token(scopes, claims=claims)
        self._check_requested_tenant(tenant_id)
        return AccessToken(info.token, info.expires_on)

    def get_token_info(
        self, *scopes: str, options: TokenRequestOptions | None = None
    ) -> AccessTokenInfo:
        """Request an access token (Azure SDK ``SupportsTokenInfo`` protocol).

        Args:
            *scopes: Scopes to request, normally one ``<resource>/.default`` value.
            options: ``claims`` and ``tenant_id`` are honoured. ``enable_cae`` changes
                nothing: every token is CAE-capable.

        Returns:
            The token with its expiry time and type.
        """
        options = options or {}
        context = self._context_for_sdk(options.get("tenant_id"))
        info = context.acquire_token(scopes, claims=options.get("claims"))
        self._check_requested_tenant(options.get("tenant_id"))
        return info

    def _context_for_sdk(self, tenant_id: str | None) -> AuthContext:
        """Pick the context that serves an Azure SDK client's token request.

        Args:
            tenant_id: The tenant the SDK asks for, if any: Key Vault's challenge names the
                vault's.

        Returns:
            :meth:`get_tenant_context` for ``tenant_id``; this context for a managed
            identity, which has no other tenant to offer, and whose answer is checked against
            the request afterwards (:meth:`_check_requested_tenant`).
        """
        if self._given.managed_identity or not tenant_id:
            return self
        return self.get_tenant_context(tenant_id)

    def _check_requested_tenant(self, tenant_id: str | None) -> None:
        """Refuse an SDK client's request for a tenant a managed identity is not in.

        Args:
            tenant_id: The tenant the SDK asked for, if any.

        Raises:
            AuthError: If this context is a managed identity in another tenant.
        """
        if not (self._given.managed_identity and tenant_id):
            return
        if as_guid(tenant_id) != self._tenant.id:
            raise AuthError(
                f"A token for tenant {tenant_id} was asked for, but this managed identity is "
                f"in tenant {self._tenant.id}. An identity has tokens for its own tenant "
                "only; the resource is in another tenant."
            )

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
            NetworkError: If Entra ID could not be reached.
        """
        return self._acquire(scopes, client_id, claims, force_refresh, pick_account=False)

    def login(
        self,
        *,
        client_id: str | None,
        scopes: Iterable[str],
        pick_account: bool = False,
        reauthenticate: bool = False,
        consent: bool = False,
    ) -> None:
        """Sign in now instead of at the first request.

        Resource clients call this from their own ``login()`` with their client id and
        scopes. Calling it is optional, because the first token request signs in anyway. A
        managed identity gets its token; the other arguments mean nothing to it.

        Args:
            client_id: Client id to sign in to; ``None`` only for a system-assigned managed
                identity.
            scopes: Scopes to request.
            pick_account: Show the account picker, even when a cached token or account
                exists or the broker or browser could sign in by itself. Someone other than
                the configured user is refused. Ignored by app flows.
            reauthenticate: Open the sign-in window and have Entra ask for the password again,
                and for multi-factor authentication where the tenant wants it, even when a
                cached token exists or a still signed-in browser could sign in by itself
                (OpenID Connect ``prompt=login``). Tokens from :meth:`get_tenant_context`
                contexts then carry the new sign-in's time, for a customer whose Conditional
                Access policy found the old one too old. Signs in in the browser even with
                ``broker``, which cannot be told to ask again (msal 1.39). Someone other than
                the configured user is refused. Ignored by app flows.
            consent: Open the sign-in window and have Entra show its consent screen for the
                scopes, even when they are consented already and a cached token or a still
                signed-in browser could sign in by itself (OpenID Connect ``prompt=consent``).
                An administrator sees "Consent on behalf of your organization" there, so a
                tenant where only the signed-in user has consented can get a tenant-wide grant.
                Signs in in the browser even with ``broker``, which ignores the request (msal
                1.39). Someone other than the configured user is refused. Ignored by app flows.

        Raises:
            ValueError: If more than one of ``pick_account``, ``reauthenticate`` and
                ``consent`` is set.
            InteractionRequired: If this context came from :meth:`get_tenant_context` and the
                user must sign in.
            NetworkError: If Entra ID could not be reached.
        """
        if pick_account + reauthenticate + consent > 1:
            raise ValueError("Only one of pick_account, reauthenticate and consent can be set")
        if self._given.managed_identity:
            # There is nobody to ask anything of; the token is simply got.
            pick_account = reauthenticate = consent = False
        self._acquire(
            scopes,
            client_id,
            None,
            pick_account or reauthenticate or consent,
            pick_account=pick_account,
            reauthenticate=reauthenticate,
            consent=consent,
        )

    def flush_cache(self) -> None:
        """Write the disk cache's unwritten changes to its file.

        With ``cache="disk"``, the tokens MSAL stores and drops change the cache in memory. The
        file is written here, by :meth:`AsyncAuthContext.close`, and when the process exits,
        once for all the changes since the last write: writing means encrypting the whole
        file, and a run across many tenants changes the cache thousands of times. Call it once
        a sign-in is worth keeping should the process be killed, such as after a browser
        sign-in or after each batch of work. Contexts from :meth:`get_tenant_context` share the
        cache, so one call writes every tenant's tokens. With ``cache="memory"`` there is
        nothing to write.

        Raises:
            CacheFileEmpty: If the cache file is there but empty, which no process can decrypt.
            OSError: If the file could not be written. The changes stay for the next call.
        """
        if isinstance(self._given.cache, DiskTokenCache):
            self._given.cache.flush()

    def acquire_token_silently(
        self,
        scopes: Iterable[str],
        *,
        client_id: str | None = None,
        force_refresh: bool = False,
    ) -> AccessTokenInfo:
        """Acquire a token without ever prompting, even where this context may prompt.

        A token in the cache, or one the refresh token can get, is returned; when somebody
        would have to sign in, the request fails instead. Resource clients use it to look at
        what a tenant has granted before asking for more.

        Args:
            scopes: Scopes to request.
            client_id: Client id to use; defaults as for :meth:`acquire_token`.
            force_refresh: Skip cached access tokens and ask Entra, through the refresh token.
                A cached token carries the scopes it was issued with, so it can predate a
                change to the tenant's grant by up to its lifetime. The Windows broker answers
                from its own cache even so (msal 1.39 does not pass this on).

        Returns:
            The token with its expiry time and type.

        Raises:
            InteractionRequired: If the user would have to sign in.
            ConsentRequired: If consent is missing in the tenant.
            AuthError: For any other failure.
            NetworkError: If Entra ID could not be reached.
        """
        return self._acquire(
            scopes, client_id, None, force_refresh, pick_account=False, silent_only=True
        )

    # ------------------------------------------------------------------ internals

    def resolve_client_id(self, client_id: str | None = None) -> str:
        """Apply the client id precedence rule for a bare token request.

        Args:
            client_id: Client id chosen by the caller, if any.

        Returns:
            ``client_id``, else the context's client id, else (user flows) the Azure
            PowerShell client id.

        Raises:
            ValueError: If an app flow has no client id, or a system-assigned managed
                identity's is not known yet.
        """
        resolved = client_id or self.client_id
        if resolved:
            return resolved
        if self._given.managed_identity:
            raise ValueError(
                "A system-assigned managed identity's client id is not known until its first token"
            )
        if self.is_app_flow:
            raise ValueError("App flows need a client_id; first-party client ids cannot be used")
        return AZURE_POWERSHELL_CLIENT_ID

    def _token_key(self, scopes: Iterable[str], client_id: str | None) -> _TokenKey:
        """Return the key a token request is remembered under.

        Args:
            scopes: Scopes the token is requested for.
            client_id: Client id the token is requested with.

        Returns:
            The resolved client id and the set of scopes. A managed identity's tokens are
            keyed by their scopes alone: the endpoint takes no client id for them.
        """
        if self._given.managed_identity:
            return (_MANAGED_IDENTITY_KEY, frozenset(scopes))
        return (self.resolve_client_id(client_id), frozenset(scopes))

    def _recent_token(self, scopes: Iterable[str], client_id: str | None) -> AccessTokenInfo | None:
        """Return a still-fresh token this context fetched recently, without locking.

        These tokens are kept in this context's memory, in front of the MSAL token cache,
        so a fresh token is returned without asking MSAL. A caller that returns it notes
        that the cache answered (:meth:`_issued_by_entra`).

        Args:
            scopes: Scopes the token was requested for.
            client_id: Client id the token was requested with.

        Returns:
            The token, or ``None`` when there is none or it is close to expiry.
        """
        info = self._recent_tokens.get(self._token_key(scopes, client_id))
        if info is not None and info.expires_on - time.time() > _REFRESH_MARGIN_SECONDS:
            return info
        return None

    def _issued_by_entra(self, scopes: Iterable[str], client_id: str | None) -> bool:
        """Say whether the token last returned for ``scopes`` came from Entra.

        MSAL reports where each token came from (``token_source``): Entra itself, through a
        sign-in or the refresh token, or a cache. A token this context returned from its
        own memory counts as cached too. A token Entra just issued proves the sign-in works
        now; only a cached one needs that proved separately (``login(fresh=True)`` on a
        client).

        Args:
            scopes: Scopes the token was requested for.
            client_id: Client id the token was requested with.

        Returns:
            ``True`` when Entra issued the token in the last request for it; ``False`` when
            a cache answered, or nothing was requested yet.
        """
        return self._from_entra.get(self._token_key(scopes, client_id), False)

    def _acquire(
        self,
        scopes: Iterable[str],
        client_id: str | None,
        claims: str | None,
        force_refresh: bool,
        *,
        pick_account: bool,
        reauthenticate: bool = False,
        consent: bool = False,
        silent_only: bool = False,
    ) -> AccessTokenInfo:
        """Acquire a token under the single-flight lock for its key.

        Args:
            scopes: Scopes to request.
            client_id: Client id chosen by the caller, if any.
            claims: Claims challenge to satisfy.
            force_refresh: Skip cached access tokens.
            pick_account: Show the account picker, even when a silent token is available.
            reauthenticate: Have Entra ask for the password again, even when a silent token
                is available.
            consent: Have Entra show its consent screen, even when a silent token is
                available.
            silent_only: Never prompt, even where this context may: fail instead.

        Returns:
            The token with its expiry time and type.
        """
        scope_list = list(dict.fromkeys(scopes))
        if not scope_list:
            raise ValueError("At least one scope is required")
        resolved = None if self._given.managed_identity else self.resolve_client_id(client_id)
        key = self._token_key(scope_list, resolved)
        with self._guard:
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:
            if not (claims or force_refresh or pick_account or reauthenticate or consent):
                recent = self._recent_token(scope_list, resolved)
                if recent is not None:
                    self._from_entra[key] = False
                    return recent
            # MSAL sends its requests with ``requests`` and lets that library's exceptions
            # through: a failed connection, and an error status from Entra where MSAL has no
            # answer to read (a 5xx for a token, any for the tenant's configuration). An error
            # status MSAL holds back to throttle a retry is its own MsalServiceError (msal 1.39
            # ``oauth2.py``, ``authority.py``, ``throttled_http_client.py``).
            try:
                if resolved is None:
                    result = self._acquire_for_managed_identity(scope_list, claims, force_refresh)
                elif self.is_app_flow:
                    result = self._acquire_for_app(resolved, scope_list, claims, force_refresh)
                else:
                    result = self._acquire_for_user(
                        resolved,
                        scope_list,
                        claims,
                        force_refresh,
                        pick_account,
                        reauthenticate=reauthenticate,
                        consent=consent,
                        silent_only=silent_only,
                    )
            except (requests.HTTPError, MsalServiceError) as exc:
                raise AuthError(
                    f"Entra ID failed a token request for tenant {self._tenant}: {exc}"
                ) from exc
            except requests.RequestException as exc:
                raise network_error(f"A token request for tenant {self._tenant}", exc) from exc
            info = AccessTokenInfo(
                str(result["access_token"]),
                int(time.time()) + int(result.get("expires_in", 0)),
                token_type=str(result.get("token_type", "Bearer")),
            )
            self._recent_tokens[key] = info
            self._from_entra[key] = result.get("token_source") == _SOURCE_ENTRA
            return info

    def _app(self, client_id: str, *, use_broker: bool = False) -> Any:
        """Return the memoised MSAL application for a client id.

        Args:
            client_id: Client id of the application.
            use_broker: Whether the application should use the Windows broker.

        Returns:
            An ``msal.PublicClientApplication`` or ``msal.ConfidentialClientApplication``,
            declaring ``_CLIENT_CAPABILITIES``.
        """
        key = (client_id, use_broker)
        app = self._apps.get(key)
        if app is None:
            if self._given.credential is not None:
                app = msal.ConfidentialClientApplication(
                    client_id,
                    client_credential=self._given.credential.msal_client_credential(
                        client_id=client_id, token_endpoint=self.token_endpoint
                    ),
                    authority=self.authority,
                    token_cache=self._given.cache,
                    client_capabilities=_CLIENT_CAPABILITIES,
                )
            elif use_broker:
                # Without PII logging the broker hides Entra's reason for a failure: one broker
                # error covers missing consent, Conditional Access and more (errors.py).
                app = msal.PublicClientApplication(
                    client_id,
                    authority=self.authority,
                    token_cache=self._given.cache,
                    client_capabilities=_CLIENT_CAPABILITIES,
                    enable_broker_on_windows=True,
                    enable_pii_log=True,
                )
            else:
                app = msal.PublicClientApplication(
                    client_id,
                    authority=self.authority,
                    token_cache=self._given.cache,
                    client_capabilities=_CLIENT_CAPABILITIES,
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
            raise error_from_msal_result(result, tenant=self._tenant, scopes=scopes)
        return dict(result)

    def _managed_identity_client(self) -> Any:
        """Return the memoised MSAL managed identity client.

        Returns:
            An ``msal.ManagedIdentityClient`` for the configured identity, on this context's
            cache, declaring ``_CLIENT_CAPABILITIES`` (msal 1.39 passes them on to Service
            Fabric only).
        """
        key = (_MANAGED_IDENTITY_KEY, False)
        app = self._apps.get(key)
        if app is None:
            client_id = self._given.client_id
            identity = (
                msal_managed_identity.UserAssignedManagedIdentity(client_id=client_id)
                if client_id
                else msal_managed_identity.SystemAssignedManagedIdentity()
            )
            app = msal_managed_identity.ManagedIdentityClient(
                identity,
                http_client=_managed_identity_http_client(),
                token_cache=self._given.cache,
                client_capabilities=_CLIENT_CAPABILITIES,
            )
            with self._guard:
                app = self._apps.setdefault(key, app)
        return app

    def _acquire_for_managed_identity(
        self, scopes: list[str], claims: str | None, force_refresh: bool
    ) -> dict[str, Any]:
        """Get a token from the host's identity endpoint.

        Args:
            scopes: The one ``<resource>/.default`` scope.
            claims: Claims challenge to satisfy; msal then asks the endpoint again.
            force_refresh: Drop the cached token for the resource first.

        Returns:
            The successful MSAL result.

        Raises:
            ValueError: If the scopes are not one ``<resource>/.default``.
            ManagedIdentityUnavailable: If this host has no identity endpoint.
            NetworkError: If the host's endpoint could not be reached, or did not answer.
            AuthError: If the endpoint refused, or the token is for the wrong tenant.
        """
        resource = _resource_from_scopes(scopes)
        app = self._managed_identity_client()
        if force_refresh:
            self._forget_managed_identity_tokens(resource)
        endpoint = f"the {_identity_source_name()} managed identity endpoint"
        try:
            result = app.acquire_token_for_client(resource=resource, claims_challenge=claims)
        except requests.ConnectionError as exc:
            # A connection that could not be made, including one that timed out.
            source = msal_managed_identity.get_managed_identity_source()
            if source is msal_managed_identity.DEFAULT_TO_VM:
                raise ManagedIdentityUnavailable(
                    "This host has no managed identity endpoint: no IDENTITY_ENDPOINT or "
                    f"MSI_ENDPOINT is set, and nothing answered at {_IMDS_HOST} within "
                    f"{_IDENTITY_CONNECT_TIMEOUT_SECONDS:g} seconds ({type(exc).__name__}). "
                    "A managed identity works only on an Azure host that has one assigned."
                ) from exc
            raise network_error(f"A token request to {endpoint}", exc) from exc
        except requests.RequestException as exc:
            raise network_error(f"A token request to {endpoint}", exc) from exc
        except json.JSONDecodeError as exc:
            raise ManagedIdentityUnavailable(
                f"{endpoint[0].upper()}{endpoint[1:]} answered a token request with something "
                "that is not a token response. This host is not an Azure host with a managed "
                "identity."
            ) from exc
        except msal_managed_identity.ManagedIdentityError as exc:
            raise AuthError(f"{endpoint[0].upper()}{endpoint[1:]} cannot be used: {exc}") from exc
        if "access_token" not in result:
            raise self._managed_identity_refusal(result, resource, endpoint)
        self._learn_from_token(str(result["access_token"]))
        return dict(result)

    def _forget_managed_identity_tokens(self, resource: str) -> None:
        """Drop the cached managed identity tokens for a resource.

        Args:
            resource: The resource whose tokens are dropped.
        """
        cache = self._given.cache
        for entry in list(
            cache.search(
                TokenCache.CredentialType.ACCESS_TOKEN,
                target=[resource],
                query={"home_account_id": None},
            )
        ):
            cache.remove_at(entry)

    def _managed_identity_refusal(
        self, result: dict[str, Any], resource: str, endpoint: str
    ) -> AuthError:
        """Build the error for a token the identity endpoint would not issue.

        Args:
            result: The failed MSAL result.
            resource: The resource the token was for.
            endpoint: The endpoint's name, for the message.

        Returns:
            The error, naming the identity, the endpoint and the resource, leading with the
            endpoint's own words. msal labels every App Service refusal ``invalid_scope``, a
            wrong client id included, so the label follows the words rather than leading.
        """
        client_id = self._given.client_id
        identity = "the system-assigned identity"
        if client_id:
            identity = f"the user-assigned identity {client_id}"
        description = str(result.get("error_description") or "").strip()
        error = str(result.get("error") or "")
        reason = description or error or "no reason given"
        if description and error:
            reason = f"{description} ({error})"
        refusal = AuthError(
            f"{endpoint[0].upper()}{endpoint[1:]} refused a token for {resource} for "
            f"{identity}: {reason}. Check that the identity is assigned to this host and that "
            "the resource is one it can get tokens for."
        )
        return with_entra_answer(refusal, result)

    def _learn_from_token(self, token: str) -> None:
        """Take what a managed identity's token says about the identity and its tenant.

        Args:
            token: The access token.

        Raises:
            AuthError: If the token is for a tenant other than the one this context was built
                for.
        """
        claims = _token_claims(token)
        tenant_id = as_guid(str(claims.get("tid") or ""))
        if tenant_id is not None:
            if self._tenant.id is None:
                self._tenant = Tenant(tenant_id, self._tenant.cloud)
            elif self._tenant.id != tenant_id:
                raise AuthError(
                    f"This managed identity's tokens are for tenant {tenant_id}, but the "
                    f"context was built for tenant {self._tenant} ({self._tenant.id}). An "
                    "identity has tokens for its own tenant only."
                )
        app_id = as_guid(str(claims.get("appid") or ""))
        if app_id is not None and self._identity_client_id is None:
            self._identity_client_id = app_id

    def _broker_usable(self) -> bool:
        """Decide whether to use the Windows broker for this context.

        Returns:
            ``True`` when the broker was requested and can be used.

        Raises:
            BrokerUnavailable: If the broker was requested, cannot be used, and
                ``broker_fallback`` is off.
        """
        if not self._given.broker:
            return False
        if _broker_installed():
            return True
        if not self._given.broker_fallback:
            raise BrokerUnavailable(
                "The authentication broker needs Windows and the 'broker' extra "
                "(pip install azure-auth[broker])"
            )
        _LOGGER.warning("Authentication broker unavailable; falling back to the browser")
        return False

    def _accounts(self, app: Any) -> list[dict[str, Any]]:
        """Find the user's cached accounts, each described by its home-tenant entry.

        MSAL keeps one account entry per tenant the user has a token from, and
        ``get_accounts`` merges them, keeping the username and account id of whichever entry
        was saved last. Through the broker, a GDAP customer tenant's Exchange token is saved
        under the username ``user_<object id>@<home domain>`` and the account id
        ``<object id>.<home tenant>.<customer tenant>`` (measured 2026-10-16). MSAL's lookup by
        username then finds nobody, and every later silent request fails, in every tenant.
        The home-tenant entry keeps the real username, and its account id is the one the
        broker answers for in every tenant. An account with no home-tenant entry, such as a
        guest's, is left as MSAL describes it.

        Args:
            app: The MSAL application to look in.

        Returns:
            The accounts whose username is the context's, as ``acquire_token_silent`` takes
            them.
        """
        homes = {
            (entry.get("home_account_id"), entry.get("environment")): entry
            for entry in self._given.cache.search(TokenCache.CredentialType.ACCOUNT)
            if entry.get("realm") == str(entry.get("home_account_id") or "").rpartition(".")[2]
        }
        username = (self._given.username or "").lower()
        accounts = []
        for account in app.get_accounts():
            home = homes.get((account.get("home_account_id"), account.get("environment")))
            if home is not None:
                account = {key: home.get(key) for key in account}
            if str(account.get("username") or "").lower() == username:
                accounts.append(account)
        return accounts

    def _acquire_for_user(
        self,
        client_id: str,
        scopes: list[str],
        claims: str | None,
        force_refresh: bool,
        pick_account: bool,
        *,
        reauthenticate: bool = False,
        consent: bool = False,
        silent_only: bool = False,
    ) -> dict[str, Any]:
        """Get a user token: silently if possible, interactively if allowed.

        Args:
            client_id: Client id of the public client application.
            scopes: Scopes to request.
            claims: Claims challenge to satisfy.
            force_refresh: Skip cached access tokens.
            pick_account: Show the account picker, even when a silent token is available.
            reauthenticate: Have Entra ask for the password again, in the browser, even when
                a silent token is available.
            consent: Have Entra show its consent screen, in the browser, even when a silent
                token is available.
            silent_only: Never prompt, even where this context may: fail instead.

        Returns:
            The successful MSAL result.
        """
        # The broker cannot be told to ask for the password again, or to show the consent
        # screen: it takes select_account only (msal 1.39 broker.py).
        use_broker = not (reauthenticate or consent) and self._broker_usable()
        app = self._app(client_id, use_broker=use_broker)
        result: dict[str, Any] | None = None
        if not (pick_account or reauthenticate or consent):
            accounts = self._accounts(app)
            if len(accounts) > 1:
                raise AccountSelectionRequired(
                    f"{len(accounts)} cached accounts match {self._given.username!r}"
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

        if silent_only and self._can_prompt:
            raise error_from_msal_result(result, tenant=self._tenant, scopes=scopes)
        if not self._can_prompt:
            error = error_from_msal_result(result, tenant=self._tenant, scopes=scopes)
            # When Entra gave a reason, the reason is the message. For Conditional Access or a
            # user not assigned to the application, the advice to sign in at home was wrong.
            if isinstance(error, InteractionRequired) and not entra_error_codes(result):
                advised = InteractionRequired(
                    f"{error} Contexts from get_tenant_context() never prompt; call login() on a "
                    "client of the home context (auth.home) first.",
                    tenant_id=self._tenant.guid,
                    scopes=scopes,
                )
                raise with_entra_answer(advised, result)
            raise error

        # Entra puts up its own consent screen when an application has not been granted the
        # scopes being asked for, so consent is handled by the ordinary sign-in; ``consent``
        # asks for the screen again on request only. An automatic retry with prompt=consent
        # was tried here and removed:
        # measured against a live tenant on 2026-09-20, a user who may not consent is shown
        # "Need admin approval" and leaving that page returns a bare access_denied, which no
        # retry can fix. Pressing Cancel on the consent screen returns consent_required with
        # AADSTS65004 (measured 2026-09-25), which is the user's decision. Reopening the
        # browser on either would be wrong, and the retry could never fire in the case it was
        # written for.
        result = self._interactive(
            client_id,
            scopes,
            claims,
            use_broker=use_broker,
            pick_account=pick_account,
            reauthenticate=reauthenticate,
            consent=consent,
        )
        if "access_token" not in result:
            raise error_from_msal_result(result, tenant=self._tenant, scopes=scopes)
        self._check_signed_in_user(result)
        return result

    def _interactive(
        self,
        client_id: str,
        scopes: list[str],
        claims: str | None,
        *,
        use_broker: bool,
        pick_account: bool = False,
        reauthenticate: bool = False,
        consent: bool = False,
    ) -> dict[str, Any]:
        """Prompt the user, through the broker when enabled, else in the browser.

        Without ``pick_account``, ``reauthenticate`` or ``consent`` the sign-in may still
        finish with nobody acting: the broker answers silently for an account it holds, and a
        browser that is still signed in completes the page by itself.

        Args:
            client_id: Client id of the public client application.
            scopes: Scopes to request.
            claims: Claims challenge to satisfy.
            use_broker: Whether to try the Windows broker first.
            pick_account: Show the account picker, so a person always chooses the account.
            reauthenticate: Have Entra ask for the password again, and for multi-factor
                authentication where the tenant wants it.
            consent: Have Entra show its consent screen for the scopes again.

        Returns:
            The MSAL result, successful or not.

        Raises:
            BrokerUnavailable: If the broker fails and ``broker_fallback`` is off.
        """
        # With select_account the broker skips its silent attempts and drops the login hint
        # (msal 1.39).
        prompt: str | None = None
        if consent:
            prompt = "consent"
        elif reauthenticate:
            prompt = "login"
        elif pick_account:
            prompt = "select_account"
        if use_broker:
            broker_app = self._app(client_id, use_broker=True)
            try:
                result = broker_app.acquire_token_interactive(
                    scopes,
                    prompt=prompt,
                    login_hint=self._given.username,
                    claims_challenge=claims,
                    parent_window_handle=broker_app.CONSOLE_WINDOW_HANDLE,
                )
            except Exception as exc:
                if not self._given.broker_fallback:
                    raise BrokerUnavailable(f"The authentication broker failed: {exc}") from exc
                _LOGGER.warning("Authentication broker failed (%s); using the browser", exc)
            else:
                if not _broker_failed(result):
                    return dict(result)
                if not self._given.broker_fallback:
                    raise BrokerUnavailable(
                        f"The authentication broker failed: {result.get('error_description')}"
                    )
                _LOGGER.warning("Authentication broker failed; using the browser")

        app = self._app(client_id, use_broker=False)
        if self._given.before_browser_opens is not None:
            self._given.before_browser_opens()
        if self._given.browser is not None:
            return self._browser_sign_in(app, scopes, claims, prompt, self._given.browser)
        try:
            result = app.acquire_token_interactive(
                scopes,
                prompt=prompt,
                login_hint=self._given.username,
                claims_challenge=claims,
                timeout=self._given.browser_timeout,
            )
        except BrowserInteractionTimeoutError as exc:
            raise self._browser_timeout_error() from exc
        return dict(result)

    def _browser_sign_in(
        self,
        app: Any,
        scopes: list[str],
        claims: str | None,
        prompt: str | None,
        browser: tuple[str, ...],
    ) -> dict[str, Any]:
        """Sign in in the chosen browser, as ``acquire_token_interactive`` would in the default.

        ``acquire_token_interactive`` cannot be told which browser to use on Windows (msal
        1.39), so this runs its steps itself: build the sign-in address, open it in the
        browser and wait for the answer, then redeem the code. The token cache is written as
        ``acquire_token_interactive`` writes it.

        Args:
            app: The MSAL public client application.
            scopes: Scopes to request.
            claims: Claims challenge to satisfy.
            prompt: The OIDC ``prompt``, or ``None``.
            browser: The program followed by its arguments.

        Returns:
            The MSAL result, successful or not.

        Raises:
            AuthError: If the sign-in is not completed within ``browser_timeout``.
        """
        name = _register_browser(browser)
        with AuthCodeReceiver(port=0) as receiver:
            flow = app.initiate_auth_code_flow(
                scopes,
                redirect_uri=f"http://localhost:{receiver.get_port()}",
                prompt=prompt,
                login_hint=self._given.username,
                claims_challenge=claims,
                response_mode="form_post",
            )
            response = receiver.get_auth_response(
                auth_uri=flow["auth_uri"],
                state=flow["state"],
                timeout=self._given.browser_timeout,
                browser_name=name,
            )
        if response is None:
            raise self._browser_timeout_error()
        return dict(app.acquire_token_by_auth_code_flow(flow, response, scopes=scopes))

    def _browser_timeout_error(self) -> AuthError:
        """Build the error for a browser sign-in nobody completed.

        Returns:
            The error, naming ``browser_timeout``.
        """
        return AuthError(
            f"The browser sign-in was not completed within {self._given.browser_timeout:g} "
            "seconds. The window was closed, nobody answered it, or the sign-in page stopped "
            "at an error that never returns to the application, such as a Conditional "
            "Access block."
        )

    def _check_signed_in_user(self, result: dict[str, Any]) -> None:
        """Make sure the person who signed in is the configured user.

        Args:
            result: A successful MSAL result.

        Raises:
            AuthError: If somebody else signed in. Their tokens would never be found again,
                because cached accounts are selected by username.
        """
        signed_in = (result.get("id_token_claims") or {}).get("preferred_username")
        expected = self._given.username
        if signed_in and expected and signed_in.lower() != expected.lower():
            raise AuthError(
                f"Signed in as {signed_in!r}, but this context is configured for {expected!r}"
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

    @property
    def home(self) -> AsyncAuthContext:
        """The asynchronous view of :attr:`AuthContext.home`."""
        return self._sync.home.aio

    def get_tenant_context(self, tenant: str) -> AsyncAuthContext:
        """Return the asynchronous view of :meth:`AuthContext.get_tenant_context`.

        Args:
            tenant: Tenant id (GUID) or verified domain name of the other tenant.

        Returns:
            The asynchronous view of the context for that tenant.
        """
        return self._sync.get_tenant_context(tenant).aio

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
            enable_cae: Accepted for protocol compatibility. Every application declares
                continuous access evaluation, so the token is CAE-capable either way.
            **kwargs: Ignored.

        Returns:
            The token and its expiry time.
        """
        context = self._sync._context_for_sdk(tenant_id).aio
        info = await context.acquire_token(scopes, claims=claims)
        self._sync._check_requested_tenant(tenant_id)
        return AccessToken(info.token, info.expires_on)

    async def get_token_info(
        self, *scopes: str, options: TokenRequestOptions | None = None
    ) -> AccessTokenInfo:
        """Request an access token (Azure SDK ``AsyncSupportsTokenInfo`` protocol).

        Args:
            *scopes: Scopes to request, normally one ``<resource>/.default`` value.
            options: ``claims`` and ``tenant_id`` are honoured. ``enable_cae`` changes
                nothing: every token is CAE-capable.

        Returns:
            The token with its expiry time and type.
        """
        options = options or {}
        context = self._sync._context_for_sdk(options.get("tenant_id")).aio
        info = await context.acquire_token(scopes, claims=options.get("claims"))
        self._sync._check_requested_tenant(options.get("tenant_id"))
        return info

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
            recent = self._sync._recent_token(scopes, client_id)
            if recent is not None:
                self._sync._from_entra[self._sync._token_key(scopes, client_id)] = False
                return recent
        return await asyncio.to_thread(
            self._sync.acquire_token,
            scopes,
            client_id=client_id,
            claims=claims,
            force_refresh=force_refresh,
        )

    async def acquire_token_silently(
        self,
        scopes: Sequence[str],
        *,
        client_id: str | None = None,
        force_refresh: bool = False,
    ) -> AccessTokenInfo:
        """Acquire a token without ever prompting; see :meth:`AuthContext.acquire_token_silently`.

        Args:
            scopes: Scopes to request.
            client_id: Client id to use.
            force_refresh: Skip cached access tokens and ask Entra.

        Returns:
            The token with its expiry time and type.
        """
        if not force_refresh:
            recent = self._sync._recent_token(scopes, client_id)
            if recent is not None:
                self._sync._from_entra[self._sync._token_key(scopes, client_id)] = False
                return recent
        return await asyncio.to_thread(
            self._sync.acquire_token_silently,
            scopes,
            client_id=client_id,
            force_refresh=force_refresh,
        )

    async def login(
        self,
        *,
        client_id: str | None,
        scopes: Sequence[str],
        pick_account: bool = False,
        reauthenticate: bool = False,
        consent: bool = False,
    ) -> None:
        """Sign in now; see :meth:`AuthContext.login`.

        Args:
            client_id: Client id to sign in to.
            scopes: Scopes to request.
            pick_account: Show the account picker; see :meth:`AuthContext.login`.
            reauthenticate: Have Entra ask for the password again; see
                :meth:`AuthContext.login`.
            consent: Have Entra show its consent screen again; see
                :meth:`AuthContext.login`.
        """
        await asyncio.to_thread(
            self._sync.login,
            client_id=client_id,
            scopes=scopes,
            pick_account=pick_account,
            reauthenticate=reauthenticate,
            consent=consent,
        )

    async def flush_cache(self) -> None:
        """Write the disk cache's unwritten changes to its file.

        See :meth:`AuthContext.flush_cache`.
        """
        await asyncio.to_thread(self._sync.flush_cache)

    async def close(self) -> None:
        """Write the disk cache's unwritten changes to its file (:meth:`flush_cache`).

        Also what the ``AsyncTokenCredential`` protocol asks for.
        """
        await self.flush_cache()

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
