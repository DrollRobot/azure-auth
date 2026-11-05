"""The identity endpoint of the Azure host this process runs on.

Two flows get tokens here: a context that signs in as the host's managed identity, and an
application whose credential is the identity (:class:`ManagedIdentityAssertionCredential` in
:mod:`azure_auth.auth.credentials`). msal's ``ManagedIdentityClient`` does the endpoints
(Container Apps, App Service, Functions, instance metadata, Arc, Service Fabric, Machine
Learning). This module adds what msal lacks: a timeout on every request, so that off Azure the
flow fails at once with :class:`ManagedIdentityUnavailable`; an :class:`AuthError` naming the
identity when the endpoint refuses; and no fallback.
"""

from __future__ import annotations

import json
from typing import Any

import requests
from msal import managed_identity as msal_managed_identity
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from azure_auth.auth.errors import AuthError, ManagedIdentityUnavailable, with_entra_answer
from azure_auth.errors import network_error

# The identity endpoint is on the host itself (``localhost``, or the link-local instance
# metadata address), so it answers at once or not at all: a short wait to connect tells a host
# without an endpoint from one with. The read timeout covers the endpoint asking Entra ID.
CONNECT_TIMEOUT_SECONDS = 2.0
READ_TIMEOUT_SECONDS = 10.0
IMDS_HOST = "169.254.169.254"

# What each of msal's identity endpoints is called in messages.
_SOURCES: dict[int, str] = {
    id(msal_managed_identity.APP_SERVICE): "App Service (IDENTITY_ENDPOINT)",
    id(msal_managed_identity.SERVICE_FABRIC): "Service Fabric (IDENTITY_ENDPOINT)",
    id(msal_managed_identity.MACHINE_LEARNING): "Azure Machine Learning (MSI_ENDPOINT)",
    id(msal_managed_identity.AZURE_ARC): "Azure Arc",
    id(msal_managed_identity.CLOUD_SHELL): "Cloud Shell",
    id(msal_managed_identity.DEFAULT_TO_VM): f"instance metadata ({IMDS_HOST})",
}


class IdentitySession(requests.Session):
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
        kwargs.setdefault("timeout", (CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS))
        return super().request(method, url, *args, **kwargs)


def http_client() -> requests.Session:
    """Create the session a managed identity client sends through.

    Returns:
        An :class:`IdentitySession`. Tests replace this function to answer the endpoint.
    """
    return IdentitySession()


def identity_client(
    client_id: str | None, *, token_cache: Any, client_capabilities: list[str] | None = None
) -> Any:
    """Create an msal client for one of the host's identities.

    Args:
        client_id: The client id of a user-assigned identity, or ``None`` for the host's
            system-assigned identity.
        token_cache: The msal token cache the identity's tokens are kept in.
        client_capabilities: The capabilities to declare (msal 1.39 passes them on to Service
            Fabric only).

    Returns:
        An ``msal.ManagedIdentityClient`` sending through :func:`http_client`.
    """
    identity = (
        msal_managed_identity.UserAssignedManagedIdentity(client_id=client_id)
        if client_id
        else msal_managed_identity.SystemAssignedManagedIdentity()
    )
    return msal_managed_identity.ManagedIdentityClient(
        identity,
        http_client=http_client(),
        token_cache=token_cache,
        client_capabilities=client_capabilities,
    )


def source_name() -> str:
    """Name the identity endpoint msal would use on this host.

    Returns:
        The endpoint's name, for messages.
    """
    source = msal_managed_identity.get_managed_identity_source()
    return _SOURCES.get(id(source), "managed identity")


def describe_identity(client_id: str | None) -> str:
    """Name an identity in a message.

    Args:
        client_id: The client id of a user-assigned identity, or ``None``.

    Returns:
        ``the user-assigned identity <client id>``, or ``the system-assigned identity``.
    """
    if client_id:
        return f"the user-assigned identity {client_id}"
    return "the system-assigned identity"


def request_token(
    client: Any, resource: str, *, client_id: str | None, claims: str | None = None
) -> dict[str, Any]:
    """Get a token for a resource from the host's identity endpoint.

    Args:
        client: The msal client, from :func:`identity_client`.
        resource: The resource the token is for, without ``/.default``.
        client_id: The client id of the user-assigned identity, or ``None``, for messages.
        claims: Claims challenge to satisfy; msal then asks the endpoint again.

    Returns:
        The successful msal result.

    Raises:
        ManagedIdentityUnavailable: If this host has no identity endpoint.
        NetworkError: If the host's endpoint could not be reached, or did not answer.
        AuthError: If the endpoint refused.
    """
    endpoint = f"the {source_name()} managed identity endpoint"
    try:
        result = client.acquire_token_for_client(resource=resource, claims_challenge=claims)
    except requests.ConnectionError as exc:
        # A connection that could not be made, including one that timed out.
        source = msal_managed_identity.get_managed_identity_source()
        if source is msal_managed_identity.DEFAULT_TO_VM:
            raise ManagedIdentityUnavailable(
                "This host has no managed identity endpoint: no IDENTITY_ENDPOINT or "
                f"MSI_ENDPOINT is set, and nothing answered at {IMDS_HOST} within "
                f"{CONNECT_TIMEOUT_SECONDS:g} seconds ({type(exc).__name__}). "
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
        raise _refusal(result, resource, endpoint, client_id)
    return dict(result)


def _refusal(
    result: dict[str, Any], resource: str, endpoint: str, client_id: str | None
) -> AuthError:
    """Build the error for a token the identity endpoint would not issue.

    Args:
        result: The failed msal result.
        resource: The resource the token was for.
        endpoint: The endpoint's name, for the message.
        client_id: The client id of the user-assigned identity, or ``None``.

    Returns:
        The error, naming the identity, the endpoint and the resource, leading with the
        endpoint's own words. msal labels every App Service refusal ``invalid_scope``, a
        wrong client id included, so the label follows the words rather than leading.
    """
    description = str(result.get("error_description") or "").strip()
    error = str(result.get("error") or "")
    reason = description or error or "no reason given"
    if description and error:
        reason = f"{description} ({error})"
    refusal = AuthError(
        f"{endpoint[0].upper()}{endpoint[1:]} refused a token for {resource} for "
        f"{describe_identity(client_id)}: {reason}. Check that the identity is assigned to "
        "this host and that the resource is one it can get tokens for."
    )
    return with_entra_answer(refusal, result)
