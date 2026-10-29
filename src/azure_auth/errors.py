"""Exceptions shared by the whole package.

Network failures and error answers reach a caller of this package's own methods as this
package's exceptions, never as those of the HTTP libraries it uses or of the Azure SDK. The
original is chained as ``__cause__``: a network failure becomes :class:`NetworkError`, an
error from Entra ID :class:`~azure_auth.AuthError`, and an error status from a resource
:class:`~azure_auth.ResourceError`.
"""

from __future__ import annotations


class NetworkError(Exception):
    """A request got no usable answer from the network.

    The host could not be reached, the connection or its TLS handshake failed, the answer
    broke the HTTP protocol, or it did not arrive in time. Raised by token requests and
    resource clients alike. A request that was sent before the failure may still have been
    carried out. The HTTP library's own exception is chained as ``__cause__``.
    """


def network_error(action: str, cause: Exception) -> NetworkError:
    """Build the :class:`NetworkError` for an HTTP library's failure.

    Args:
        action: What was being done, such as ``GET https://graph.microsoft.com/v1.0/me``.
        cause: The HTTP library's exception, for the message; chain it with ``from``.

    Returns:
        The exception to raise.
    """
    reason = f"{type(cause).__name__}: {cause}" if str(cause) else type(cause).__name__
    return NetworkError(f"{action} failed: {reason}")
