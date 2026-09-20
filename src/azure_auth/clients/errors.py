"""Exceptions raised when a resource rejects a request."""

from __future__ import annotations

from typing import Any


class ResourceError(Exception):
    """A resource answered with an error status.

    Attributes:
        status: HTTP status code.
        code: Service error code, such as ``Request_ResourceNotFound``, when one was given.
        request_id: Service request id for support cases, when one was given.
        body: The decoded response body: parsed JSON when possible, else text.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int,
        code: str | None = None,
        request_id: str | None = None,
        body: Any = None,
    ) -> None:
        """Create the error.

        Args:
            message: Human readable description.
            status: HTTP status code.
            code: Service error code.
            request_id: Service request id.
            body: The decoded response body.
        """
        super().__init__(message)
        self.status = status
        self.code = code
        self.request_id = request_id
        self.body = body


class GraphError(ResourceError):
    """Microsoft Graph rejected a request."""


class AzureError(ResourceError):
    """Azure Resource Manager rejected a request or a long-running operation failed."""


class InvokeCommandError(ResourceError):
    """Exchange Online or Security & Compliance rejected a cmdlet invocation."""
