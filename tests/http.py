"""Helpers for testing resource clients without a network."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterable
from typing import Any

import httpx2

Handler = Callable[[httpx2.Request], httpx2.Response]


class Recorder:
    """An ``httpx2`` mock transport handler that replays responses and records requests."""

    def __init__(self, responses: Iterable[httpx2.Response] | Handler) -> None:
        """Replay ``responses`` in order, or delegate to a handler function."""
        self.requests: list[httpx2.Request] = []
        self._handler = responses if callable(responses) else None
        self._responses = [] if callable(responses) else list(responses)

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        """Record the request and produce the next response."""
        self.requests.append(request)
        if self._handler is not None:
            return self._handler(request)
        return self._responses.pop(0)

    @property
    def transport(self) -> httpx2.MockTransport:
        """The transport to hand to a client."""
        return httpx2.MockTransport(self)

    def bodies(self) -> list[Any]:
        """Return the decoded JSON body of every recorded request."""
        return [json.loads(request.content) for request in self.requests if request.content]

    def urls(self) -> list[str]:
        """Return the URL of every recorded request."""
        return [str(request.url) for request in self.requests]


def ok(
    body: Any = None, status: int = 200, headers: dict[str, str] | None = None
) -> httpx2.Response:
    """Build a JSON response."""
    if body is None:
        return httpx2.Response(status, headers=headers)
    return httpx2.Response(status, json=body, headers=headers)


def fake_jwt(**claims: Any) -> str:
    """Build an unsigned token whose payload carries ``claims``."""

    def encode(value: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{encode({'alg': 'none'})}.{encode(claims)}.signature"
