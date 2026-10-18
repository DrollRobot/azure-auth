"""A stand-in browser for the chosen-browser tests: answers a sign-in the way Entra would.

Run as ``python fake_browser.py --record <file> [arguments...] <sign-in address>``, as
``webbrowser`` runs a registered browser. It posts a code and the address's ``state`` to its
``redirect_uri``, as Entra's ``form_post`` response does.

With ``--wrong-state`` among the arguments it first posts a code with another state, as a
forged answer would, and then the person's decline with the right state, so that the
sign-in ends at once rather than at its timeout.

Before its last post it writes to ``<file>``, as JSON, the arguments it was given and the
HTTP status the forged answer got (``null`` when there was none).
"""

from __future__ import annotations

import http.client
import json
import sys
import urllib.parse
from pathlib import Path

# The authorization code this browser hands back.
CODE = "code-from-the-fake-browser"


def post(redirect_uri: str, fields: dict[str, str]) -> int:
    """Post a form to the listener, as a ``form_post`` response does.

    Args:
        redirect_uri: The listener's address, plain HTTP on the loopback interface.
        fields: The form fields.

    Returns:
        The HTTP status of the listener's reply.
    """
    target = urllib.parse.urlsplit(redirect_uri)
    connection = http.client.HTTPConnection(target.hostname or "localhost", target.port, timeout=30)
    try:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        connection.request("POST", target.path or "/", urllib.parse.urlencode(fields), headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def main(argv: list[str]) -> None:
    """Answer the sign-in address, and record what was done.

    Args:
        argv: The arguments after the script name; ``--record <file>`` first, the sign-in
            address last.
    """
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(argv[-1]).query)
    redirect_uri = query["redirect_uri"][0]
    state = query["state"][0]
    forged_status = None
    if "--wrong-state" in argv:
        forged_status = post(redirect_uri, {"code": CODE, "state": "not-the-state"})
        answer = {"error": "access_denied", "error_description": "Declined.", "state": state}
    else:
        answer = {"code": CODE, "state": state}
    # Written before the last post, which ends the sign-in, so the test always finds it.
    record = {"argv": argv, "forged_status": forged_status}
    Path(argv[1]).write_text(json.dumps(record), encoding="utf-8")
    post(redirect_uri, answer)


if __name__ == "__main__":
    main(sys.argv[1:])
