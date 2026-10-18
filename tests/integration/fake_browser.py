"""A stand-in browser for the chosen-browser tests: answers a sign-in the way Entra would.

Run as ``python fake_browser.py --record <file> [arguments...] <sign-in address>``, as
``webbrowser`` runs a registered browser. It writes the arguments it was given to ``<file>``
as JSON, then posts a code and the address's ``state`` to its ``redirect_uri``, as Entra's
``form_post`` response does. With ``--wrong-state`` among the arguments it posts another
state, as a forged answer would.
"""

from __future__ import annotations

import http.client
import json
import sys
import urllib.parse
from pathlib import Path

# The authorization code this browser hands back.
CODE = "code-from-the-fake-browser"


def main(argv: list[str]) -> None:
    """Record the arguments and answer the sign-in address.

    Args:
        argv: The arguments after the script name; ``--record <file>`` first, the sign-in
            address last.
    """
    Path(argv[1]).write_text(json.dumps(argv), encoding="utf-8")
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(argv[-1]).query)
    state = "not-the-state" if "--wrong-state" in argv else query["state"][0]
    body = urllib.parse.urlencode({"code": CODE, "state": state})
    target = urllib.parse.urlsplit(query["redirect_uri"][0])
    # Plain HTTP to the listener, as the redirect address says. The receiver answers a wrong
    # state with a 400, which the test judges by its outcome, not here.
    connection = http.client.HTTPConnection(target.hostname or "localhost", target.port, timeout=30)
    try:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        connection.request("POST", target.path or "/", body, headers)
        connection.getresponse().read()
    finally:
        connection.close()


if __name__ == "__main__":
    main(sys.argv[1:])
