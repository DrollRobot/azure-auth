"""Capture every log record at DEBUG, and check that no secret reached one.

An application that logs at DEBUG to a file writes whatever any library logs. The tests that
use this capture what such an application would see, from every logger, then look for each
secret the code under test handled.

The secrets themselves are never shown: pytest prints the captured log of a failed test, so
captured records are kept away from pytest's own log capture, and a failure names the kind of
secret and where it was logged, never its value.
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Iterable, Iterator, Mapping
from urllib.parse import quote, quote_plus

# Shorter values cannot be told apart from ordinary log text.
MIN_SECRET_LENGTH = 8

_FORMATTER = logging.Formatter("%(name)s %(levelname)s %(message)s")


class _Collector(logging.Handler):
    """Keeps every record it is handed."""

    def __init__(self) -> None:
        """Accept records of every level."""
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Keep the record."""
        self.records.append(record)


@contextlib.contextmanager
def all_logs_at_debug() -> Iterator[list[logging.LogRecord]]:
    """Capture every record from every logger, as an application logging at DEBUG would.

    Every logger is set to pass DEBUG on to the root, whatever level it was given, and the
    root's handlers, pytest's among them, are replaced by a collector until the block ends.

    Yields:
        The list the records are added to.
    """
    collector = _Collector()
    root = logging.getLogger()
    manager = root.manager
    loggers = [item for item in manager.loggerDict.values() if isinstance(item, logging.Logger)]
    saved = [(item, item.level, item.propagate, item.disabled) for item in loggers]
    saved_root = (root.level, root.handlers[:])
    saved_disable = manager.disable
    logging.disable(logging.NOTSET)
    root.setLevel(logging.DEBUG)
    root.handlers = [collector]
    for item in loggers:
        item.setLevel(logging.NOTSET)
        item.propagate = True
        item.disabled = False
    try:
        yield collector.records
    finally:
        for item, level, propagate, disabled in saved:
            item.setLevel(level)
            item.propagate = propagate
            item.disabled = disabled
        root.setLevel(saved_root[0])
        root.handlers = saved_root[1]
        logging.disable(saved_disable)


def _spellings(value: str) -> set[str]:
    """Return the ways a value is written when it is logged raw, in JSON, a URL or a repr.

    Args:
        value: The secret.

    Returns:
        Every spelling to look for.
    """
    return {
        value,
        json.dumps(value)[1:-1],
        quote(value, safe=""),
        quote_plus(value),
        repr(value)[1:-1],
    }


def _text(record: logging.LogRecord) -> str:
    """Return everything a handler could write for a record.

    That is the formatted message with any traceback, and every attribute of the record,
    which covers the arguments and the extra fields a structured formatter writes.

    Args:
        record: The log record.

    Returns:
        The text to search.
    """
    return f"{_FORMATTER.format(record)}\n{vars(record)!r}"


def find_secrets(
    records: Iterable[logging.LogRecord], secrets: Mapping[str, Iterable[str]]
) -> dict[str, list[str]]:
    """Find which secrets are in which records.

    Args:
        records: The captured records.
        secrets: Each kind of secret, such as ``"access token"``, with its values.

    Returns:
        For each kind found, where it was logged: the logger and the source line of each
        record that holds it. Kinds not found are left out.

    Raises:
        ValueError: If a value is too short to look for.
    """
    __tracebackhide__ = True  # pytest prints the arguments of the frames it shows
    spellings: dict[str, set[str]] = {}
    for kind, values in secrets.items():
        for value in values:
            if len(value) < MIN_SECRET_LENGTH:
                raise ValueError(
                    f"a {kind} shorter than {MIN_SECRET_LENGTH} characters cannot be told "
                    "apart from ordinary log text"
                )
            spellings.setdefault(kind, set()).update(_spellings(value))
    found: dict[str, list[str]] = {}
    for record in records:
        text = _text(record)
        for kind, forms in spellings.items():
            if any(form in text for form in forms):
                where = f"{record.name} ({record.filename}:{record.lineno})"
                found.setdefault(kind, []).append(where)
    return found


def assert_no_secrets(
    records: Iterable[logging.LogRecord], secrets: Mapping[str, Iterable[str]]
) -> None:
    """Fail if any secret is in any record, saying where without saying what.

    Args:
        records: The captured records.
        secrets: Each kind of secret, such as ``"access token"``, with its values.

    Raises:
        AssertionError: If nothing was logged, which proves nothing, or a secret was.
    """
    __tracebackhide__ = True  # pytest prints the arguments of the frames it shows
    records = list(records)
    assert records, "nothing was logged, so there was nothing to look for secrets in"
    found = find_secrets(records, secrets)
    lines = [f"{kind} logged by {', '.join(sorted(set(where)))}" for kind, where in found.items()]
    assert not found, "secrets reached the log:\n" + "\n".join(lines)
