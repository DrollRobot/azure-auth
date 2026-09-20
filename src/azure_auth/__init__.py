"""FIXME: one-line summary of what this package provides.

This file is the public API surface for the package. Import symbols here
so callers can write `from azure_auth import MyClass` instead of spelling out
the full internal module path.

Example:
    >>> from azure_auth import greet
    >>> greet("world")
    'Hello, world!'
"""

from __future__ import annotations

# FIXME: replace with your real public symbols
from azure_auth.main import main

# __all__ controls what `from azure_auth import *` exports and what static
# analysis tools treat as the public API.
__all__ = ["main"]
