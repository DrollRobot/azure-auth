"""Core logic for the azure_auth package.

Put your main implementation here. Split into more modules (e.g.
`models.py`, `utils.py`) as the package grows -- there is no need to
keep everything in one file.

This module can also be run directly:
    uv run python -m azure_auth --arg1 value
"""

from __future__ import annotations

import argparse


def main() -> None:
    """Entry point for the command-line interface.

    Parses arguments and calls the core logic. Keep this function thin --
    argument parsing and I/O belong here; business logic belongs in other
    functions that are easy to test without subprocess calls.
    """
    parser = argparse.ArgumentParser(description="FIXME: describe what this tool does")

    # FIXME: replace these arguments with ones that match your use case
    parser.add_argument("--arg1", required=True, help="FIXME: describe this argument")
    parser.add_argument(
        "--arg2",
        type=int,
        default=1,
        help="FIXME: describe this argument (default: 1)",
    )

    args = parser.parse_args()

    # FIXME: call your core logic here, e.g.
    # client = ApiClient(args.arg1)
    print(args.arg1, args.arg2)


# This block runs only when the file is executed directly, not when it is
# imported as a module.  Keep it as a one-liner that calls main() so the
# real logic stays in a testable function.
if __name__ == "__main__":
    main()
