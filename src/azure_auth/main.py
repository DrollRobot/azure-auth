"""Core logic for the azure_auth package.

Put your main implementation here. Split into more modules (e.g.
`models.py`, `utils.py`) as the package grows -- there is no need to
keep everything in one file.

This module can also be run directly:
    uv run python -m azure_auth --arg1 value

Configuration comes from the config system (see
``src/azure_auth/config/``): non-secret values from the per-user
config.toml, secrets from the user-selected credential backend, with env-var
overrides for CI. The ``--profile`` flag below is the standard shape for
multi-tenant use; keep it even if your project starts single-tenant.
"""

from __future__ import annotations

import argparse

from azure_auth.config import load_settings


def main() -> None:
    """Entry point for the command-line interface.

    Parses arguments and calls the core logic. Keep this function thin --
    argument parsing and I/O belong here; business logic belongs in other
    functions that are easy to test without subprocess calls.
    """
    parser = argparse.ArgumentParser(description="FIXME: describe what this tool does")

    parser.add_argument(
        "--profile",
        default=None,
        help="Config profile to use (default: default_profile from config.toml).",
    )
    # FIXME: replace these arguments with ones that match your use case
    parser.add_argument("--arg1", required=True, help="FIXME: describe this argument")
    parser.add_argument(
        "--arg2",
        type=int,
        default=1,
        help="FIXME: describe this argument (default: 1)",
    )

    args = parser.parse_args()

    # Fails loudly (naming the fix) when required config is missing.
    settings = load_settings(profile=args.profile)

    # FIXME: call your core logic here, e.g.
    # client = ApiClient(settings.api_url, secret=settings.client_secret)
    print(args.arg1, args.arg2, settings.api_url)


# This block runs only when the file is executed directly, not when it is
# imported as a module.  Keep it as a one-liner that calls main() so the
# real logic stays in a testable function.
if __name__ == "__main__":
    main()
