# Contributing to azure-auth
Thank you for your interest in contributing!

## Setting up a development environment
Requires Python 3.14+ and [uv](https://docs.astral.sh/uv/).
```
git clone https://github.com/DrollRobot/azure-auth.git
cd azure-auth
uv sync --all-groups --all-extras
uv run pre-commit install
```

## Running checks
The full list of lint, format, type-check, test, and pre-commit commands lives
in [AGENTS.TESTING.md](AGENTS.TESTING.md). Run those before opening a PR.

Pre-commit also runs lint, format, type check, and secret detection
automatically on every commit.

### Code structure
- `src/azure_auth/auth/` -- `AuthContext`, credentials, the token cache, the Windows
  certificate store signer and the authentication errors
- `src/azure_auth/clients/` -- the asynchronous resource clients; the source of truth
- `src/azure_auth/_sync/` -- blocking clients, **generated** from `clients/`; never edit
- `src/azure_auth/sync/` -- public import path for the blocking clients
- `scripts/generate_sync.py` -- the generator for `_sync/` and `tests/unit/sync/`
- `tests/unit/`, `tests/integration/`, `tests/live/` -- pytest suites by scope
- `tests/unit/sync/` -- **generated** from the client tests in `tests/unit/`; never edit
- `docs/` -- MkDocs documentation source

### Naming and module conventions
- One `AuthContext` owns credentials, cache and account. Resource clients never talk to MSAL;
  they ask the context for a token and pass their client id and scopes.
- Every resource client subclasses `ResourceClient`, which owns retries, the 401 claims
  challenge, error mapping and the check that a token is only sent to the resource's host.
- Write clients asynchronously with plain constructs (`async def`, `await`, `async with`,
  `async for`, `asyncio.sleep`). After changing anything in `src/azure_auth/clients/` or a
  client test in `tests/unit/`, run `uv run python scripts/generate_sync.py` and commit the
  result. A test fails when the generated files are out of date.
- MSAL result dictionaries never leave `auth/`; translate them into the exceptions in
  `auth/errors.py`.
- Secrets are held in memory only. There is no unencrypted disk cache, and none may be added.
- Everything that knows about the undocumented Exchange `InvokeCommand` endpoint stays in
  `clients/invoke_command.py`.

### Public API
Export new public symbols from `src/azure_auth/__init__.py`.

### Docs
```shell
# build HTML
uv run mkdocs build --strict

# live preview at http://127.0.0.1:8000
uv run mkdocs serve

# deploy to GitHub Pages
uv run mkdocs gh-deploy --force
```

### Type annotations
All functions must be fully annotated. The package ships a `py.typed` marker,
so downstream consumers depend on its type information.

## Pull requests
1. Branch from `main` and open a PR against `main`.
2. Run the checks and tests in [AGENTS.TESTING.md](AGENTS.TESTING.md) and ensure
   they pass clean.
3. Update `CHANGELOG.md` under `## [Unreleased]`.
4. Update docstrings and `docs/` if the public API changed.

## Reporting issues
Use the GitHub issue templates for bugs and feature requests.
