# Contributing to azure-auth
Thank you for your interest in contributing!

## Setting up a development environment
Requires Python 3.14+ and [uv](https://docs.astral.sh/uv/).
```
git clone https://github.com/FIXME/azure-auth.git
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
<!-- FIXME: update paths and descriptions to match your project layout -->
- `src/azure_auth/` -- library source (src layout)
- `tests/` -- pytest test suite
- `docs/` -- MkDocs documentation source

### Naming and module conventions
<!-- FIXME: describe the key architectural patterns your project uses.
     Example patterns: command/handler, service/repository, client/parser, etc. -->

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
