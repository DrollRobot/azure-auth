# Development

## Set up

Requires Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/DrollRobot/azure-auth.git
cd azure-auth
uv sync --all-groups --all-extras
uv run pre-commit install
uv run pre-commit install --hook-type pre-push
```

## Run the checks and tests

The lint, format, type-check and test commands, and the test tags, are in
[AGENTS.TESTING.md](https://github.com/DrollRobot/azure-auth/blob/main/AGENTS.TESTING.md).

The live tests sign in to a real tenant. Copy
[`.env.example`](https://github.com/DrollRobot/azure-auth/blob/main/.env.example) to `.env`,
fill it in, and run:

```bash
uv run --env-file .env pytest tests/live -s --no-cov
```

## Build the docs

```bash
uv run mkdocs build --strict  # build HTML
uv run mkdocs serve  # live preview at http://127.0.0.1:8000
```

## Contribute

See [CONTRIBUTING.md](https://github.com/DrollRobot/azure-auth/blob/main/CONTRIBUTING.md) for
the code layout, conventions and pull requests.
