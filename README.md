# azure-auth

<!-- FIXME: point these badges at your own repo, and drop the ones you don't use -->
[![CI](https://github.com/DrollRobot/azure_auth/actions/workflows/ci.yml/badge.svg)](https://github.com/DrollRobot/azure_auth/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.14%2B-blue)](https://www.python.org/)
<!-- FIXME: match the badge and the link below to the license you chose -->
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

<!-- FIXME: one paragraph -- what this package does, and who should use it -->

## Installation

<!-- FIXME: replace with the real install command once the package is published -->
```bash
uv add git+https://github.com/DrollRobot/azure_auth.git
```

## Usage

<!-- FIXME: the shortest example that does something useful -->
```python
import azure_auth
```

## Development

```bash
uv sync                                     # create the venv, install dev/test deps
uv run pre-commit install                   # commit hooks
uv run pre-commit install --hook-type pre-push
uv run pytest -m "not live"                 # offline tests
```

<!-- FIXME: anything a contributor needs that the commands above don't cover --
     required config options, credentials, external services, test fixtures -->

## License

<!-- FIXME: name the license you chose; the full text is in LICENSE -->
