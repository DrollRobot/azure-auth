# Tests

## Writing tests

- All new code should have unit and integration tests, and e2e/live tests
    wherever possible.
- All tests should use the tag system described below. Tests MUST have at least
    one Scope tag (`unit`, `integration`, or `e2e`).

### Test Tags

| Tag | Axis | Description |
|------|------|-------------|
| `unit` | Scope | Single function/class in isolation; all dependencies mocked or stubbed. |
| `integration` | Scope | Multiple real components wired together across a boundary. |
| `e2e` | Scope | Whole application end to end, driven like a real user. |
| `smoke` | Purpose | Fast "is it fundamentally broken" check. |
| `regression` | Purpose | Guards against reintroduction of a previously fixed bug. |
| `acceptance` | Purpose | Verifies behavior against a requirement or user-facing spec. |
| `functional` | Purpose | Tests behavior/output of a feature without regard to internal structure. |
| `live` | Dependency | Requires a real external resource — network, live tenant, secrets, third-party API. |
| `interactive` | Dependency | Requires a human at this desktop to complete a sign-in prompt. Tell the user a prompt is coming before starting one. |
| `destructive_local` | Dependency | Mutates the host/device running pytest. Skipped by default. |
| `destructive_remote` | Dependency | Mutates a remote/external system. Skipped by default. |
| `slow` | Performance | Long-running: anything that would push the pre-push run past 60 seconds. See below. |

## Running tests

- **The pre-push run must finish in under 60 seconds.** The `pytest (prepush)` hook runs
    `-m "not live and not slow and not destructive_local and not destructive_remote"`. A new
    test that would push that over 60 seconds is marked `slow`.
- Tests should be run before committing code.
- Use the test procedure below.
```
# if pyproject.toml was changed:
uv sync --all-extras
uv lock --check

# code checks and formatting
uv run ruff check .                 # lint
uv run ruff format .                # apply ruff formatting
uv run mypy                         # type check (targets set in pyproject.toml)

# if package requires cross-platform support: type check the other OS targets
# (bare `uv run mypy` above only checks the host platform)
uv run mypy --platform win32        # type check as Windows
uv run mypy --platform darwin       # type check as macOS
uv run mypy --platform linux        # type check as Linux

# tests (destructive tests are skipped by default; see note below)
uv run pytest -m "not live"         # offline tests
uv run pytest                       # live and not-live tests (when credentialed)
```

## Interactive tests
Tests marked `interactive` open a sign-in prompt and need a human at the machine
running pytest. Nothing gates them, because a missing human is obvious: the run
blocks and then times out.

Agents should run them only when the user has said they are present, and should
say a prompt is coming before starting one. Everything else can be run freely
and repeatedly:
```
uv run pytest -m "not interactive"              # safe to repeat unattended
uv run pytest -m "live and not interactive"     # live, but no prompt
uv run pytest -m "interactive"                  # only with a user present
```

## Destructive tests
Destructive tests never run in the normal procedure above. Two independent
categories, each needing BOTH its own layers (flag + gate).

| | `destructive_local` | `destructive_remote` |
|---|---|---|
| Mutates | This host/device | A remote/external system (cloud resource, database, API tenant, ...) |
| Collection gate | `--run-destructive-local` | `--run-destructive-remote` |
| Execution gate | `DISPOSABLE_ENVIRONMENT=1` (env var) | `tests/verify_remote_disposable.py` exits 0 |

### Local destructive tests
`DISPOSABLE_ENVIRONMENT` values:
- `1` — user has declared this host disposable. Ask the user once per session
    before running `destructive_local` tests.
- `0` — not disposable. Never run them.
- Not set — host not assessed. Never run them; give the user the commands
    below and ask them to set the variable.
```
# windows (admin PowerShell)
[Environment]::SetEnvironmentVariable('DISPOSABLE_ENVIRONMENT','0','Machine')

# linux
echo 'DISPOSABLE_ENVIRONMENT=0' | sudo tee -a /etc/environment

# macOS
echo 'export DISPOSABLE_ENVIRONMENT=0' | sudo tee -a /etc/zprofile
```
**Agents must NEVER set `DISPOSABLE_ENVIRONMENT` themselves.**

Once the variable is `1` and the user has approved in the current session, run freely:
```
uv run pytest --run-destructive-local
```

### Remote destructive tests
The target is whatever this project's configuration points at, so no local
variable can vouch for it — repointing the config would carry a local flag to
an unmarked or production target. The marker lives on the remote target
itself, in whatever form that system supports (resource tag, marker row,
tenant custom field, ...). Two scripts:

- `scripts/mark_remote_disposable.py` — For human use only, during setup.
- `tests/verify_remote_disposable.py` — Checked with every
  `pytest --run-destructive-remote` call. If it fails, tests won't run.

**Agents must NEVER run `mark_remote_disposable.py` or attempt to mark a remote**
**resource as disposable**

If the user has approved running destructive tests in the current session, run freely:
```
uv run pytest --run-destructive-remote
```

#### The marker is generic, and shared between projects
A disposable target is disposable for everyone. Nothing in the marker names a
project, so a throwaway target can be marked once and every repository carrying
this script pair recognises it — no project has to know anything about its
neighbours. Treat the value as a cross-repo contract: changing it breaks every
other repo using the convention.

For an **Entra tenant**, the marker is this address in the organization's
`marketingNotificationEmails`:
```
disposable-environment@example.invalid
```
`marketingNotificationEmails` is used because reading it needs only
`Organization.Read.All`, so no project needs an extra permission just to check.
The `.invalid` TLD is reserved by RFC 2606, so the address can never resolve or
receive mail. It is the remote counterpart of `DISPOSABLE_ENVIRONMENT=1`: one
says *this machine* is throwaway, the other says *this tenant* is.

The value is defined once, as `SENTINEL` in `tests/verify_remote_disposable.py`;
`scripts/mark_remote_disposable.py` imports it so the writer and reader cannot
drift apart.
