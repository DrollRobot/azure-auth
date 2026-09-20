# Agent Rules

## Package Purpose
A collection of clients and helper functions for authentication with Azure, Graph, Exchange, and other Microsoft cloud systems.

## General rules
- Environment values are are stored in the config system. Package config schema
  is defined in src/name/config/schema.py.
- Secrets are stored only in keyvault or keyring. Never in source, never in
  plain-text on disk.

## Code Formatting and Style
- Follow pep8 style guidelines.
- Always include thorough docstrings for all functions and classes.
- Line length limit: 100 characters.
- Use type hints for all function signatures.
- Do not fight automatic formatting. Always commit autoformatting changes, even if
  they're out of scope for the current task.

## pre-commit
- Formatting changes and detect-secrets updates to the .secrets.baseline are routine
  and expected. If all that's required is re-staging and re-committing, this is not
  something worth reporting to the user. Just move on.

## detect-secrets
This repo uses detect-secrets.
- Do not try to work around secret detection by renaming, splitting
  strings, `# pragma: allowlist secret`, or any other means. Let detect-secrets do
  its job. A new entry in the baseline for a user to audit is not a problem to be
  avoided. Simply tell the user an audit is required.
- Baseline updates during pre-commit checks are expected. Do not attempt to revert.
- Agents can/should freely scan for secrets:
```bash
uv run detect-secrets scan --baseline .secrets.baseline
```
- Agents should NEVER regenerate the baseline from scratch.
```bash
detect-secrets scan > .secrets.baseline
```
- Agents should NEVER attempt to audit (users only), or modify the `.secrets.baseline`
  file directly.

## Commit Messages
Review before writing commit messages: [AGENTS.COMMITTING.md](AGENTS.COMMITTING.md).

## Testing
For instructions on writing and running tests: [AGENTS.TESTING.md](AGENTS.TESTING.md).
ALWAYS READ BEFORE WRITING NEW CODE.

## Build and Release
For build and release procedures, see [AGENTS.RELEASING.md](AGENTS.RELEASING.md).
