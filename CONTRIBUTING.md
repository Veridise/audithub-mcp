# Contributing

## Local development setup

1. Install [uv](https://docs.astral.sh/uv/) and Python 3.12+.
2. Clone this repo and `cd` into the repo root, then set up your virtualenv:

```bash
uv venv
uv sync --active
```

3. Run checks inside the virtualenv:

```bash
source ./.venv/bin/activate
ruff check src tests
mypy
pytest
```

## Repository Structure

This repository contains a single MCP server at the repo root:

- package code in `src/audithub_mcp/`
- tests in `tests/`
- configuration examples at the root

The security invariants documented in [AGENTS.md](AGENTS.md) still apply.

## Pull request process

1. Branch off `main`.
2. CI must pass (ruff, mypy, pytest).
3. One approval required.

## Code style

Follow the conventions in [AGENTS.md](AGENTS.md#python-coding-standards).

## Security

All servers must be read-only by design. See [SECURITY.md](SECURITY.md) for the full security model.
