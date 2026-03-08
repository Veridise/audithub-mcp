# Contributing

## Local development setup

1. Install [uv](https://docs.astral.sh/uv/) and Python 3.12+.
2. Clone this repo and `cd` into a server directory:

```bash
cd src/ah
uv venv
uv pip install -e ".[dev]"
```

3. Run checks:

```bash
ruff check src tests
mypy
pytest
```

## Adding a new server

Follow the checklist in [AGENTS.md](AGENTS.md#adding-a-new-server). All servers must satisfy the security invariants documented there.

## Pull request process

1. Branch off `main`.
2. CI must pass (ruff, mypy, pytest).
3. One approval required.

## Code style

Follow the conventions in [AGENTS.md](AGENTS.md#python-coding-standards).

## Security

All servers must be read-only by design. See [SECURITY.md](SECURITY.md) for the full security model.
