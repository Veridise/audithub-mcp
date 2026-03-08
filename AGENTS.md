# Agents

Instructions for AI agents (Codex, ChatGPT, and others) working in this repository.

## Repository purpose

Monorepo of read-only MCP servers for Veridise tooling. Each server exposes a Veridise data source via the Model Context Protocol.

## Structure

Each server lives in `src/<name>/` as a self-contained Python package with its own `pyproject.toml`, tests, and configuration.

## Tooling

- Python 3.12+
- `uv` (not pip or poetry) for dependency management
- `ruff` for linting and formatting
- `mypy` (strict mode) for type checking
- `pytest` for test runner

## Security invariants

These are non-negotiable. Every server must satisfy all four:

1. **Read-only tool surface**: every tool name starts with `get_`. No tool may create, modify, or delete resources.
2. **GET-only HTTP**: no POST/PUT/PATCH/DELETE paths. The HTTP helper is hard-wired to GET.
3. **Credential isolation**: secrets come from environment variables, read once at startup. Never include credentials in tool output, error messages, or logs.
4. **ID allowlisting**: access is restricted to explicitly configured IDs. Reject disallowed IDs before making any network request. Error messages must not enumerate the full allowlist.

## Python coding standards

- Use domain types, not primitives: define Pydantic models, dataclasses, NamedTuples, or newtypes instead of raw `str`, `dict`, `tuple`, `list`. If the object has semantic meaning (an org ID, a comment, a project), it gets a type.
- `dict` is for genuinely unstructured key-value data (e.g. JSON passthrough). `tuple` is for fixed-length heterogeneous sequences. `str` is for actual text. Don't use them as poor-man's structs.
- Type every function signature -- parameters and return types. Use `Annotated[...]` with `Field()` constraints where the type has bounds (e.g. positive int IDs).
- Prefer `TypeAdapter` for validating list/union responses from external APIs.
- No `Any` unless interfacing with genuinely untyped external data -- add a comment explaining why.
- Absolute imports only -- no relative (`..`) paths.
- Google-style docstrings on public APIs.
- 100-char line length.

## Working rules

- Each server is independent: changes to one should not break another.
- Use `uv` for all Python dependency operations.
- Run `ruff check`, `mypy`, and `pytest` before committing.

## Per-server dev workflow

```bash
cd src/<name>
uv venv && uv pip install -e ".[dev]"
ruff check src tests
mypy
pytest
```

## Adding a new server

1. Create `src/<name>/` directory.
2. Add `pyproject.toml` with `mcp>=1.0.0` dependency.
3. Add `.python-version` file.
4. Implement tools following the security invariants above.
5. Add security tests (read-only surface, allowlist enforcement, credential isolation).
6. Update root `README.md` server table.
7. Add the server to the CI matrix in `.github/workflows/python.yml`.

## Testing

Tests stub private libraries via `sys.modules` so they run in CI without proprietary dependencies. Test security properties explicitly:

- Read-only tool surface (all tool names start with `get_`)
- Allowlist enforcement (disallowed IDs rejected before network calls)
- Credential isolation (exceptions sanitized, secrets not in output)

## Do not

- Add mutation tools (POST/PUT/PATCH/DELETE).
- Install private libraries in CI.
- Use relative imports.
- Use raw `dict`/`str`/`tuple` for domain objects.
- Skip security tests when adding new tools.
