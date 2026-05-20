# LLM Conventions

This file contains conventions that LLM agents must follow.

## Python coding standards

- Use domain types, not primitives: define Pydantic models, dataclasses,
  NamedTuples, or newtypes instead of raw `str`, `dict`, `tuple`, `list`.
  If the object has semantic meaning (an org ID, a comment, a project), it gets
  a type.
- `dict` is for genuinely unstructured key-value data (e.g. JSON passthrough).
  `tuple` is for fixed-length heterogeneous sequences.
  `str` is for actual text.
  Don't use them as poor-man's structs.
- Type every function signature: parameters and return types.
  Use `Annotated[...]` with `Field()` constraints where the type has bounds
  (e.g. positive int IDs).
- Prefer `TypeAdapter` for validating list/union responses from external APIs.
- No `Any` unless interfacing with genuinely untyped external data; add a comment
  explaining why.
- Absolute imports only; no relative (`..`) paths.
- Google-style docstrings on public APIs.

## Working rules

- Each server is independent: changes to one should not break another.

## Testing

Tests stub private libraries via `sys.modules` so they run in CI without
proprietary dependencies. Test security properties explicitly:

- Tool surface behavior and any mutation authorization gates
- Allowlist enforcement (disallowed IDs rejected before network calls)
- Credential isolation (exceptions sanitized, secrets not in output)

## Do not

- Use relative imports.
- Use raw `dict`/`str`/`tuple` for domain objects.
- Skip security tests when adding new tools.
