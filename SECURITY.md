# Security

## Security model

MCP servers in this repository are read-only by default. They expose data from Veridise services to AI agents and cannot create, modify, or delete resources unless a server documents an explicit opt-in mutation mode.

## Security invariants

Every server must satisfy these four properties:

1. **Default read-only tool surface**: default registered MCP tools are named `get_*`. Mutation-named tools require an explicit opt-in gate and narrowly scoped security tests.

2. **Default GET-only HTTP**: read-only tools only invoke GET paths. POST, PUT, PATCH, and DELETE paths require a documented opt-in mutation mode. Admin endpoints (`/admin/*`) are always excluded.

3. **Credential isolation**: OIDC credentials are read from environment variables once at server startup. They are never echoed in tool return values, error messages, or log output. Exceptions from underlying HTTP/OIDC libraries are caught and re-raised as sanitized `RuntimeError` instances before reaching the MCP caller.

4. **ID allowlisting**: servers require explicit allowlists of permitted resource IDs, configured at startup via environment variables or CLI flags. All ID parameters use strict Pydantic validation (integer type, positive value). Disallowed IDs are rejected before any network request. Error messages report the rejected ID but do not enumerate the full allowlist.

## Reporting security issues

If you discover a security vulnerability, please report it to **security@veridise.com**. Do not open a public issue.

## Responsible disclosure

We ask that you:

1. Report the vulnerability privately via email.
2. Give us reasonable time to address the issue before public disclosure.
3. Avoid exploiting the vulnerability beyond what is necessary to demonstrate it.

We will acknowledge receipt within 2 business days and aim to provide a fix or mitigation plan within 7 days.
