# Security

## Security model

All MCP servers in this repository are read-only by design. They expose data from Veridise services to AI agents but cannot create, modify, or delete any resource.

## Security invariants

Every server must satisfy these four properties:

1. **Read-only tool surface**: every registered MCP tool is named `get_*`. No mutation-named tool (create, update, delete, patch, post, put, set) is present.

2. **GET-only HTTP**: the sole HTTP helper is hard-wired to the GET method. No POST, PUT, PATCH, or DELETE path exists in any server module. Admin endpoints (`/admin/*`) are excluded.

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
