# Architecture

This file describes the overall architecture of the Veridise MCP servers.
Each server exposes a Veridise data source via the Model Context Protocol.

## Structure

This repository contains a single MCP server, `audithub-mcp`, with package code in
`src/audithub_mcp/`, tests in `tests/`, and configuration examples at the repo root.

## MCP runtime

The server uses the MCP Python SDK v2 `MCPServer` API. HTTP host, port, and
transport security settings are passed to `run()`. Protocol models use snake_case
Python attributes; the `--list-tools` JSON output retains MCP wire names such as
`inputSchema` through alias serialization. Sanitized tool failures use `ToolError`
so clients receive actionable messages without exposing the underlying exceptions.

The SDK v2 migration removes the experimental MCP background-task runtime.
`wait_for_task_completion` polls AuditHub inline and returns a task snapshot and
completion flag. Clients should supply a timeout below their tool call timeout
and repeat the call if the task is still pending; omitting the timeout waits until
completion. AuditHub task creation remains available through the existing opt-in
tools. See the [SDK migration guide](https://py.sdk.modelcontextprotocol.io/migration/).

## Security invariants

Every server must satisfy four requirements:

1. **Explicitly scoped tool surface**: every tool must be narrowly scoped and
   documented. Mutation tools must have clear authorization and bounded effects.
2. **Least-privilege HTTP surface**: expose only the HTTP methods and paths a
   server needs. AuditHub admin endpoints must not be exposed. Local operational
   endpoints must be opt-in, independently authenticated, and excluded from the
   MCP tool surface.
3. **Credential isolation**: credentials come from configuration files or
   environment variables and are read once at startup. Generated operational
   secrets are written only to explicitly configured protected files. Never
   include credentials or secrets in tool output, error messages, or logs.
4. **ID allowlisting**: access is restricted to explicitly configured IDs, such
   as organization and project IDs.
   Reject disallowed IDs on the client side before making any network request.
   Error messages must not enumerate the full allowlist.
