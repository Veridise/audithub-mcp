# Architecture

This file describes the overall architecture of the Veridise MCP servers.
Each server exposes a Veridise data source via the Model Context Protocol.

## Structure

This repository contains a single MCP server, `audithub-mcp`, with package code in
`src/audithub_mcp/`, tests in `tests/`, and configuration examples at the repo root.

## Security invariants

Every server must satisfy four requirements:

1. **Explicitly scoped tool surface**: every tool must be narrowly scoped and
   documented. Mutation tools must have clear authorization and bounded effects.
2. **Least-privilege HTTP surface**: expose only the HTTP methods and paths a
   server needs. Admin endpoints must not be exposed.
3. **Credential isolation**: secrets come from configuration files or
   environment variables, read once at startup. Never include credentials in
   tool output, error messages, or logs.
4. **ID allowlisting**: access is restricted to explicitly configured IDs, such
   as organization and project IDs.
   Reject disallowed IDs on the client side before making any network request.
   Error messages must not enumerate the full allowlist.
