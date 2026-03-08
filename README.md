# MCP Servers

Veridise MCP servers for AI-assisted auditing. Each server exposes read-only access to a Veridise data source via the [Model Context Protocol](https://modelcontextprotocol.io/).

| Server | Path | Data source | Access | Status |
|---|---|---|---|---|
| `ah` | `src/ah/` | AuditHub API | Read-only | Alpha |

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- `audithub-client` (private library, installed from a local clone)

## Quick install

```bash
# Install the private dependency from your local clone
uv pip install -e /path/to/AuditHub-Client

# Install a server (e.g. ah)
uv pip install -e src/ah
```

## Configuration

Copy `src/ah/.env.example` to `src/ah/.env` and fill in your AuditHub credentials.

### Configure your agent

All credentials are loaded from your `.env` file — nothing secret goes in the agent config.

Add to your agent's MCP configuration file (`.codex/config.json` for Codex, `.claude/mcp.json` for Claude Code, or your ChatGPT Desktop MCP config):

```json
{
  "mcpServers": {
    "ah": {
      "command": "bash",
      "args": ["-c", "set -a && source /absolute/path/to/ah.env && set +a && ah-mcp"]
    }
  }
}
```

Replace `/absolute/path/to/ah.env` with the actual path to your `.env` file (see `src/ah/.env.example`). The `.env` file should contain all credentials and allowlist settings; no secrets belong in the agent config file.

## Security model

All servers in this repo are read-only by design:

1. **Read-only tool surface** -- every tool name starts with `get_`
2. **GET-only HTTP** -- no POST/PUT/PATCH/DELETE paths exist
3. **Credential isolation** -- secrets from env vars, never in tool output
4. **ID allowlisting** -- access restricted to configured IDs

## Adding a new server

1. Create `src/<name>/` with its own `pyproject.toml` and `.python-version`
2. Add `mcp>=1.0.0` as a dependency
3. Implement read-only tools following the `ah` server as a template
4. Add security tests (read-only surface, allowlist enforcement, credential isolation)
5. Update the server table in this README
6. Add the server to the CI matrix in `.github/workflows/python.yml`

## License

[Apache 2.0](LICENSE)
