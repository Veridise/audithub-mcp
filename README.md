# MCP Servers

Veridise MCP servers for AI-assisted auditing. Each server exposes a Veridise data source via the [Model Context Protocol](https://modelcontextprotocol.io/). Servers are read-only by default unless an opt-in mutation mode is documented for that server.

| Server | Path | Data source | Access | Status |
|---|---|---|---|---|
| `ah` | `src/ah/` | AuditHub API | Read-only by default; opt-in OrCa task runs | Alpha |

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Quick install

```bash
# From the repo root, install the workspace and default dev tooling into the active virtual environment
uv sync --active
```

## Configuration

See the [config docs](./docs/configuration.md) for details on how to configure
`ah-mcp`.

### Configure your agent

Once you have decided on how to configure `ah-mcp`, you must enable it in your
agent's MCP configuration file (`.codex/config.json` for Codex,
`.claude/mcp.json` for Claude Code, or your ChatGPT Desktop MCP config).

For a JSON/YAML file `ah-mcp` config, copy `src/ah/.env.example` to a fixed
location and fill in the required settings.
The MCP server config should pass the config directly to `ah-mcp`:

```json
{
  "mcpServers": {
    "ah": {
      "command": "ah-mcp",
      "args": [
        "--config",
        "/absolute/path/to/your/ah-mcp-config.json"
      ]
    }
  }
}
```

To configure `ah-mcp` through environment variables only, copy
`src/ah/.env.example` to a fixed location and fill in the required settings.
The MCP server config should load the environment before starting `ah-mcp`:

```json
{
  "mcpServers": {
    "ah": {
      "command": "bash",
      "args": [
        "-c",
        "cd /absolute/path/to/mcp-servers && set -a && source /absolute/path/to/ah.env && set +a && uv run ah-mcp"
      ]
    }
  }
}
```

Replace `/absolute/path/to/ah.env` with the actual path to your `.env` file (see `src/ah/.env.example`).
The `ah-mcp` configuration should contain all credentials and allowlist
settings; no secrets should be configured in the agent config file itself.

## Security model

All servers in this repo are read-only by default:

1. **Default read-only tool surface** -- default tools start with `get_`
2. **Default GET-only HTTP** -- mutation paths are absent unless explicitly enabled
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
