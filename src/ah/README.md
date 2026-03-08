# ah-mcp

Read-only MCP server for [AuditHub](https://audithub.veridise.com). Exposes AuditHub data (organizations, projects, versions, issues, comments, tasks) as MCP tools that an AI agent can call. No write operations are possible.

> **Warning:** This server is currently under-developed and has not been tested. Verify all tool outputs manually before acting on them.

---

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- `audithub-client` (private library -- must be installed separately)

## Installation

```bash
# Install the private dependency from your local clone
uv pip install -e /path/to/AuditHub-Client

# Runtime only
uv pip install -e .

# Runtime + dev tools (ruff, mypy, pytest)
uv pip install -e ".[dev]"
```

## Configuration

All credentials are read from environment variables. Copy `.env.example` to `.env` and populate the values before starting the server.

| Variable | Required | Description |
|---|---|---|
| `AUDITHUB_BASE_URL` | Yes | Base URL of the AuditHub REST API, e.g. `https://audithub.veridise.com/api/v1` |
| `AUDITHUB_OIDC_CONFIGURATION_URL` | Yes | OpenID Connect discovery document URL for the identity provider |
| `AUDITHUB_OIDC_CLIENT_ID` | Yes | OIDC client identifier |
| `AUDITHUB_OIDC_CLIENT_SECRET` | Yes | OIDC client secret -- keep out of logs and shell history |
| `AH_ALLOWED_ORG_IDS` | Yes | Comma-separated list of numeric organization IDs the server may access, e.g. `"1,2,3"` |
| `AH_ALLOWED_PROJECT_IDS` | Yes | Comma-separated list of numeric project IDs the server may access, e.g. `"10,20"` |

CLI flags `--allowed-org-ids` and `--allowed-project-ids` override the corresponding environment variables when both are supplied.

## Running the server

Copy `.env.example` to `.env`, fill in your values, then:

```bash
set -a && source .env && set +a && ah-mcp
```

All six variables in `.env` must be set before the server starts. Missing variables cause an immediate exit with a clear error listing which are absent.

## Configure for agents

All credentials are loaded from your `.env` file — nothing secret goes in the agent config.

Add to your agent's MCP configuration (e.g. `.codex/config.json` for Codex, `.claude/mcp.json` for Claude Code, or your ChatGPT Desktop MCP config):

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

Replace `/absolute/path/to/ah.env` with the actual path to your `.env` file. Your `.env` file (see `.env.example`) holds all credentials and allowlist IDs; no secrets belong in the agent config file.

## Available MCP tools

| Tool | Description |
|---|---|
| `get_my_organizations` | List all AuditHub organizations the authenticated user belongs to |
| `get_project` | Get details for a specific project |
| `get_latest_version` | Get the latest version of a project |
| `get_task_info` | Get status and details for an AuditHub task |
| `get_task_logs` | Get logs for a specific step of a task |
| `get_version_comments` | Get comments for a specific project version |
| `get_version_comment_threads` | Get comment threads for a specific project version |
| `get_project_issues` | Get all issues for a project |
| `get_project_issue` | Get a specific issue from a project |
| `get_project_comments` | Get all comments for a project across all versions |

All tools return typed Python objects. On error, tools raise ``RuntimeError`` with a plain-text message; the MCP protocol surfaces this as an error response to the caller.

## Security model

- **Read-only by design.** Every tool is named `get_*` and every HTTP call goes through `_get()`, which is hard-wired to the `GET` method. No `POST`, `PATCH`, `PUT`, or `DELETE` path exists in the server code.
- **Credential isolation.** OIDC credentials are read from the environment once at startup and never echoed in tool return values, log output, or error messages. Exceptions from the underlying HTTP/OIDC library are caught and re-serialised before reaching the MCP caller.
- **ID allowlisting.** The server refuses to access any organization or project whose numeric ID was not explicitly included in `AH_ALLOWED_ORG_IDS` / `AH_ALLOWED_PROJECT_IDS`. The check runs before any network request.
- **GET-only HTTP.** The sole HTTP helper accepts no method argument and is imported from `audithub_client.library.http` as the `GET` constant. Admin endpoints (`/admin/*`) are not called.

## Development

```bash
make help       # list all targets
make dev-install
make test
make check      # lint + type-check
```
