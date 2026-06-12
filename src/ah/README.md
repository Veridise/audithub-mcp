# ah-mcp

MCP server for [AuditHub](https://audithub.veridise.com). By default it exposes
read-only AuditHub data.
It can also expose opt-in mutating/side-effecting tools for starting tasks and
creating project versions.

> **Warning:** This server is currently under-developed and has not been tested. Verify all tool outputs manually before acting on them.

---

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Installation

```bash
# From the repo root, install the workspace and default dev tooling into the active virtual environment
uv sync --active
```

If your virtual environment is not already activated, run the command through `uv` instead:

```bash
uv run ah-mcp --help
```

## Override `audithub-sdk` Locally

To test `ah-mcp` against a local checkout of `audithub-sdk`, add a path source override in the
workspace root [`pyproject.toml`](../../pyproject.toml), then re-sync the environment.

Example root `pyproject.toml` override:

```toml
[tool.uv.sources]
ah-mcp = { workspace = true }
audithub-sdk = { path = "/absolute/path/to/audithub-sdk", editable = true }
```

Then run:

```bash
uv sync --active
```

This keeps `ah-mcp` installed from the workspace while forcing `audithub-sdk` to resolve from the
local filesystem checkout in editable mode.

To return to the pinned version, remove the `audithub-sdk` entry from
`[tool.uv.sources]` in the workspace root and run `uv sync --active` again.

## Configuration

All credentials are read from environment variables and passed into the SDK auth layer at startup.

| Variable | Required | Description |
|---|---|---|
| `AUDITHUB_BASE_URL` | Yes | Base URL of the AuditHub REST API, e.g. `https://audithub.veridise.com/api/v1` |
| `AUDITHUB_OIDC_CONFIGURATION_URL` | Yes | OpenID Connect discovery document URL for the identity provider |
| `AUDITHUB_OIDC_CLIENT_ID` | Yes | OIDC client identifier |
| `AUDITHUB_OIDC_CLIENT_SECRET` | Yes | OIDC client secret -- keep out of logs and shell history |
| `AH_ALLOWED_ORG_IDS` | Yes | Comma-separated list of numeric organization IDs the server may access, e.g. `"1,2,3"` |
| `AH_ALLOWED_PROJECT_IDS` | Yes | Comma-separated list of numeric project IDs the server may access, e.g. `"10,20"` |
| `AH_ENABLE_TASK_RUNS` | No | Set to `1` to register the opt-in tools for AuditHub tasks; in config files, set `capabilities.task_runs: true` |
| `AH_ENABLE_VERSION_CREATION` | No | Set to `1` to register the opt-in `create_version_from_url` mutation tool; in config files, set `capabilities.version_creation: true` |

CLI flags `--allowed-org-ids` and `--allowed-project-ids` override the corresponding environment variables when both are supplied. Use `--enable-task-runs` to register the task tools without setting `AH_ENABLE_TASK_RUNS`, or `--enable-version-creation` to register `create_version_from_url` without setting `AH_ENABLE_VERSION_CREATION`.

Custom detector uploads are config-file only for now: set `capabilities.edit_custom_detectors: true` to register `upload_custom_detector`.

## Running the server

Copy `.env.example` to `.env`, fill in your values, then:

```bash
set -a && source .env && set +a && uv run ah-mcp
```

All required variables in `.env` must be set before the server starts. Missing variables cause an immediate exit with a clear error listing which are absent.

To print the registered MCP tools and their JSON schemas without starting the server, run:

```bash
uv run ah-mcp --list-tools
```

## Configure for agents

All credentials are loaded from your `.env` file — nothing secret goes in the agent config.

Add to your agent's MCP configuration (e.g. `.codex/config.json` for Codex, `.claude/mcp.json` for Claude Code, or your ChatGPT Desktop MCP config):

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

Replace `/absolute/path/to/mcp-servers` with this repository path and `/absolute/path/to/ah.env`
with the actual path to your `.env` file. Your `.env` file (see `.env.example`) holds all
credentials and allowlist IDs; no secrets belong in the agent config file.

## Available MCP tools

| Tool | Description |
|---|---|
| `get_my_organizations` | List all AuditHub organizations the authenticated user belongs to |
| `get_organization_name_index` | List allowlisted organizations as deterministic name-to-ID lookup entries |
| `get_defi_vanguard_detectors` | List all DeFi Vanguard detectors for an organization using the Vanguard listing block format |
| `get_project` | Get details for a specific project |
| `get_project_name_index` | List allowlisted projects in an organization as deterministic name-to-ID lookup entries |
| `get_latest_version` | Get the latest version of a project |
| `get_version_name_index` | List project versions as deterministic name-to-ID lookup entries |
| `get_task_info` | Get status and details for an AuditHub task |
| `get_task_artifacts` | List sanitized artifact metadata for an AuditHub task |
| `get_task_artifact` | Fetch a task artifact by ID as base64-encoded content |
| `get_task_logs` | Get logs for one or more steps of a task and write each result to a local output file |
| `get_task_findings` | Fetch findings for a task and write them to a local output file |
| `wait_for_task_completion` | Poll a task until no pending steps remain or the timeout is reached, then return the latest task snapshot and completion state; with no timeout, task-capable clients can invoke it as a task |
| `parse_findings_from_task_log` | Parse one or more task log files into JSON containing findings plus counts written to a local absolute output path |
| `get_version_comments` | Get comments for a specific project version |
| `get_version_comment_threads` | Get comment threads for a specific project version |
| `get_thread_comments` | Get comments for a specific thread within a project version |
| `get_project_issues` | Get all issues for a project |
| `get_project_issue` | Get a specific issue from a project |
| `get_project_comments` | Get all comments for a project across all versions |
| `run_orca_task` | Start an OrCa task for a project version; registered only when task runs are explicitly enabled |
| `run_defi_vanguard_task` | Start a DeFi Vanguard task for a project version; registered only when task runs are explicitly enabled |
| `create_version_from_file` | Create a project version by uploading a local `.zip` archive; registered only when version creation is explicitly enabled |
| `create_version_from_url` | Create a project version from a git repository or archive URL; registered only when version creation is explicitly enabled |

All tools return typed Python objects backed by `audithub-sdk` models. On error, tools raise `RuntimeError` with a sanitized plain-text message; the MCP protocol surfaces this as an error response to the caller.

The name index tools only expose organizations and projects that already pass the configured
allowlists. Version name lookup requires an allowlisted organization and project. These tools help
callers resolve stable human-readable names to internal AuditHub IDs before invoking the existing
ID-based tools.

## Security model

- **Read-only by default.** Default tools are named `get_*` and only invoke generated `audithub-sdk` GET endpoints.
- **Task completion polling.** `wait_for_task_completion` repeatedly fetches task details until no pending steps remain or the timeout is reached, then returns the latest sanitized `Task` snapshot with a boolean completion flag. When called with no timeout by a task-capable client, it can run as a task instead of blocking the request.
- **Opt-in OrCa task execution.** The `run_orca_task` mutation tool is registered only when `AH_ENABLE_TASK_RUNS=1` or `--enable-task-runs` is supplied. It calls the generated OrCa POST endpoint through `audithub-sdk`.
- **Opt-in DeFi Vanguard task execution.** The `run_defi_vanguard_task` mutation tool is registered under the same task-run opt-in gate. Its inputs are flattened at the top level: `organization_id`, `project_id`, `version_id`, detector selections, and the runtime options. Pass detector selections as two-item JSON arrays `[type, id]`, where builtin selectors use a built-in detector code from `get_defi_vanguard_detectors`, and custom selectors use the catalog id shown by the same tool. The server resolves those selections through the backend detector catalog before calling the generated DeFi Vanguard v2 POST endpoint.
- **On-chain OrCa mode.** When launching OrCa against already deployed contracts, pass `deployment_info_file` as a path ending in `.deployment.json`. The server normalizes that into `on_chain=True` and rejects mismatched paths early so callers do not accidentally launch a local Foundry-style run.
- **Opt-in version creation.** The `create_version_from_url` mutation tool is registered only when `AH_ENABLE_VERSION_CREATION=1` or `--enable-version-creation` is supplied. It calls the generated project version URL POST endpoint through `audithub-sdk`.
- **Local findings parsing.** The `parse_findings_from_task_log` utility tool reads one or more local task log files, extracts findings with the shared log parser, and writes a JSON file containing the parsed findings plus the total finding count and per-log counts. It does not call the AuditHub API.
- **Detector catalog cache.** The DeFi Vanguard v2 built-in detector list is fetched lazily from the AuditHub configuration endpoint and cached in-process for one day. Custom detectors are fetched live on each request from both the organization library and the standard library.
- **Detector listing format.** `get_defi_vanguard_detectors` returns one block per detector. Each block starts with `detector: <json>` where `<json>` is a JSON value matching `DefiVanguardV2DetectorSelectionInput`, followed by `title:`. Standard-library custom detectors also include `description:` loaded from the detector payload. Each block ends with `------`.
- **Credential isolation.** OIDC credentials are read from the environment once at startup and passed into `audithub_sdk_ext.AuthenticatedApiClient`. They are never accepted as tool arguments and are not surfaced in tool outputs or sanitized error messages.
- **ID allowlisting.** The server refuses to access any organization or project whose numeric ID was not explicitly included in `AH_ALLOWED_ORG_IDS` / `AH_ALLOWED_PROJECT_IDS`. The check runs before any network request.
- **SDK-only transport.** All AuditHub interaction flows through `audithub-sdk` and `audithub_sdk_ext`; there is no raw HTTP helper in the MCP server.

## Development Workflow

* Run tests: `pytest`
* Type check: `mypy .`
* Format code: `ruff format`
