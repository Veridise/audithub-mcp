# AuditHub MCP Server

This repository contains the source code of `audithub-mcp`, an MCP server for
[AuditHub](https://audithub.veridise.com).

`audithub-mcp` allows LLM-based agents to access functionality such as:
* Discovering information about AuditHub organizations and projects
* Launching and monitoring AuditHub tool tasks
* Accessing AuditHub issues and findings

By design, the MCP server limits the functionality to be read-only and non-destructive.
Additional features can be enabled through the configuration file.

> **Warning:** LLMs can make mistakes. Verify all tool outputs manually before acting on them.

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

The development package currently includes a macOS arm64 PAQL executable for local
`validate_paql` testing. This copied build retains a Nix-store tree-sitter dependency and is
not a portable release artifact. On another system, set `PAQL_EXECUTABLE` to a compatible
native PAQL binary or make `paql` available on `PATH`.

## Installation

`audithub-mcp` is implemented as a Python package, but it is not yet available in PyPI.
You must install it directly from this repository.

### Global Installation

If you are using the `uv` package manager, you can install `audithub-mcp` using `uv`:

```
uv tool install 'git+https://github.com/Veridise/audithub-mcp'
audithub-mcp --help
```

### Local Clone

From the repo root:

```bash
uv venv
uv sync --active
```

If your virtual environment is already active and you just want to run the
server entrypoint, use:

```bash
uv run audithub-mcp --help
```

## Using `audithub-mcp`

To use `audithub-mcp`, you need to configure two parts: your agent and the
`audithub-mcp` config file.
Once both are configured, the agent should automatically start the MCP server
and use its tools.

### Agent Configuration

To enable `audithub-mcp` in your agent, you must add it to the MCP server
config for your agent.

The following examples assume that `audithub-mcp` is available on `PATH`, and
that your config file is located at `~/.config/audithub-mcp/config.yaml`.

* Codex CLI
  * For interactive setup, use `codex mcp add audithub-mcp`
  * If you want to set it up with a config file, add the following to your `.codex/config.toml`:
    ```toml
    [mcp_servers.audithub-mcp]
    command = "audithub-mcp"
    args = ["--config", "~/.config/audithub-mcp/config.yaml"]
    ```
* Claude Code
  * For interactive setup, use `claude mcp add audithub-mcp audithub-mcp`
  * If you want to set it up with a config file, add the following to your `.claude/mcp.json`:
    ```json
    {
      "mcpServers": {
        "audithub-mcp": {
          "command": "audithub-mcp",
          "args": [
            "--config",
            "~/.config/audithub-mcp/config.yaml"
          ]
        }
      }
    }
    ```

### MCP Server Configuration

You will need to create a YAML file containing the `audithub-mcp` server
creation and ensure that the agent configuration calls `audithub-mcp` with the
`--config <path>` argument.

If you are not sure where to put the config file, a good default location is in
`~/.config/audithub-mcp/config.yaml`.
The file permissions should be set to `400` (owner read-only) since it contains
credentials.

See the [config docs](./docs/configuration.md) for details on how to create the
configuration file.

## Available MCP Tools

| Tool | Description |
|---|---|
| `get_organizations` | List allowlisted organizations; pass `details=true` for full organization records and `filter_id` to narrow results |
| `get_defi_vanguard_detectors` | List all DeFi Vanguard detectors for an organization using the Vanguard listing block format |
| `get_projects` | List allowlisted projects in an organization; pass `details=true` for full project records and `filter_id` to narrow results |
| `get_versions` | List versions for a project; pass `details=true` for full version records, `filter_id` to narrow results, and `latest_only=true` for the latest version only |
| `get_task_info` | Get status and details for an AuditHub task |
| `get_task_artifacts` | List sanitized artifact metadata for an AuditHub task |
| `get_task_artifact` | Fetch a task artifact by ID as base64-encoded content |
| `get_task_logs` | Get logs for one or more steps of a task and write each result to a local output file |
| `get_task_findings` | Fetch findings for a task and write them to a local output file |
| `wait_for_task_completion` | Poll a task until no pending steps remain or the timeout is reached, then return the latest task snapshot and completion state; with no timeout, task-capable clients can invoke it as a task |
| `parse_findings_from_task_log` | Parse one or more task log files into JSON containing findings plus counts written to a local absolute output path |
| `validate_paql` | Parse a PAQL pattern or Luau query definition with the native PAQL validator; optionally typecheck it against the configured dialect |
| `get_version_comments` | Get comments for a specific project version |
| `get_version_comment_threads` | Get comment threads for a specific project version |
| `get_thread_comments` | Get comments for a specific thread within a project version |
| `get_project_issues` | Get all issues for a project |
| `get_project_issue` | Get a specific issue from a project |
| `get_project_comments` | Get all comments for a project across all versions |
| `help_context` | Get a prompt/instructions on how agents should use the mcp server |
| `run_orca_task` | Start an OrCa task for a project version; registered only when task runs are explicitly enabled |
| `run_defi_vanguard_task` | Start a DeFi Vanguard task for a project version; registered only when task runs are explicitly enabled |
| `create_version_from_file` | Create a project version by uploading a local `.zip` archive; registered only when version creation is explicitly enabled |
| `create_version_from_url` | Create a project version from a git repository or archive URL; registered only when version creation is explicitly enabled |

All tools return typed Python objects backed by `audithub-sdk` models.

The objects returned by `get_organizations`, `get_projects`, and `get_versions`
only exposes items belonging to organizations/projects on the configured
allowlists.

## Available MCP Resources

| Resource | Description |
|---|---|
| `docs://vanguard/custom-detectors` | Vanguard custom-detector documentation resource; the server fetches the linked markdown files on first access, caches the rendered text in memory, and returns the markdown bodies |

## Security Model

- **Read-only by default.** Default tools are named `get_*` and only invoke generated `audithub-sdk` GET endpoints.
- **Task completion polling.** `wait_for_task_completion` repeatedly fetches task details until no pending steps remain or the timeout is reached, then returns the latest sanitized `Task` snapshot with a boolean completion flag. When called with no timeout by a task-capable client, it can run as a task instead of blocking the request.
- **Opt-in OrCa task execution.** The `run_orca_task` mutation tool is registered only when `AH_ENABLE_TASK_RUNS=1` or `--enable-task-runs` is supplied. It calls the generated OrCa POST endpoint through `audithub-sdk`.
- **Opt-in DeFi Vanguard task execution.** The `run_defi_vanguard_task` mutation tool is registered under the same task-run opt-in gate. Its inputs are flattened at the top level: `organization_id`, `project_id`, `version_id`, detector selections, and the runtime options. Pass detector selections as two-item JSON arrays `[type, id]`, where builtin selectors use a built-in detector code from `get_defi_vanguard_detectors`, and custom selectors use the catalog id shown by the same tool. The server resolves those selections through the backend detector catalog before calling the generated DeFi Vanguard v2 POST endpoint.
- **On-chain OrCa mode.** When launching OrCa against already deployed contracts, pass `deployment_info_file` as a path ending in `.deployment.json`. The server normalizes that into `on_chain=True` and rejects mismatched paths early so callers do not accidentally launch a local Foundry-style run.
- **Opt-in version creation.** The `create_version_from_url` mutation tool is registered only when `AH_ENABLE_VERSION_CREATION=1` or `--enable-version-creation` is supplied. It calls the generated project version URL POST endpoint through `audithub-sdk`.
- **Local findings parsing.** The `parse_findings_from_task_log` utility tool reads one or more local task log files, extracts findings with the shared log parser, and writes a JSON file containing the parsed findings plus the total finding count and per-log counts. It does not call the AuditHub API.
- **Local PAQL validation.** The `validate_paql` utility tool invokes the bundled native
  `paql` executable directly without a shell and does not contact AuditHub. An explicitly
  configured `PAQL_EXECUTABLE` takes precedence over the bundle, followed by a `paql`
  executable on `PATH` when the bundle is unavailable. Syntax validation is available by
  default. Typechecking uses the bundled Vanguard Solidity dialect spec; an explicitly
  configured `PAQL_DIALECT_SPEC` overrides it.
- **Detector catalog cache.** The DeFi Vanguard v2 built-in detector list is fetched lazily from the AuditHub configuration endpoint and cached in-process for one day. Custom detectors are fetched live on each request from both the organization library and the standard library.
- **Detector listing format.** `get_defi_vanguard_detectors` returns one block per detector. Each block starts with `detector: <json>` where `<json>` is a JSON value matching `DefiVanguardV2DetectorSelectionInput`, followed by `title:`. Standard-library custom detectors also include `description:` loaded from the detector payload. Each block ends with `------`.
- **Credential isolation.** OIDC credentials are read from the environment once at startup and passed into `audithub_sdk_ext.AuthenticatedApiClient`. They are never accepted as tool arguments and are not surfaced in tool outputs or sanitized error messages.
- **ID allowlisting.** The server refuses to access any organization or project whose numeric ID was not explicitly included in `AH_ALLOWED_ORG_IDS` / `AH_ALLOWED_PROJECT_IDS`. The check runs before any network request.
- **SDK-only transport.** All AuditHub interaction flows through `audithub-sdk` and `audithub_sdk_ext`; there is no raw HTTP helper in the MCP server.

## Development Workflow

- Run tests: `uv run pytest`
- Type check: `uv run mypy`
- Lint: `uv run ruff check`
- Format code: `uv run ruff format`

### Override `audithub-sdk` Locally

To test `audithub-mcp` against a local checkout of `audithub-sdk`, add a path source
override in the root [`pyproject.toml`](./pyproject.toml), then re-sync the
environment.

Example root `pyproject.toml` override:

```toml
[tool.uv.sources]
audithub-sdk = { path = "/absolute/path/to/audithub-sdk", editable = true }
```

Then run:

```bash
uv sync --active
```

To return to the pinned version, remove the `audithub-sdk` entry from
`[tool.uv.sources]` and run `uv sync --active` again.

## License

[Apache 2.0](./LICENSE)
