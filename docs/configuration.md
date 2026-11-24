# Configuration

## How-to

`audithub-mcp` can be configured in three ways:

1. Config file only (**Recommended**).
   - Pass `--config <path> --no-env-config` to load settings from the file without applying
     environment overrides.
2. Config file plus environment overrides.
   - Pass `--config <path>` to load settings from a JSON or YAML file first.
   - By default, environment variables still override values from the file.
3. Environment variables only (**Deprecated due to security risks, prefer config files**).
   - Set the required `AUDITHUB_*` credential environment variables and the
     `AH_ALLOWED_*` environment variables in the shell environment before
     starting the server.

CLI flags can also override the allowlist and feature toggles after the base settings are loaded:

- `--allowed-org-ids`
- `--writable-org-ids`
- `--allowed-project-ids`
- `--enable-project-creation`
- `--enable-task-runs`
- `--enable-version-creation`
- `--enable-edit-custom-detectors`

Use CLI overrides when you want a temporary change without editing the config file or exporting
new environment variables.

### Local HTTP Shutdown

Local Streamable HTTP mode can optionally expose an authenticated operational endpoint that
gracefully exits the server process:

```bash
audithub-mcp \
  --local-http-server \
  --local-http-port 8000 \
  --shutdown-secret-file /shared/audithub-mcp-shutdown-token
```

When `--shutdown-secret-file PATH` is supplied, the server generates a fresh random secret at
startup and atomically writes it to `PATH` with owner-only (`0600`) permissions. The parent
directory must already exist. Send `POST /shutdown` with the file contents as a bearer token:

```http
POST /shutdown
Authorization: Bearer <generated-secret>
```

An authenticated request returns HTTP 202 and then sends `SIGTERM` to the server process so the
HTTP runtime can perform graceful shutdown. The route is not an MCP tool and is not included in
MCP discovery. Without `--shutdown-secret-file`, it returns HTTP 404. The option is rejected
outside local HTTP mode.

In multi-container deployments, place the output file on a volume mounted only into the MCP
server and its authorized controller. Do not mount that volume into the agent container. The
orchestrator remains responsible for its container restart policy after the server exits.

## Configuration Reference

The JSON and YAML config file uses the same keys listed below. Environment variables use the same
values when `--config` is not supplied, or when `--config` is supplied without `--no-env-config`.

Notes:
- boolean values such as `AH_ENABLE_*` accept `1/0`, `true/false`, `yes/no`, and `on/off`.

### PAQL Validator

The read-only `validate_paql` tool uses the bundled Emscripten WebAssembly build of PAQL. A
cross-platform Node.js runtime is installed through uv as part of the Python package; operators
do not need to install Node.js or PAQL separately.

- `PAQL_NODE_EXECUTABLE` (optional)
  - Path to an alternative Node.js executable used to host the PAQL WebAssembly module.
  - Omit it to use the runtime installed by the `nodejs-wheel` dependency.
- `PAQL_WASM_MODULE` (optional)
  - Path to an alternative Emscripten JavaScript module.
  - Its paired `.wasm` file must have the same basename and reside in the same directory.
  - Omit it to use the bundled `paql-wasm.js` and `paql-wasm.wasm` files.
- `PAQL_DIALECT_SPEC` (optional)
  - Path overriding the bundled Vanguard Solidity dialect spec used when `validate_paql`
    receives `typecheck=true`.
  - Omit it to use the bundled Solidity dialect.

### Required

The following options need to be set from an AuditHub API key; instructions on
how to generate one can be found [here](https://docs.audithub.dev/saas/guide/pages/account_settings/API_keys).

- `audithub_base_url` (string)
  - Base URL for the AuditHub REST API.
  - Environment variable: `AUDITHUB_BASE_URL`
- `audithub_oidc_configuration_url` (string)
  - OIDC discovery URL used to authenticate with AuditHub.
  - Environment variable: `AUDITHUB_OIDC_CONFIGURATION_URL`
- `audithub_oidc_client_id` (string)
  - OIDC client identifier.
  - Environment variable: `AUDITHUB_OIDC_CLIENT_ID`
- `audithub_oidc_client_secret` (string)
  - OIDC client secret. Keep this out of logs and shell history.
  - Environment variable: `AUDITHUB_OIDC_CLIENT_SECRET`

For security reasons, you must also explicitly allowlist the set of organization
and projects that the MCP server provides access to.

- `allowed_org_ids` (array of positive integers)
  - Non-empty list of organization IDs the server may access.
  - Environment variable: `AH_ALLOWED_ORG_IDS`
    - Environment format: comma-separated positive integers, for example `1,2,3`.
  - Can also be overridden on the command-line using `--allowed-org-ids id1,id2,...`
- `allowed_project_ids` (array of positive integers)
  - Project IDs the server may access. Use an empty list to create a first project
    when project creation is enabled for at least one writable organization.
    Other configurations require at least one project ID.
  - Environment variable: `AH_ALLOWED_PROJECT_IDS`
    - Environment format: comma-separated positive integers, for example `10,20`.
  - Can also be overridden on the command-line using `--allowed-project-ids id1,id2,...`

### Optional Capabilities

By default, the MCP server only exposes tools for read-only functionality.
You must explicitly opt-in to state-changing / destruction tools by setting the
appropriate `capabilities` options.

- `capabilities` (object)
  - Optional feature toggles for state-changing features.
  - `project_creation` (boolean)
    - Set to `true` to register `create_project`. The default is `false`.
    - Set `AH_ENABLE_PROJECT_CREATION=1` or pass `--enable-project-creation` to enable it at startup.
  - `task_runs` (boolean)
    - Set to `true` to enable tools for executing AuditHub tasks. Default: `false`.
    - Environment variable: `AH_ENABLE_TASK_RUNS`
      - Environment format: truthy or falsy string values. Accepted truthy values are `1`,
        `true`, `yes`, and `on`. Accepted falsy values are `0`, `false`, `no`, and `off`.
  - `version_creation` (boolean)
    - Set to `true` to enable tools for uploading source code to AuditHub. Default: `false`.
    - Environment variable: `AH_ENABLE_VERSION_CREATION`
      - Environment format: truthy or falsy string values. Accepted truthy values are `1`,
        `true`, `yes`, and `on`. Accepted falsy values are `0`, `false`, `no`, and `off`.
  - `edit_custom_detectors` (boolean)
    - Set to `true` to enable `upload_custom_detector` for organization-level custom
      detectors. Default: `false`.
    - Command-line override: `--enable-edit-custom-detectors`.
    - The tool accepts inline detector source text via `contents`. A local `file_path`
      remains available for same-machine workflows, but remote MCP clients should pass
      the detector text directly.
    - Tool input contract:
      - Provide either `contents` or `file_path`.
      - `filename` is required when creating a detector.
      - `update` selects an existing detector to replace; when updating, `filename` is optional.
      - If both `contents` and `file_path` are supplied, the inline `contents` value is used.
      - `file_path` should be an absolute path to a local detector file.
    - Examples:
      - Create a detector from inline text:
        `upload_custom_detector(organization_id=1, contents="...", filename="foo.luau")`
      - Create a detector from a local file:
        `upload_custom_detector(organization_id=1, file_path="/abs/path/foo.luau", filename="foo.luau")`
      - Update detector `42` using inline text:
        `upload_custom_detector(organization_id=1, contents="...", update=42)`
      - Update detector `42` and rename it:
        `upload_custom_detector(organization_id=1, contents="...", filename="bar.luau", update=42)`

### Project creation and Scout reviews

Both tools require the target organization ID in `writable_org_ids`, an optional
subset of `allowed_org_ids` that defaults to an empty list. Set it in the config
file, with `AH_WRITABLE_ORG_IDS`, or with `--writable-org-ids`. The environment
variable and CLI flag accept comma-separated IDs. AuditHub also checks the
authenticated account's project-creation or Scout task permissions on each request.

```yaml
allowed_org_ids: [1, 2]
writable_org_ids: [1]
allowed_project_ids: [10]
capabilities:
  project_creation: true
  task_runs: true
```

#### Creating a project

Call `create_project` with these arguments to import a GitHub tag as the project's
first version.

```json
{
  "organization_id": 1,
  "name": "OpenZeppelin Contracts",
  "input_info": {
    "input_type": "git",
    "url": "https://github.com/OpenZeppelin/openzeppelin-contracts.git",
    "revision": "v5.0.0",
    "includes_submodules": true
  },
  "version_name": "v5.0.0",
  "project_root": ".",
  "src_path": "contracts",
  "contents": ["solidity"]
}
```

| Initial source | Arguments |
| --- | --- |
| Git repository | Pass `input_info` with `input_type: "git"` and `url`. Optional `revision` selects a branch, tag, or commit. `includes_submodules` defaults to `false`. |
| ZIP URL | Pass `"input_info": {"input_type": "archive", "url": "https://example.com/contracts.zip"}`. |
| ZIP on the MCP server | Pass `"archive": "/absolute/path/contracts.zip"`. |
| ZIP on a remote MCP client | Pass `archive` as an object with `content_base64` containing the ZIP bytes encoded as base64. The optional `filename` defaults to `sources.zip`. |
| Already staged in the organization | Pass the string `temp_version_id` and the matching `input_info` from staging. For a staged ZIP upload the default archive source applies. |
| Empty project | Omit the source and initial version arguments. |

| Project and version settings | Accepted values |
| --- | --- |
| `project_root`, `src_path` | Relative paths for the project root and sources. Both default to `.`. |
| `include_path`, `specs_path`, `hints_path`, `deployment_script_path` | Optional relative paths for includes, specifications, hints, and the deployment script. |
| `contents` | List of languages from `circom`, `solidity`, `picus`, and `llzk`. |
| `build_system` | `hardhat`, `hardhat-ignition`, or `foundry`. |
| `env_vars` | List of objects with string `name` and `value` fields. |
| `dependencies` | Optional `foundry` boolean and `npm` object. The object takes `tool` (`npm`, `yarn`, or `pnpm`), a `lockfile` boolean, and optional `node_version`. |
| `version_name` | First version's name. AuditHub defaults to `initial`. |
| `commit_hash`, `is_deployed` | Metadata for a newly staged source. For Git, `revision` selects the code and AuditHub records the resolved commit. An existing staged version carries its own metadata. |

The result contains the new project ID in `id`. Add it to `allowed_project_ids` and
restart the server to access it through project-scoped tools. If staging succeeds
and project creation returns an error, the tool reports the temporary ID. Check
whether AuditHub created the project before retrying. If it has not, pass that ID
and the same source description to reuse the staged version.

#### Starting a Scout review

`run_scout_task(organization_id=1, project_id=10, version_id=42, budget="standard")`
submits a Scout (AuditHub Agent) source review and returns its `task_id`. Supply
a budget class available to the organization. Pass an optional `name` or use
`input_limit` to select source files by path relative to the version root.
Scout submits the review with proof-of-concept generation disabled. Use
`get_task_info` or `wait_for_task_completion` to follow the run.

### Draft issue creation

Enable `capabilities.draft_issue_creation: true`, `--enable-draft-issue-creation`,
or `AH_ENABLE_DRAFT_ISSUE_CREATION=1` to register `create_draft_issue`.
It is disabled by default and enforces both organization and project allowlists.

The tool accepts `organization_id`, `project_id`, and `issue_input` containing
title, description, raised_by, affected_files, likelihood, impact, and severity.
Classification values are AuditHub configuration IDs. Optional lists are type,
promoted_findings, candidate_for_tool, poc_author, and document_authors. The `type`
list accepts existing IDs, names, or a mixture, for example
`"type": [1, "Access Control", "Custom Category"]`. Names are matched exactly
(case-sensitive) against the organization's types after trimming surrounding
whitespace. Empty names are rejected. Missing names are created in the organization
before draft creation, and their returned IDs are attached to the issue. Repeated
names create at most one type per call. Numeric IDs retain their existing behavior.
The result contains the new issue ID and the API message.

The tool calls the issue creation endpoint and, when names are supplied, the
organization issue-type listing and creation endpoints. AuditHub creates issues with auditor-only
visibility; see [Audit Issue Management](https://docs.audithub.dev/saas/guide/pages/projects/project_viewer/audit_issue_management).
Status and visibility inputs are forbidden. No issue sharing, status update, or
GitHub export tool is exposed. Publishing requires a separate human workflow.
Creation is not idempotent: inspect project issues before retrying after an
ambiguous network failure. Newly created organization types remain if a later type
or draft creation request fails.
