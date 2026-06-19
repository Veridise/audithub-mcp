# Configuration

## How-to

`audithub-mcp` can be configured in three ways:

1. Environment variables only.
   - Set the required `AUDITHUB_*` credential environment variables and the
     `AH_ALLOWED_*` environment variables in the shell environment before
     starting the server.
2. Config file plus environment overrides.
   - Pass `--config <path>` to load settings from a JSON or YAML file first.
   - By default, environment variables still override values from the file.
3. Config file only.
   - Pass `--config <path> --no-env-config` to load settings from the file without applying
     environment overrides.

CLI flags can also override the allowlist and feature toggles after the base settings are loaded:

- `--allowed-org-ids`
- `--allowed-project-ids`
- `--enable-task-runs`
- `--enable-version-creation`

Use CLI overrides when you want a temporary change without editing the config file or exporting
new environment variables.

## Configuration Reference

The JSON and YAML config file uses the same keys listed below. Environment variables use the same
values when `--config` is not supplied, or when `--config` is supplied without `--no-env-config`.

Notes:
- boolean values such as `AH_ENABLE_*` accept `1/0`, `true/false`, `yes/no`, and `on/off`.

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
  - Non-empty list of project IDs the server may access.
  - Environment variable: `AH_ALLOWED_PROJECT_IDS`
    - Environment format: comma-separated positive integers, for example `10,20`.
  - Can also be overridden on the command-line using `--allowed-project-ids id1,id2,...`

### Optional

- `capabilities` (object)
  - Optional feature toggles for state-changing features.
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
