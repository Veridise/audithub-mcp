# OrCa Tools

This document describes the intended high-level flow and behavior of the OrCa
related MCP tools in `audithub-mcp`.

## Overview

The OrCa tools consist of:

- `run_orca_task` launches an OrCa task against a specific project version.

## Task Flow

The `run_orca_task` tool is used to launch an OrCa task for a specified
organization, project, and version. It performs the following steps:

1. Enforce capability checks such as task-run opt-in, organization and project
   allowlists, etc.
2. Validate the OrCa task input through the local Pydantic models.
3. Normalize on-chain settings:
   - `specs_override` must contain at least one spec reference
   - if `deployment_info_file` is provided, it must end in `.deployment.json`
   - if `deployment_info_file` is provided, `on_chain` is automatically set to
     `true`
   - if `on_chain=true`, `deployment_info_file` must be present
4. Convert the validated local task input into the generated AuditHub SDK input
   payload.
5. Submit the OrCa task through the AuditHub SDK endpoint.

## Input Model

`run_orca_task` accepts a structured `task_input` payload with the following
high-level fields:

- `specs_override`: required list of spec references
- `hints_override`: optional list of hint references
- `deployment_script_path_override`: optional source-based deployment script path
- `deployment_info_file`: optional on-chain deployment info file
- `auxiliary_deployment_script`: optional auxiliary deployment script path
- `name`: optional task display name
- `parameters`: optional OrCa runtime parameters

Spec and hint references support four source types:

- version files inside the uploaded project archive
- standard-library entries
- organization-library entries
- ad hoc inline contents

Runtime parameters support the current OrCa fuzzing and execution settings,
including:

- `disable_user_proxies`
- `fuzz_pure`
- `fuzz_targets`
- `fuzzing_blacklist`
- `language`
- `timeout`
- `fork_network`
- `fork_block_number`

## Intended Behavior

- OrCa task input is validated locally before the SDK call is made.
- On-chain OrCa runs are inferred from `deployment_info_file`, so callers do not
  need to separately set `on_chain` when that file is supplied.
- The tool does not currently expose a separate OrCa catalog or resource; users
  must provide explicit spec and hint references in the task input.
