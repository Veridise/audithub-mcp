# Vanguard Tools

This document describes the intended high-level flow and behavior of the DeFi
Vanguard-related MCP tools in `audithub-mcp`.

## Overview

The Vanguard tools consist of:

- `get_defi_vanguard_detectors` lists the detector catalog in a copy-pasteable format.
- `run_defi_vanguard_task` launches a DeFi Vanguard task against a specific project version.

## Resources

`audithub-mcp` also exposes a read-only resource for Vanguard custom-detector
documentation:

- `docs://vanguard/custom-detectors`

The resource returns a JSON object mapping document titles to the markdown text
of relevant documentation pages.

Behavior:

- The server downloads the markdown texts the first time the resource is read.
- The downloaded text is cached in memory for the lifetime of the process.
- If any of the fetches returns a non-OK HTTP response, the resource read fails.

## Catalog Flow

`get_defi_vanguard_detectors` follows this flow:

1. Fetch and cache the global AuditHub configuration on first use.
2. Fetch custom detectors live on every request.
3. Output one entry per detector, all in text format.

The catalog combines three sources:

- builtin detectors from the cached global configuration
- standard-library custom detectors from the cached global configuration
- organization-library custom detectors from the live organization API

Built-in detectors and custom detectors are emitted in a copy-pasteable format,
such that a clearly indicated `detector` field can be fed as input to
`run_defi_vanguard_task`.
Each block carries a machine-readable `detector` id and a human-readable `title`.
For standard-library custom detectors, the `description` is also included.

## Caching

To reduce latency, the Vanguard tools will automatically cache global
configuration such as the built-in detector list, supported solc versions, and
the custom detector standard library.
These will be fetched on-demand when the Vanguard tools are invoked.

## Task Flow

The `run_defi_vanguard_task` tool is used to launch a Vanguard task for a
specified organization, project, and version. It performs the following steps:

1. Enforce capability checks such as task-run opt-in, organization and project
   allowlists, etc.
2. Load the global Vanguard configuration and live detector catalogs.
3. Validate parameters:
   - the provided detector selections must be in the catalog
   - the requested compiler version must exist in the global configuration
4. Build the generated Vanguard input payload.
5. Submit the Vanguard task through the AuditHub SDK endpoint.

Notes:

- If no specific solc version is specified, it should be set to "latest"

## Intended Behavior

- Builtin detector data is cached in-process for one day.
- Custom detector data is never cached.
- The detector listing is meant to be human-friendly for review, but still
  machine-readable for direct reuse in the task tool.
