"""MCP server for AuditHub backed exclusively by ``audithub-sdk``.

Security model
--------------
This server is read-only by default. Read tools are named ``get_*`` and only
invoke generated SDK methods for HTTP GET endpoints. Mutation tools are
registered only when their narrow opt-in gates are explicitly enabled.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import inspect
import json
import sys
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated, Any, cast

import audithub_sdk
from audithub_sdk.api.configuration_api import ConfigurationApi
from audithub_sdk.api.custom_detectors_org_lib_api import CustomDetectorsOrgLibApi
from audithub_sdk.api.custom_detectors_std_lib_api import CustomDetectorsStdLibApi
from audithub_sdk.api.issues_api import IssuesApi
from audithub_sdk.api.projects_api import ProjectsApi
from audithub_sdk.api.tasks_api import TasksApi
from audithub_sdk.api.tools_api import ToolsApi
from audithub_sdk.api.users_api import UsersApi
from audithub_sdk.api.versions_api import VersionsApi
from audithub_sdk.models.custom_detector import CustomDetector
from audithub_sdk.models.fuzzing_blacklist_entry import FuzzingBlacklistEntry
from audithub_sdk.models.hint_ad_hoc import HintAdHoc
from audithub_sdk.models.hint_from_organization_library import HintFromOrganizationLibrary
from audithub_sdk.models.hint_from_standard_library import HintFromStandardLibrary
from audithub_sdk.models.hint_from_version import HintFromVersion
from audithub_sdk.models.or_ca_input import OrCaInput
from audithub_sdk.models.or_ca_parameters import OrCaParameters
from audithub_sdk.models.root_model_list_union_hint_from_version_hint_from_standard_library_hint_from_organization_library_hint_ad_hoc_inner import (  # noqa: E501
    RootModelListUnionHintFromVersionHintFromStandardLibraryHintFromOrganizationLibraryHintAdHocInner as SdkOrCaHintReference,  # noqa: E501
)
from audithub_sdk.models.root_model_list_union_v_spec_from_version_v_spec_from_standard_library_v_spec_from_organization_library_v_spec_ad_hoc_inner import (  # noqa: E501
    RootModelListUnionVSpecFromVersionVSpecFromStandardLibraryVSpecFromOrganizationLibraryVSpecAdHocInner as SdkOrCaSpecReference,  # noqa: E501
)
from audithub_sdk.models.v_spec_ad_hoc import VSpecAdHoc
from audithub_sdk.models.v_spec_from_organization_library import VSpecFromOrganizationLibrary
from audithub_sdk.models.v_spec_from_standard_library import VSpecFromStandardLibrary
from audithub_sdk.models.v_spec_from_version import VSpecFromVersion
from audithub_sdk_ext import AuthenticatedApiClient, OIDCClientCredentialsContext
from mcp import types as mcp_types
from mcp.server.fastmcp import Context, FastMCP
from mcp.shared.exceptions import McpError
from pydantic import Field, TypeAdapter, ValidationError

from audithub_mcp import config as server_config
from audithub_mcp import parse_fio_logs, vanguard
from audithub_mcp.audit import log_call_error, log_call_start, log_call_success
from audithub_mcp.models import (
    Comment,
    CustomDetectorUploadResult,
    DefiVanguardV2DetectorSelectionInput,
    DefiVanguardV2TaskInput,
    FindingsParseResult,
    FIOData,
    IssueDetails,
    IssueForList,
    MyOrganization,
    OrCaAdHocHintReference,
    OrCaAdHocSpecReference,
    OrCaHintReference,
    OrCaOrganizationLibraryHintReference,
    OrCaOrganizationLibrarySpecReference,
    OrCaParametersInput,
    OrCaSpecReference,
    OrCaStandardLibraryHintReference,
    OrCaStandardLibrarySpecReference,
    OrCaTaskInput,
    OrCaVersionHintReference,
    OrCaVersionSpecReference,
    OrganizationLookupItem,
    Project,
    ProjectLookupItem,
    Task,
    TaskArtifact,
    TaskArtifactContent,
    TaskCreation,
    TaskLogsWriteResult,
    Thread,
    Version,
    VersionCreation,
    VersionFromFileInput,
    VersionFromUrlInput,
    VersionLookupItem,
    WaitForTaskCompletionResult,
    _PositiveId,
)

_AhId = server_config._AhId
_ArtifactId = server_config._ArtifactId
_MaxBytes = server_config._MaxBytes
_DEFAULT_ARTIFACT_MAX_BYTES = server_config._DEFAULT_ARTIFACT_MAX_BYTES
AuditHubSdkContext = server_config.AuditHubSdkContext
AuditHubServerConfig = server_config.AuditHubServerConfig
load_config_from_env = server_config.load_config_from_env
validate_startup_config = server_config.validate_startup_config

__all__ = [
    "AuditHubServerConfig",
    "AuditHubSdkContext",
    "OIDCClientCredentialsContext",
    "audithub_sdk",
]

mcp = FastMCP("audithub_mcp")
mcp._mcp_server.experimental.enable_tasks()

_VANGUARD_CUSTOM_DETECTOR_DOCS_RESOURCE_URI = "docs://vanguard/custom-detectors"
_VANGUARD_CUSTOM_DETECTOR_DOCS = {
    "Custom Detector Definition": "https://docs.audithub.dev/vanguard/custom-detectors/",
    "PAQL Reference": "https://docs.audithub.dev/vanguard/custom-detectors/paql",
    "Solidity PAQL Dialect": "https://docs.audithub.dev/vanguard/custom-detectors/solidity-dialect",
}


_context: AuditHubSdkContext | None = None
_allowed_org_ids: frozenset[int] = frozenset()
_allowed_project_ids: frozenset[int] = frozenset()
_task_runs_enabled = False
_version_creation_enabled = False
_edit_custom_detectors_enabled = False

_org_ta = TypeAdapter(list[MyOrganization])
_comment_ta = TypeAdapter(list[Comment])
_fio_data_ta = TypeAdapter(list[FIOData])
_thread_ta = TypeAdapter(list[Thread])
_issue_list_ta = TypeAdapter(list[IssueForList])
_project_ta = TypeAdapter(list[Project])
_version_ta = TypeAdapter(list[Version])
_str_list_ta = TypeAdapter(list[str])
_orca_task_creation_ta = TypeAdapter(TaskCreation)
_version_creation_ta = TypeAdapter(VersionCreation)

_SdkOrCaSpecActual = (
    VSpecFromVersion | VSpecFromStandardLibrary | VSpecFromOrganizationLibrary | VSpecAdHoc
)
_SdkOrCaHintActual = (
    HintFromVersion | HintFromStandardLibrary | HintFromOrganizationLibrary | HintAdHoc
)

_WAIT_FOR_TASK_COMPLETION_TOOL_NAME = "wait_for_task_completion"
_TASK_COMPLETION_POLL_INTERVAL_SECONDS = 10.0
_PENDING_STEP_STATUSES = {"pending", "queued", "running", "started", "in_progress"}
_TERMINAL_TASK_STATUSES = {
    "finished",
    "failed",
    "succeeded",
    "success",
    "completed",
    "cancelled",
    "canceled",
    "skipped",
}


@dataclass(frozen=True)
class RegisteredTool:
    """Name and callable pair for opt-in MCP tools."""

    #: MCP tool name used for registration and deregistration.
    name: str
    #: Callable registered with FastMCP for this tool.
    fn: Callable[..., object]


def _is_tool_registered(tool_name: str) -> bool:
    """Return whether an MCP tool is currently registered."""
    return tool_name in mcp._tool_manager._tools


def _startup_config_env_var_name(field_name: str) -> str | None:
    """Map a startup config field name to its backing environment variable."""
    return {
        "audithub_base_url": "AUDITHUB_BASE_URL",
        "audithub_oidc_configuration_url": "AUDITHUB_OIDC_CONFIGURATION_URL",
        "audithub_oidc_client_id": "AUDITHUB_OIDC_CLIENT_ID",
        "audithub_oidc_client_secret": "AUDITHUB_OIDC_CLIENT_SECRET",
    }.get(field_name)


def _missing_required_env_vars(exc: ValidationError) -> list[str]:
    """Extract missing startup environment variables from a validation error."""
    missing_env_vars: list[str] = []
    for error in exc.errors():
        error_input = error.get("input")
        if error_input != "" and not (
            hasattr(error_input, "get_secret_value") and error_input.get_secret_value() == ""
        ):
            continue
        loc = error.get("loc")
        if not loc:
            continue
        env_var_name = _startup_config_env_var_name(str(loc[0]))
        if env_var_name is not None:
            missing_env_vars.append(env_var_name)
    return sorted(set(missing_env_vars))


def _set_registered_tools_enabled(tools: Sequence[RegisteredTool], enabled: bool) -> None:
    """Register or unregister a group of MCP tools."""
    if enabled:
        for tool in tools:
            if _is_tool_registered(tool.name):
                continue
            mcp.add_tool(tool.fn)
        return
    for tool in tools:
        if _is_tool_registered(tool.name):
            mcp.remove_tool(tool.name)


def _set_task_runs_enabled(enabled: bool) -> None:
    """Enable or disable opt-in task-run MCP tools."""
    global _task_runs_enabled
    _task_runs_enabled = enabled
    _set_registered_tools_enabled(_TASK_RUN_TOOLS, enabled)


def _set_version_creation_enabled(enabled: bool) -> None:
    """Enable or disable opt-in version-creation MCP tools."""
    global _version_creation_enabled
    _version_creation_enabled = enabled
    _set_registered_tools_enabled(_VERSION_CREATION_TOOLS, enabled)


def _set_edit_custom_detectors_enabled(enabled: bool) -> None:
    """Enable or disable opt-in custom-detector upload MCP tools."""
    global _edit_custom_detectors_enabled
    _edit_custom_detectors_enabled = enabled
    _set_registered_tools_enabled(_CUSTOM_DETECTOR_UPLOAD_TOOLS, enabled)


def _assert_task_runs_enabled() -> None:
    """Raise unless mutating AuditHub task runs are enabled."""
    if not _task_runs_enabled:
        raise RuntimeError(
            "AuditHub task runs are disabled. Restart the server with "
            "--enable-task-runs or AH_ENABLE_TASK_RUNS=1 to enable task runs."
        )


def _assert_version_creation_enabled() -> None:
    """Raise unless mutating AuditHub version creation is enabled."""
    if not _version_creation_enabled:
        raise RuntimeError(
            "AuditHub version creation is disabled. Restart the server with "
            "--enable-version-creation or AH_ENABLE_VERSION_CREATION=1 to enable "
            "create_version_from_file and create_version_from_url."
        )


def _assert_edit_custom_detectors_enabled() -> None:
    """Raise unless custom detector uploads are enabled."""
    if not _edit_custom_detectors_enabled:
        raise RuntimeError(
            "AuditHub custom detector uploads are disabled. Restart the server with "
            "capabilities.edit_custom_detectors: true in the config file to enable "
            "upload_custom_detector."
        )


def _load_startup_config() -> AuditHubServerConfig:
    """Load startup config and translate validation errors into a user-friendly message."""
    try:
        return load_config_from_env()
    except ValidationError as exc:
        missing_env_vars = _missing_required_env_vars(exc)
        if missing_env_vars:
            raise RuntimeError(
                "Missing required configuration values; please set the following "
                "environment variables: " + ", ".join(missing_env_vars)
            ) from None
        raise RuntimeError("AuditHub startup configuration is invalid.") from None


def _build_context() -> AuditHubSdkContext:
    """Build SDK context from environment-backed config input."""
    return _load_startup_config().context


def _load_settings_from_cli_args(args: argparse.Namespace) -> AuditHubServerConfig:
    """Load settings from CLI-selected sources and translate startup failures."""
    try:
        if args.config is None:
            return _load_startup_config()
        return server_config.load_config_from_path(
            Path(args.config), override_from_env_vars=not args.no_env_config
        )
    except server_config.StartupConfigError as exc:
        raise RuntimeError(str(exc)) from None


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI parser for the AuditHub MCP server."""
    parser = argparse.ArgumentParser(
        description="AuditHub MCP server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Load settings from the specified JSON or YAML file",
    )
    parser.add_argument(
        "--allowed-org-ids",
        metavar="IDS",
        help=(
            "Comma-separated organization IDs the server may access (overrides AH_ALLOWED_ORG_IDS)."
        ),
    )
    parser.add_argument(
        "--allowed-project-ids",
        metavar="IDS",
        help=(
            "Comma-separated project IDs the server may access (overrides AH_ALLOWED_PROJECT_IDS)."
        ),
    )
    parser.add_argument(
        "--no-env-config",
        action="store_true",
        help="Do not allow environment variables to override config file settings",
    )
    parser.add_argument(
        "--enable-task-runs",
        action="store_true",
        help="Register opt-in mutation tools that can start AuditHub tasks.",
    )
    parser.add_argument(
        "--enable-version-creation",
        action="store_true",
        help="Register opt-in mutation tools that can create AuditHub project versions.",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List all registered MCP tools and their schemas, then exit.",
    )
    return parser


def _apply_cli_args_to_config(
    config: AuditHubServerConfig, args: argparse.Namespace
) -> AuditHubServerConfig:
    """Overlay parsed CLI arguments onto environment-backed server config."""
    allowed_org_ids = (
        config.allowed_org_ids
        if args.allowed_org_ids is None
        else server_config._parse_id_list(
            args.allowed_org_ids, "--allowed-org-ids / AH_ALLOWED_ORG_IDS"
        )
    )
    allowed_project_ids = (
        config.allowed_project_ids
        if args.allowed_project_ids is None
        else server_config._parse_id_list(
            args.allowed_project_ids, "--allowed-project-ids / AH_ALLOWED_PROJECT_IDS"
        )
    )
    return AuditHubServerConfig(
        context=config.context,
        allowed_org_ids=allowed_org_ids,
        allowed_project_ids=allowed_project_ids,
        task_runs_enabled=config.task_runs_enabled or args.enable_task_runs,
        version_creation_enabled=config.version_creation_enabled or args.enable_version_creation,
        edit_custom_detectors_enabled=config.edit_custom_detectors_enabled,
    )


async def _list_tools() -> None:
    """Print the registered MCP tools and their schemas, then exit."""
    tools = await mcp.list_tools()
    print(json.dumps([tool.model_dump(mode="json") for tool in tools], indent=2, sort_keys=True))


@mcp.resource(
    _VANGUARD_CUSTOM_DETECTOR_DOCS_RESOURCE_URI,
    name="vanguard_custom_detector_docs",
    title="Vanguard custom detector docs",
    description="Links to AuditHub's PAQL and Solidity PAQL documentation.",
    mime_type="application/json",
)
def get_vanguard_custom_detector_docs() -> dict[str, str]:
    """Return links to the AuditHub custom-detector documentation."""
    return _VANGUARD_CUSTOM_DETECTOR_DOCS


def _ctx() -> AuditHubSdkContext:
    """Return the cached SDK context."""
    if _context is None:
        raise RuntimeError(
            "AuditHub context is not initialised. "
            "Ensure startup configuration has been loaded before starting the server."
        )
    return _context


def _assert_org_allowed(organization_id: int) -> None:
    """Raise if *organization_id* is not allowlisted."""
    if organization_id not in _allowed_org_ids:
        raise RuntimeError(
            f"Organization ID {organization_id} is not in the configured allowlist. "
            "Call get_organizations to find the IDs you have access to."
        )


def _assert_project_allowed(project_id: int) -> None:
    """Raise if *project_id* is not allowlisted."""
    if project_id not in _allowed_project_ids:
        raise RuntimeError(
            f"Project ID {project_id} is not in the configured allowlist. "
            "Use get_projects after finding a valid organization ID."
        )


def _build_pagination_params(limit: int | None, offset: int | None) -> dict[str, int] | None:
    """Build a query-params dict from optional limit/offset values."""
    if limit is not None and limit < 0:
        raise ValueError(f"limit must be >= 0, got {limit!r}")
    if offset is not None and offset < 0:
        raise ValueError(f"offset must be >= 0, got {offset!r}")
    params: dict[str, int] = {}
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    return params or None


def _slice_paginated[T](items: Sequence[T], limit: int | None, offset: int | None) -> list[T]:
    """Apply client-side limit/offset slicing."""
    _build_pagination_params(limit, offset)
    start = 0 if offset is None else offset
    end = None if limit is None else start + limit
    return list(items[start:end])


def _normalize_sort_key(name: str) -> str:
    """Normalize a user-visible name into a deterministic case-insensitive sort key."""
    return name.strip().casefold()


def _sanitize_task(task: Task) -> Task:
    """Remove credential-like fields from SDK task objects before returning them."""
    if task.artifacts is not None:
        for artifact in task.artifacts:
            artifact.presigned_url = None
    return task


def _task_artifacts(task: Task) -> list[TaskArtifact]:
    """Return sanitized task artifact metadata."""
    if task.artifacts is None:
        return []
    return [
        TaskArtifact.model_validate(artifact, from_attributes=True) for artifact in task.artifacts
    ]


def _task_has_pending_steps(task: Task) -> bool:
    """Return whether *task* still has at least one pending step."""
    if task.steps is None:
        return task.status.casefold() not in _TERMINAL_TASK_STATUSES
    return any(step.status.casefold() in _PENDING_STEP_STATUSES for step in task.steps)


def _response_header(headers: Mapping[str, str] | None, name: str) -> str | None:
    """Read a response header without depending on a concrete header mapping type."""
    if headers is None:
        return None
    folded_name = name.casefold()
    for key, value in headers.items():
        if key.casefold() == folded_name:
            return value
    return None


def _write_output_file(output_file_path: str, contents: str) -> None:
    """Write text content to a local file with a sanitized error message."""
    output_path = Path(output_file_path)
    try:
        output_path.write_text(contents, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Failed to write output file {output_path!s}: {exc}") from None


async def _with_api_client[T](fn: Callable[[AuthenticatedApiClient], Awaitable[T]]) -> T:
    """Create an authenticated SDK client for a single tool invocation."""
    ctx = _ctx()
    async with AuthenticatedApiClient(ctx.configuration, auth_context=ctx.auth_context) as client:
        return await fn(client)


def _safe_exception_message(exc: Exception) -> str:
    """Return a sanitized message safe to propagate to MCP callers."""
    status = getattr(exc, "status", None)
    if isinstance(status, int):
        return f"AuditHub API request failed with status {status}."
    return "An internal error occurred."


async def _run_tool[T](
    fn: Callable[[], T | Awaitable[T]],
    *,
    tool_name: str = "",
    safe_args: dict[str, int | float | None] | None = None,
) -> T:
    """Execute a tool function, sanitizing exceptions to prevent secret leakage."""
    if tool_name:
        log_call_start(tool_name, safe_args or {})
    start = time.monotonic()
    sanitized: RuntimeError | None = None
    try:
        result = fn()
        if inspect.isawaitable(result):
            result = await result
        if tool_name:
            log_call_success(tool_name, (time.monotonic() - start) * 1000)
        return result
    except RuntimeError as exc:
        if tool_name:
            log_call_error(tool_name, str(exc), (time.monotonic() - start) * 1000)
        exc.__context__ = None
        exc.__cause__ = None
        raise
    except McpError as exc:
        if tool_name:
            log_call_error(tool_name, str(exc), (time.monotonic() - start) * 1000)
        raise
    except Exception as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        safe_message = (
            _safe_exception_message(exc)
            if isinstance(getattr(exc, "status", None), int)
            else "An internal error occurred."
        )
        if tool_name:
            log_call_error(tool_name, safe_message, elapsed_ms)
            sanitized = RuntimeError(
                "An internal error occurred. Details have been logged."
                if not isinstance(getattr(exc, "status", None), int)
                else safe_message
            )
        else:
            sanitized = RuntimeError(safe_message)
    raise sanitized


@mcp.tool()
async def get_organizations(
    filter_id: Annotated[
        _AhId | None,
        Field(description="Filter to only the given organization ID."),
    ] = None,
    details: Annotated[
        bool,
        Field(description="Return full organization information in a details field"),
    ] = False,
) -> list[OrganizationLookupItem]:
    """List allowlisted AuditHub organizations."""

    async def _run() -> list[OrganizationLookupItem]:
        if filter_id is not None:
            _assert_org_allowed(filter_id)

        organizations = await _with_api_client(
            lambda client: UsersApi(client).get_organizations_users_myorganizations_get()
        )
        orgs = _org_ta.validate_python(organizations)
        if filter_id is not None:
            orgs = [org for org in orgs if org.id == filter_id]
        orgs = [org for org in orgs if org.id in _allowed_org_ids]
        orgs = sorted(orgs, key=lambda org: (_normalize_sort_key(org.name), org.id))
        return [
            OrganizationLookupItem.model_construct(
                id=org.id,
                name=org.name,
                sort_key=_normalize_sort_key(org.name),
                details=org if details else None,
            )
            for org in orgs
        ]

    return await _run_tool(
        _run,
        tool_name="get_organizations",
        safe_args={"filter_id": filter_id},
    )


@mcp.tool()
async def get_defi_vanguard_detectors(organization_id: _AhId) -> list[str]:
    """List all DeFi Vanguard v2 detectors available to an organization."""

    async def _run() -> list[str]:
        _assert_org_allowed(organization_id)
        builtin_entries, custom_entries = await vanguard.load_vanguard_detector_catalog(
            organization_id,
            fetch_configuration=lambda: _with_api_client(
                lambda client: ConfigurationApi(client).get_configuration_configuration_get()
            ),
            fetch_custom_detectors=lambda org_id: _with_api_client(
                lambda client: CustomDetectorsOrgLibApi(
                    client
                ).get_custom_detectors_organizations_organization_id_custom_detectors_get(  # noqa: E501
                    organization_id=org_id
                )
            ),
            fetch_custom_detectors_library=lambda: _with_api_client(
                lambda client: CustomDetectorsStdLibApi(
                    client
                ).get_custom_detectors_library_custom_detectors_library_get()
            ),
        )
        entries = sorted(
            [*builtin_entries, *custom_entries],
            key=lambda entry: (_normalize_sort_key(entry.display_name), entry.description),
        )
        return [vanguard.format_vanguard_detector_listing_entry(entry) for entry in entries]

    return await _run_tool(
        _run,
        tool_name="get_defi_vanguard_detectors",
        safe_args={"organization_id": organization_id},
    )


@mcp.tool()
async def get_projects(
    organization_id: _AhId,
    filter_id: Annotated[
        _AhId | None,
        Field(description="Filter to only the given project ID"),
    ] = None,
    details: Annotated[
        bool,
        Field(description="Return full project information in a details field"),
    ] = False,
) -> list[ProjectLookupItem]:
    """List allowlisted AuditHub projects for an organization."""

    async def _run() -> list[ProjectLookupItem]:
        _assert_org_allowed(organization_id)
        if filter_id is not None:
            _assert_project_allowed(filter_id)

        projects = await _with_api_client(
            lambda client: ProjectsApi(
                client
            ).get_projects_organizations_organization_id_projects_get(
                organization_id=organization_id,
            )
        )
        project_list = _project_ta.validate_python(projects)
        if filter_id is not None:
            project_list = [project for project in project_list if project.id == filter_id]
        project_list = [project for project in project_list if project.id in _allowed_project_ids]
        project_list = sorted(
            project_list, key=lambda project: (_normalize_sort_key(project.name), project.id)
        )
        return [
            ProjectLookupItem.model_construct(
                id=project.id,
                name=project.name,
                sort_key=_normalize_sort_key(project.name),
                details=project if details else None,
            )
            for project in project_list
        ]

    return await _run_tool(
        _run,
        tool_name="get_projects",
        safe_args={"organization_id": organization_id, "filter_id": filter_id},
    )


@mcp.tool()
async def get_versions(
    organization_id: _AhId,
    project_id: _AhId,
    filter_id: Annotated[
        _AhId | None,
        Field(description="Filter to only the given version ID"),
    ] = None,
    details: Annotated[
        bool,
        Field(description="Return full organization information in a details field"),
    ] = False,
    latest_only: Annotated[
        bool,
        Field(description="Filter to the latest version of the project"),
    ] = False,
) -> list[VersionLookupItem]:
    """List AuditHub versions for a project."""

    async def _run() -> list[VersionLookupItem]:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)

        latest_version = await _with_api_client(
            lambda client: VersionsApi(
                client
            ).get_latest_version_organizations_organization_id_projects_project_id_versions_latest_get(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
            )
        )
        latest_version_model = Version.model_validate(latest_version)
        latest_version_id = latest_version_model.id
        if latest_only:
            if filter_id is not None and filter_id != latest_version_id:
                return []
            return [
                VersionLookupItem.model_construct(
                    id=latest_version_model.id,
                    name=latest_version_model.name,
                    sort_key=_normalize_sort_key(latest_version_model.name),
                    latest=True,
                    details=latest_version_model if details else None,
                )
            ]

        versions = await _with_api_client(
            lambda client: VersionsApi(
                client
            ).get_versions_organizations_organization_id_projects_project_id_versions_get(
                organization_id=organization_id,
                project_id=project_id,
            )
        )
        version_list = _version_ta.validate_python(versions)
        if filter_id is not None:
            version_list = [version for version in version_list if version.id == filter_id]
        version_list = sorted(
            version_list, key=lambda version: (_normalize_sort_key(version.name), version.id)
        )
        latest_version_id_set = latest_version_id
        return [
            VersionLookupItem.model_construct(
                id=version.id,
                name=version.name,
                sort_key=_normalize_sort_key(version.name),
                latest=version.id == latest_version_id_set,
                details=version if details else None,
            )
            for version in version_list
        ]

    return await _run_tool(
        _run,
        tool_name="get_versions",
        safe_args={
            "organization_id": organization_id,
            "project_id": project_id,
            "filter_id": filter_id,
            "latest_only": latest_only,
        },
    )


@mcp.tool()
async def get_task_info(organization_id: _AhId, task_id: _AhId) -> Task:
    """Get status and details for an AuditHub task."""

    async def _run() -> Task:
        _assert_org_allowed(organization_id)
        task = await _with_api_client(
            lambda client: TasksApi(
                client
            ).get_info_organizations_organization_id_tasks_task_id_get(  # noqa: E501
                organization_id=organization_id,
                task_id=task_id,
            )
        )
        return _sanitize_task(Task.model_validate(task))

    return await _run_tool(
        _run,
        tool_name="get_task_info",
        safe_args={"organization_id": organization_id, "task_id": task_id},
    )


@mcp.tool()
async def wait_for_task_completion(
    organization_id: _AhId,
    task_id: _AhId,
    timeout: Annotated[
        float | None,
        Field(
            gt=0,
            description=(
                "Maximum number of seconds to wait before stopping polling. "
                "For an agent with no MCP task protocol support, this should be set to a value "
                "slightly below the tool call timeout."
            ),
        ),
    ] = None,
    context: Context[Any, Any, Any] | None = None,
) -> WaitForTaskCompletionResult | mcp_types.CreateTaskResult:
    """Poll an AuditHub task until it has no pending steps left or a timeout is reached, then
    return its current task info.

    This tool can be called repeatedly until the task is complete."""

    async def _wait_for_audithub_task_completion() -> WaitForTaskCompletionResult:
        _assert_org_allowed(organization_id)
        deadline = None if timeout is None else time.monotonic() + timeout
        latest_task: Task | None = None
        while True:
            # Stop immediately once the deadline has passed and return the latest snapshot.
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                if latest_task is None:
                    task = await _with_api_client(
                        lambda client: TasksApi(
                            client
                        ).get_info_organizations_organization_id_tasks_task_id_get(  # noqa: E501
                            organization_id=organization_id,
                            task_id=task_id,
                        )
                    )
                    latest_task = _sanitize_task(Task.model_validate(task))
                return WaitForTaskCompletionResult(task=latest_task, is_completed=False)

            # Fetch the current task state before deciding whether to keep polling.
            task = await _with_api_client(
                lambda client: TasksApi(
                    client
                ).get_info_organizations_organization_id_tasks_task_id_get(  # noqa: E501
                    organization_id=organization_id,
                    task_id=task_id,
                )
            )
            now = time.monotonic()
            validated_task = _sanitize_task(Task.model_validate(task))
            latest_task = validated_task

            # The task is finished, so return the final snapshot immediately.
            if not _task_has_pending_steps(validated_task):
                return WaitForTaskCompletionResult(task=validated_task, is_completed=True)

            # No timeout means a plain polling loop with the configured interval.
            if deadline is None:
                await asyncio.sleep(_TASK_COMPLETION_POLL_INTERVAL_SECONDS)
                continue

            # Sleep only for the remaining time so short timeouts stay precise.
            remaining = deadline - now
            if remaining <= 0:
                return WaitForTaskCompletionResult(task=validated_task, is_completed=False)
            await asyncio.sleep(min(_TASK_COMPLETION_POLL_INTERVAL_SECONDS, remaining))

    if context is not None and context.request_context.experimental.is_task and timeout is None:
        # Task-capable clients can run the indefinite wait as a background task.
        async def _run_as_task() -> mcp_types.CreateTaskResult:
            async def _work(task: object) -> mcp_types.CallToolResult:
                result = await _wait_for_audithub_task_completion()
                return mcp_types.CallToolResult(content=[], structuredContent=result.model_dump())

            # `experimental.run_task` is typed as `Any` by the MCP library, so cast the
            # awaited value back to the concrete result type this branch returns.
            return cast(
                mcp_types.CreateTaskResult,
                await context.request_context.experimental.run_task(_work),
            )

        # Non-task clients fall through to the normal tool return path.
        return await _run_tool(
            _run_as_task,
            tool_name=_WAIT_FOR_TASK_COMPLETION_TOOL_NAME,
            safe_args={"organization_id": organization_id, "task_id": task_id, "timeout": timeout},
        )

    return await _run_tool(
        _wait_for_audithub_task_completion,
        tool_name=_WAIT_FOR_TASK_COMPLETION_TOOL_NAME,
        safe_args={"organization_id": organization_id, "task_id": task_id, "timeout": timeout},
    )


@mcp.tool()
async def get_task_artifacts(organization_id: _AhId, task_id: _AhId) -> list[TaskArtifact]:
    """List metadata of all artifacts produced by an AuditHub task."""

    async def _run() -> list[TaskArtifact]:
        _assert_org_allowed(organization_id)
        task = await _with_api_client(
            lambda client: TasksApi(
                client
            ).get_info_organizations_organization_id_tasks_task_id_get(  # noqa: E501
                organization_id=organization_id,
                task_id=task_id,
            )
        )
        return _task_artifacts(Task.model_validate(task))

    return await _run_tool(
        _run,
        tool_name="get_task_artifacts",
        safe_args={"organization_id": organization_id, "task_id": task_id},
    )


@mcp.tool()
async def get_task_artifact(
    organization_id: _AhId,
    task_id: _AhId,
    artifact_id: _ArtifactId,
    max_bytes: _MaxBytes | None = _DEFAULT_ARTIFACT_MAX_BYTES,
) -> TaskArtifactContent:
    """Download the artifact blob of an AuditHub task as base64-encoded content."""

    async def _run() -> TaskArtifactContent:
        _assert_org_allowed(organization_id)
        response = await _with_api_client(
            lambda client: TasksApi(
                client
            ).get_artifact_organizations_organization_id_tasks_task_id_artifacts_artifact_id_get_with_http_info(  # noqa: E501
                organization_id=organization_id,
                task_id=task_id,
                artifact_id=artifact_id,
            )
        )
        raw_data = response.raw_data
        if max_bytes is not None and len(raw_data) > max_bytes:
            raise RuntimeError(
                f"Artifact content is {len(raw_data)} bytes, exceeding max_bytes={max_bytes}."
            )
        return TaskArtifactContent(
            artifact_id=artifact_id,
            content_length=len(raw_data),
            content_base64=base64.b64encode(raw_data).decode("ascii"),
            content_type=_response_header(response.headers, "content-type"),
        )

    return await _run_tool(
        _run,
        tool_name="get_task_artifact",
        safe_args={
            "organization_id": organization_id,
            "task_id": task_id,
            "max_bytes": max_bytes,
        },
    )


@mcp.tool()
async def get_task_logs(
    organization_id: _AhId,
    task_id: _AhId,
    step_codes: Annotated[
        list[str],
        Field(
            min_length=1,
            description=(
                "List of task step codes to fetch logs for. Each step code is paired "
                "with the output path at the same index."
            ),
        ),
    ],
    output_paths: Annotated[
        list[str],
        Field(
            min_length=1,
            description=(
                "List of local absolute output file paths to write the logs to. The number of "
                "output paths must match the number of step codes so each log is "
                "written to a separate file."
            ),
        ),
    ],
) -> TaskLogsWriteResult:
    """Get logs for one or more AuditHub task steps and write each to a file.

    Findings can be parsed from the logs with the parse_findings_from_task_log tool.
    """

    async def _run() -> TaskLogsWriteResult:
        _assert_org_allowed(organization_id)
        if len(step_codes) != len(output_paths):
            raise ValueError("step_codes and output_paths must have the same length.")

        total_logs = 0
        for step_code, output_file_path in zip(step_codes, output_paths, strict=True):

            async def _fetch_logs(client: object, step_code: str = step_code) -> object:
                return await TasksApi(
                    client
                ).get_output_organizations_organization_id_tasks_task_id_step_code_output_get(  # noqa: E501
                    organization_id=organization_id,
                    task_id=task_id,
                    step_code=step_code,
                )

            logs = await _with_api_client(_fetch_logs)
            validated_logs = _str_list_ta.validate_python(logs)
            _write_output_file(
                output_file_path,
                "\n".join(validated_logs) + ("\n" if validated_logs else ""),
            )
            total_logs += len(validated_logs)

        return TaskLogsWriteResult(num_logs=total_logs)

    return await _run_tool(
        _run,
        tool_name="get_task_logs",
        safe_args={"organization_id": organization_id, "task_id": task_id},
    )


@mcp.tool()
async def parse_findings_from_task_log(
    log_file_paths: Annotated[
        list[str],
        Field(
            min_length=1,
            description="Absolute paths to one or more task log files to parse.",
        ),
    ],
    output_file_path: Annotated[
        str,
        Field(min_length=1, description="Absolute path to write the JSON summary to."),
    ],
) -> FindingsParseResult:
    """Parse findings from one or more task log files (as retrieved with get_task_logs)
    and write a JSON summary.
    """

    async def _run() -> FindingsParseResult:
        log_entries: list[tuple[str, str]] = []
        for log_file_path in log_file_paths:
            log_path = Path(log_file_path)
            try:
                log_contents = log_path.read_text(encoding="utf-8")
            except OSError as exc:
                raise RuntimeError(f"Failed to read log file {log_path!s}: {exc}") from None
            log_entries.append((log_file_path, log_contents))

        parsed = parse_fio_logs.parse_logs(log_entries)
        payload = asdict(parsed)
        _write_output_file(
            output_file_path,
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
        )
        return FindingsParseResult(
            num_findings=parsed.num_findings,
            num_findings_by_log_file_path=parsed.num_findings_by_log_file_path,
        )

    return await _run_tool(_run, tool_name="parse_findings_from_task_log")


@mcp.tool()
async def get_task_findings(
    organization_id: _AhId,
    task_id: _AhId,
    output_file_path: Annotated[str, Field(min_length=1)],
) -> FindingsParseResult:
    """Get raw findings data produced by an AuditHub task execution.

    This data is large and should not be read directly."""

    async def _run() -> FindingsParseResult:
        _assert_org_allowed(organization_id)
        findings = await _with_api_client(
            lambda client: TasksApi(
                client
            ).get_task_findings_organizations_organization_id_tasks_task_id_findings_get(  # noqa: E501
                organization_id=organization_id,
                task_id=task_id,
            )
        )
        validated_findings = _fio_data_ta.validate_python(findings)
        _write_output_file(
            output_file_path,
            json.dumps(
                {"findings": [finding.model_dump(mode="json") for finding in validated_findings]},
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
        return FindingsParseResult(
            num_findings=len(validated_findings),
            num_findings_by_log_file_path={},
        )

    return await _run_tool(
        _run,
        tool_name="get_task_findings",
        safe_args={"organization_id": organization_id, "task_id": task_id},
    )


@mcp.tool()
async def get_version_comments(
    organization_id: _AhId,
    project_id: _AhId,
    version_id: _AhId,
    limit: Annotated[int, Field(ge=0)] | None = 200,
    offset: Annotated[int, Field(ge=0)] | None = 0,
) -> list[Comment]:
    """Get comments for a specific project version. Use this only to aggregate comments
    at the version level, if you are looking for a specific thread id use
    get_thread_comments instead.

    This can return large objects, prefer pagination to avoid truncation by MCP."""

    async def _run() -> list[Comment]:
        _build_pagination_params(limit, offset)
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        comments = await _with_api_client(
            lambda client: VersionsApi(
                client
            ).get_version_comments_organizations_organization_id_projects_project_id_versions_version_id_comments_get(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
                version_id=version_id,
                limit=limit,
                offset=offset,
            )
        )
        return _comment_ta.validate_python(comments)

    return await _run_tool(
        _run,
        tool_name="get_version_comments",
        safe_args={
            "organization_id": organization_id,
            "project_id": project_id,
            "version_id": version_id,
            "limit": limit,
            "offset": offset,
        },
    )


@mcp.tool()
async def get_version_comment_threads(
    organization_id: _AhId,
    project_id: _AhId,
    version_id: _AhId,
    limit: Annotated[int, Field(ge=0)] | None = 200,
    offset: Annotated[int, Field(ge=0)] | None = 0,
) -> list[Thread]:
    """Get comment threads for a specific project version."""

    async def _run() -> list[Thread]:
        _build_pagination_params(limit, offset)
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        threads = await _with_api_client(
            lambda client: VersionsApi(
                client
            ).get_version_comment_threads_organizations_organization_id_projects_project_id_versions_version_id_comment_threads_get(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
                version_id=version_id,
            )
        )
        return _slice_paginated(_thread_ta.validate_python(threads), limit, offset)

    return await _run_tool(
        _run,
        tool_name="get_version_comment_threads",
        safe_args={
            "organization_id": organization_id,
            "project_id": project_id,
            "version_id": version_id,
            "limit": limit,
            "offset": offset,
        },
    )


@mcp.tool()
async def get_thread_comments(
    organization_id: _AhId,
    project_id: _AhId,
    version_id: _AhId,
    thread_id: _AhId,
    limit: Annotated[int, Field(ge=0)] | None = 200,
    offset: Annotated[int, Field(ge=0)] | None = 0,
) -> list[Comment]:
    """Get comments for a specific thread within a project version.
    This can return large objects, prefer pagination to avoid truncation by MCP."""

    async def _run() -> list[Comment]:
        _build_pagination_params(limit, offset)
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        comments = await _with_api_client(
            lambda client: VersionsApi(
                client
            ).get_version_comments_organizations_organization_id_projects_project_id_versions_version_id_comments_get(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
                version_id=version_id,
                thread_id=thread_id,
                limit=limit,
                offset=offset,
            )
        )
        return _comment_ta.validate_python(comments)

    return await _run_tool(
        _run,
        tool_name="get_thread_comments",
        safe_args={
            "organization_id": organization_id,
            "project_id": project_id,
            "version_id": version_id,
            "thread_id": thread_id,
            "limit": limit,
            "offset": offset,
        },
    )


@mcp.tool()
async def get_project_issues(
    organization_id: _AhId,
    project_id: _AhId,
    limit: Annotated[int, Field(ge=0)] | None = 200,
    offset: Annotated[int, Field(ge=0)] | None = 0,
) -> list[IssueForList]:
    """Get all issues for an AuditHub project."""

    async def _run() -> list[IssueForList]:
        _build_pagination_params(limit, offset)
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        issues = await _with_api_client(
            lambda client: IssuesApi(
                client
            ).get_issues_organizations_organization_id_projects_project_id_issues_get(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
            )
        )
        return _slice_paginated(_issue_list_ta.validate_python(issues), limit, offset)

    return await _run_tool(
        _run,
        tool_name="get_project_issues",
        safe_args={
            "organization_id": organization_id,
            "project_id": project_id,
            "limit": limit,
            "offset": offset,
        },
    )


@mcp.tool()
async def get_project_issue(
    organization_id: _AhId, project_id: _AhId, issue_id: _AhId
) -> IssueDetails:
    """Get a specific issue from an AuditHub project."""

    async def _run() -> IssueDetails:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        issue = await _with_api_client(
            lambda client: IssuesApi(
                client
            ).get_issue_organizations_organization_id_projects_project_id_issues_issue_id_get(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
                issue_id=issue_id,
            )
        )
        return IssueDetails.model_validate(issue)

    return await _run_tool(
        _run,
        tool_name="get_project_issue",
        safe_args={
            "organization_id": organization_id,
            "project_id": project_id,
            "issue_id": issue_id,
        },
    )


@mcp.tool()
async def get_project_comments(
    organization_id: _AhId,
    project_id: _AhId,
    limit: Annotated[int, Field(ge=0)] | None = 200,
    offset: Annotated[int, Field(ge=0)] | None = 0,
) -> list[Comment]:
    """Get all comments for an AuditHub project across all versions. Use this only to
    aggregate comments at the project level, if you are looking for a specific thread
    id use get_thread_comments instead.

    This can return large objects, prefer pagination to avoid truncation by MCP."""

    async def _run() -> list[Comment]:
        _build_pagination_params(limit, offset)
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        comments = await _with_api_client(
            lambda client: ProjectsApi(
                client
            ).get_project_comments_organizations_organization_id_projects_project_id_comments_get(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
                limit=200 if limit is None else limit,
                offset=0 if offset is None else offset,
            )
        )
        return _comment_ta.validate_python(comments)

    return await _run_tool(
        _run,
        tool_name="get_project_comments",
        safe_args={
            "organization_id": organization_id,
            "project_id": project_id,
            "limit": limit,
            "offset": offset,
        },
    )


def _build_sdk_orca_spec(reference: OrCaSpecReference) -> SdkOrCaSpecReference:
    """Convert a local OrCa spec reference to the generated SDK union wrapper."""
    sdk_reference: _SdkOrCaSpecActual
    if isinstance(reference, OrCaVersionSpecReference):
        sdk_reference = VSpecFromVersion(relative_path=reference.relative_path)
    elif isinstance(reference, OrCaStandardLibrarySpecReference):
        sdk_reference = VSpecFromStandardLibrary(
            category=reference.category,
            name=reference.name,
            library_version=reference.library_version,
        )
    elif isinstance(reference, OrCaOrganizationLibrarySpecReference):
        sdk_reference = VSpecFromOrganizationLibrary(id=reference.id)
    elif isinstance(reference, OrCaAdHocSpecReference):
        sdk_reference = VSpecAdHoc(
            filename=reference.filename,
            contents=reference.contents,
            encoding=reference.encoding,
        )
    else:
        raise TypeError("Unsupported OrCa spec reference type.")
    return SdkOrCaSpecReference(actual_instance=sdk_reference)


def _build_sdk_orca_hint(reference: OrCaHintReference) -> SdkOrCaHintReference:
    """Convert a local OrCa hint reference to the generated SDK union wrapper."""
    sdk_reference: _SdkOrCaHintActual
    if isinstance(reference, OrCaVersionHintReference):
        sdk_reference = HintFromVersion(relative_path=reference.relative_path)
    elif isinstance(reference, OrCaStandardLibraryHintReference):
        sdk_reference = HintFromStandardLibrary(
            category=reference.category,
            name=reference.name,
            library_version=reference.library_version,
        )
    elif isinstance(reference, OrCaOrganizationLibraryHintReference):
        sdk_reference = HintFromOrganizationLibrary(id=reference.id)
    elif isinstance(reference, OrCaAdHocHintReference):
        sdk_reference = HintAdHoc(
            filename=reference.filename,
            contents=reference.contents,
            encoding=reference.encoding,
        )
    else:
        raise TypeError("Unsupported OrCa hint reference type.")
    return SdkOrCaHintReference(actual_instance=sdk_reference)


def _build_sdk_orca_parameters(parameters: OrCaParametersInput) -> OrCaParameters:
    """Convert local OrCa parameters to generated SDK parameters."""
    fuzzing_blacklist = (
        None
        if parameters.fuzzing_blacklist is None
        else [
            FuzzingBlacklistEntry(contract=entry.contract, function=entry.function)
            for entry in parameters.fuzzing_blacklist
        ]
    )
    return OrCaParameters(
        disable_user_proxies=parameters.disable_user_proxies,
        fuzz_pure=parameters.fuzz_pure,
        fuzz_targets=parameters.fuzz_targets,
        fuzzing_blacklist=fuzzing_blacklist,
        language=parameters.language,
        timeout=parameters.timeout,
        fork_network=parameters.fork_network,
        fork_block_number=parameters.fork_block_number,
    )


def _build_sdk_orca_input(task_input: OrCaTaskInput) -> OrCaInput:
    """Convert local OrCa task input to the generated SDK input model."""
    hints_override = (
        None
        if task_input.hints_override is None
        else [_build_sdk_orca_hint(reference) for reference in task_input.hints_override]
    )
    return OrCaInput(
        specs_override=[_build_sdk_orca_spec(reference) for reference in task_input.specs_override],
        hints_override=hints_override,
        deployment_script_path_override=task_input.deployment_script_path_override,
        on_chain=task_input.on_chain,
        deployment_info_file=task_input.deployment_info_file,
        auxiliary_deployment_script=task_input.auxiliary_deployment_script,
        name=task_input.name,
        parameters=_build_sdk_orca_parameters(task_input.parameters),
    )


async def run_orca_task(
    organization_id: _AhId,
    project_id: _AhId,
    version_id: _AhId,
    task_input: OrCaTaskInput,
) -> TaskCreation:
    """Run an OrCa task for a specific AuditHub project version."""

    async def _run() -> TaskCreation:
        _assert_task_runs_enabled()
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        created_task = await _with_api_client(
            lambda client: ToolsApi(
                client
            ).post_tool_orca_organizations_organization_id_projects_project_id_versions_version_id_tools_orca_post(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
                version_id=version_id,
                or_ca_input=_build_sdk_orca_input(task_input),
            )
        )
        return _orca_task_creation_ta.validate_python(created_task)

    return await _run_tool(
        _run,
        tool_name=_RUN_ORCA_TASK_TOOL_NAME,
        safe_args={
            "organization_id": organization_id,
            "project_id": project_id,
            "version_id": version_id,
        },
    )


async def run_defi_vanguard_task(
    organization_id: _AhId,
    project_id: _AhId,
    version_id: _AhId,
    detectors: list[DefiVanguardV2DetectorSelectionInput],
    name: str | None = None,
    input_limit: list[str] | None = None,
    cross_version_triage: bool = False,
    solc: str | None = None,
    ignore_build_system: bool = False,
) -> TaskCreation:
    """Run a DeFi Vanguard task for a specific AuditHub project version."""

    async def _run() -> TaskCreation:
        _assert_task_runs_enabled()
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        task_input = DefiVanguardV2TaskInput(
            organization_id=organization_id,
            project_id=project_id,
            version_id=version_id,
            detectors=detectors,
            name=name,
            input_limit=input_limit,
            cross_version_triage=cross_version_triage,
            solc=solc,
            ignore_build_system=ignore_build_system,
        )
        sdk_input = await vanguard.build_vanguard_v2_input(
            organization_id,
            task_input,
            fetch_configuration=lambda: _with_api_client(
                lambda client: ConfigurationApi(client).get_configuration_configuration_get()
            ),
            fetch_custom_detectors=lambda org_id: _with_api_client(
                lambda client: CustomDetectorsOrgLibApi(
                    client
                ).get_custom_detectors_organizations_organization_id_custom_detectors_get(  # noqa: E501
                    organization_id=org_id
                )
            ),
            fetch_custom_detectors_library=lambda: _with_api_client(
                lambda client: CustomDetectorsStdLibApi(
                    client
                ).get_custom_detectors_library_custom_detectors_library_get()
            ),
        )
        created_task = await _with_api_client(
            lambda client: ToolsApi(
                client
            ).post_tool_vanguard_v2_organizations_organization_id_projects_project_id_versions_version_id_tools_vanguard_v2_post(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
                version_id=version_id,
                defi_vanguard_v2_input=sdk_input,
            )
        )
        return _orca_task_creation_ta.validate_python(created_task)

    return await _run_tool(
        _run,
        tool_name=_RUN_DEFI_VANGUARD_TASK_TOOL_NAME,
        safe_args={
            "organization_id": organization_id,
            "project_id": project_id,
            "version_id": version_id,
        },
    )


async def create_version_from_url(
    organization_id: _AhId,
    project_id: _AhId,
    version_input: VersionFromUrlInput,
) -> VersionCreation:
    """Create an AuditHub project version from a git repository or archive URL."""

    async def _run() -> VersionCreation:
        _assert_version_creation_enabled()
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        created_version = await _with_api_client(
            lambda client: VersionsApi(
                client
            ).post_version_with_url_organizations_organization_id_projects_project_id_versions_url_post(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
                name=version_input.name,
                input_type=version_input.input_type,
                url=version_input.url,
                commit_hash=version_input.commit_hash,
                is_deployed=version_input.is_deployed,
                revision=version_input.revision,
                includes_submodules=version_input.includes_submodules,
            )
        )
        return _version_creation_ta.validate_python(created_version)

    return await _run_tool(
        _run,
        tool_name=_CREATE_VERSION_FROM_URL_TOOL_NAME,
        safe_args={"organization_id": organization_id, "project_id": project_id},
    )


async def create_version_from_file(
    organization_id: _AhId,
    project_id: _AhId,
    version_input: VersionFromFileInput,
) -> VersionCreation:
    """Create an AuditHub project version by uploading a .zip file of the project source code."""

    async def _run() -> VersionCreation:
        _assert_version_creation_enabled()
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        created_version = await _with_api_client(
            lambda client: _create_version_from_archive_with_client(
                client,
                organization_id=organization_id,
                project_id=project_id,
                version_input=version_input,
            )
        )
        return _version_creation_ta.validate_python(created_version)

    return await _run_tool(
        _run,
        tool_name=_CREATE_VERSION_FROM_FILE_TOOL_NAME,
        safe_args={"organization_id": organization_id, "project_id": project_id},
    )


async def _create_version_from_archive_with_client(
    client: AuthenticatedApiClient,
    *,
    organization_id: int,
    project_id: int,
    version_input: VersionFromFileInput,
) -> VersionCreation:
    """Create a version by sending the .zip archive as multipart upload data."""
    method, url, headers, body, post_params = client.param_serialize(
        method="POST",
        resource_path="/organizations/{organization_id}/projects/{project_id}/versions",
        path_params={"organization_id": organization_id, "project_id": project_id},
        query_params=None,
        header_params={
            "Accept": "application/json",
            "Content-Type": "multipart/form-data",
        },
        body=None,
        post_params=[
            ("name", version_input.name),
            *(
                [("commit_hash", version_input.commit_hash)]
                if version_input.commit_hash is not None
                else []
            ),
            *(
                [("is_deployed", version_input.is_deployed)]
                if version_input.is_deployed is not None
                else []
            ),
        ],
        files={"archive": version_input.archive},
        auth_settings=["OpenIdConnect"],
        collection_formats={},
    )
    response_data = await client.call_api(method, url, headers, body, post_params)
    await response_data.read()
    created_version = client.response_deserialize(
        response_data=response_data,
        response_types_map={"200": "IdAndMessageResponse"},
    ).data
    return _version_creation_ta.validate_python(created_version.model_dump())


def _read_custom_detector_contents(file_path: str) -> str:
    """Read a custom detector file from disk as UTF-8 text."""
    detector_path = Path(file_path)
    try:
        return detector_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"Failed to read custom detector file {detector_path}: {exc}") from None


async def _get_custom_detector_with_client(
    client: AuthenticatedApiClient,
    *,
    organization_id: int,
    custom_detector_id: int,
) -> CustomDetector:
    """Fetch a custom detector by ID from an organization."""
    return await CustomDetectorsOrgLibApi(
        client
    ).get_custom_detector_organizations_organization_id_custom_detectors_custom_detector_id_get(
        organization_id=organization_id,
        custom_detector_id=custom_detector_id,
    )


async def _upload_custom_detector_with_client(
    client: AuthenticatedApiClient,
    *,
    organization_id: int,
    file_path: str,
    filename: str | None,
    update: int | None,
) -> CustomDetectorUploadResult:
    """Create or update an organization-level custom detector."""
    contents = _read_custom_detector_contents(file_path)
    if update is None:
        if filename is None:
            raise RuntimeError("filename is required when creating a custom detector")
        created_detector = await CustomDetectorsOrgLibApi(
            client
        ).post_custom_detector_organizations_organization_id_custom_detectors_post(
            organization_id=organization_id,
            custom_detector=CustomDetector(
                filename=filename,
                contents=contents,
                encoding="plain",
            ),
        )
        return CustomDetectorUploadResult(
            id=created_detector.id,
            filename=filename,
            message=created_detector.message,
        )

    resolved_filename = filename
    if resolved_filename is None:
        existing_detector = await _get_custom_detector_with_client(
            client,
            organization_id=organization_id,
            custom_detector_id=update,
        )
        resolved_filename = existing_detector.filename

    updated_detector = await CustomDetectorsOrgLibApi(
        client
    ).put_custom_detector_organizations_organization_id_custom_detectors_custom_detector_id_put(
        organization_id=organization_id,
        custom_detector_id=update,
        custom_detector=CustomDetector(
            filename=resolved_filename,
            contents=contents,
            encoding="plain",
        ),
    )
    return CustomDetectorUploadResult(
        id=update,
        filename=resolved_filename,
        message=updated_detector.message,
    )


@mcp.tool()
async def upload_custom_detector(
    organization_id: _AhId,
    file_path: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Absolute path to the custom detector definition file. "
                "MUST follow the format documented in docs://vanguard/custom-detectors"
            ),
        ),
    ],
    filename: Annotated[
        str | None,
        Field(
            min_length=1,
            description=(
                "Filename of this detector (not unique). Required when creating a new detector."
            ),
        ),
    ] = None,
    update: Annotated[
        _PositiveId | None,
        Field(description="Custom detector ID to update instead of creating a new detector."),
    ] = None,
) -> CustomDetectorUploadResult:
    """Upload or update an organization-level custom detector from a local file."""

    async def _run() -> CustomDetectorUploadResult:
        _assert_edit_custom_detectors_enabled()
        _assert_org_allowed(organization_id)
        if update is None and filename is None:
            raise RuntimeError("filename is required when update is not provided")
        uploaded_detector = await _with_api_client(
            lambda client: _upload_custom_detector_with_client(
                client,
                organization_id=organization_id,
                file_path=file_path,
                filename=filename,
                update=update,
            )
        )
        return uploaded_detector

    return await _run_tool(
        _run,
        tool_name="upload_custom_detector",
        safe_args={"organization_id": organization_id, "update": update},
    )


_RUN_ORCA_TASK_TOOL_NAME = "run_orca_task"
_RUN_DEFI_VANGUARD_TASK_TOOL_NAME = "run_defi_vanguard_task"
_CREATE_VERSION_FROM_FILE_TOOL_NAME = "create_version_from_file"
_CREATE_VERSION_FROM_URL_TOOL_NAME = "create_version_from_url"
_UPLOAD_CUSTOM_DETECTOR_TOOL_NAME = "upload_custom_detector"

_TASK_RUN_TOOLS = (
    RegisteredTool(_RUN_ORCA_TASK_TOOL_NAME, run_orca_task),
    RegisteredTool(_RUN_DEFI_VANGUARD_TASK_TOOL_NAME, run_defi_vanguard_task),
)
_VERSION_CREATION_TOOLS = (
    RegisteredTool(_CREATE_VERSION_FROM_FILE_TOOL_NAME, create_version_from_file),
    RegisteredTool(_CREATE_VERSION_FROM_URL_TOOL_NAME, create_version_from_url),
)
_CUSTOM_DETECTOR_UPLOAD_TOOLS = (
    RegisteredTool(_UPLOAD_CUSTOM_DETECTOR_TOOL_NAME, upload_custom_detector),
)


def _mark_wait_for_task_completion_as_task_required() -> None:
    """Advertise ``wait_for_task_completion`` as task-required in tool listings."""
    original_handler = mcp._mcp_server.request_handlers[mcp_types.ListToolsRequest]

    async def _handler(request: mcp_types.ListToolsRequest) -> mcp_types.ServerResult:
        result = await original_handler(request)
        list_tools_result = result.root
        if isinstance(list_tools_result, mcp_types.ListToolsResult):
            for tool in list_tools_result.tools:
                if tool.name != _WAIT_FOR_TASK_COMPLETION_TOOL_NAME:
                    continue
                tool.execution = mcp_types.ToolExecution(taskSupport=mcp_types.TASK_OPTIONAL)
                mcp._mcp_server._tool_cache[tool.name] = tool
                break
        return result

    mcp._mcp_server.request_handlers[mcp_types.ListToolsRequest] = _handler


_mark_wait_for_task_completion_as_task_required()


def main() -> None:
    """Entry point for the ``audithub-mcp`` console script."""
    parser = _build_arg_parser()
    args, _ = parser.parse_known_args()
    try:
        if args.list_tools:
            _set_task_runs_enabled(True)
            _set_version_creation_enabled(True)
            _set_edit_custom_detectors_enabled(True)
            asyncio.run(_list_tools())
            return
        settings = _apply_cli_args_to_config(_load_settings_from_cli_args(args), args)
        validate_startup_config(settings)
    except RuntimeError as exc:
        sys.exit(str(exc))

    global _allowed_org_ids, _allowed_project_ids, _context
    _allowed_org_ids = settings.allowed_org_ids
    _allowed_project_ids = settings.allowed_project_ids
    _set_task_runs_enabled(settings.task_runs_enabled)
    _set_version_creation_enabled(settings.version_creation_enabled)
    _set_edit_custom_detectors_enabled(settings.edit_custom_detectors_enabled)
    _context = settings.context
    mcp.run()


if __name__ == "__main__":
    main()
