"""MCP server for AuditHub backed exclusively by ``audithub-sdk``.

Security model
--------------
This server is read-only by default. Read tools are named ``get_*`` and only
invoke generated SDK methods for HTTP GET endpoints. Mutation tools are
registered only when their narrow opt-in gates are explicitly enabled.
"""

from __future__ import annotations

import argparse
import base64
import inspect
import os
import sys
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated

import audithub_sdk
from audithub_sdk.api.issues_api import IssuesApi
from audithub_sdk.api.projects_api import ProjectsApi
from audithub_sdk.api.tasks_api import TasksApi
from audithub_sdk.api.tools_api import ToolsApi
from audithub_sdk.api.users_api import UsersApi
from audithub_sdk.api.versions_api import VersionsApi
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
from mcp.server.fastmcp import FastMCP
from pydantic import Field, TypeAdapter

from ah_mcp.audit import log_call_error, log_call_start, log_call_success
from ah_mcp.models import (
    Comment,
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
    OrganizationNameIndexEntry,
    Project,
    ProjectNameIndexEntry,
    Task,
    TaskArtifact,
    TaskArtifactContent,
    TaskCreation,
    Thread,
    Version,
    VersionCreation,
    VersionFromArchiveInput,
    VersionFromUrlInput,
    VersionNameIndexEntry,
)

_AhId = Annotated[int, Field(strict=True, gt=0)]
_ArtifactId = Annotated[str, Field(min_length=1)]
_MaxBytes = Annotated[int, Field(strict=True, gt=0)]

mcp = FastMCP("ah")

_REQUIRED_ENV_VARS: tuple[str, ...] = (
    "AUDITHUB_BASE_URL",
    "AUDITHUB_OIDC_CONFIGURATION_URL",
    "AUDITHUB_OIDC_CLIENT_ID",
    "AUDITHUB_OIDC_CLIENT_SECRET",
)


@dataclass(frozen=True)
class AuditHubSdkContext:
    """Static SDK configuration derived from environment variables at startup."""

    configuration: audithub_sdk.Configuration
    auth_context: OIDCClientCredentialsContext


_context: AuditHubSdkContext | None = None
_allowed_org_ids: frozenset[int] = frozenset()
_allowed_project_ids: frozenset[int] = frozenset()
_task_runs_enabled = False
_version_creation_enabled = False

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

_DEFAULT_ARTIFACT_MAX_BYTES = 5 * 1024 * 1024

_TASK_RUN_TOOL_NAME = "run_orca_task"
_VERSION_CREATION_TOOL_NAMES = (
    "create_version_from_archive",
    "create_version_from_url",
)
_SdkOrCaSpecActual = (
    VSpecFromVersion | VSpecFromStandardLibrary | VSpecFromOrganizationLibrary | VSpecAdHoc
)
_SdkOrCaHintActual = (
    HintFromVersion | HintFromStandardLibrary | HintFromOrganizationLibrary | HintAdHoc
)


def _parse_id_list(value: str, flag: str) -> frozenset[int]:
    """Parse a comma-separated string of positive integers into a frozenset."""
    try:
        ids = frozenset(int(tok.strip()) for tok in value.split(",") if tok.strip())
    except ValueError:
        sys.exit(f"Error: {flag} must be a comma-separated list of integers, got: {value!r}")
    non_positive = [item for item in ids if item <= 0]
    if non_positive:
        sys.exit(f"Error: {flag} contains non-positive IDs: {sorted(non_positive)}")
    return ids


def _parse_bool_flag(value: str | None, flag: str) -> bool:
    """Parse an optional boolean environment flag."""
    if value is None or value == "":
        return False
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    sys.exit(f"Error: {flag} must be one of 1/0, true/false, yes/no, or on/off.")


def _is_tool_registered(tool_name: str) -> bool:
    """Return whether an MCP tool is currently registered."""
    return tool_name in mcp._tool_manager._tools


def _set_task_runs_enabled(enabled: bool) -> None:
    """Enable or disable opt-in task-run MCP tools."""
    global _task_runs_enabled
    _task_runs_enabled = enabled
    if enabled:
        if not _is_tool_registered(_TASK_RUN_TOOL_NAME):
            mcp.add_tool(run_orca_task)
        return
    if _is_tool_registered(_TASK_RUN_TOOL_NAME):
        mcp.remove_tool(_TASK_RUN_TOOL_NAME)


def _set_version_creation_enabled(enabled: bool) -> None:
    """Enable or disable opt-in version-creation MCP tools."""
    global _version_creation_enabled
    _version_creation_enabled = enabled
    if enabled:
        if not _is_tool_registered(_VERSION_CREATION_TOOL_NAMES[0]):
            mcp.add_tool(create_version_from_archive)
        if not _is_tool_registered(_VERSION_CREATION_TOOL_NAMES[1]):
            mcp.add_tool(create_version_from_url)
        return
    for tool_name in _VERSION_CREATION_TOOL_NAMES:
        if _is_tool_registered(tool_name):
            mcp.remove_tool(tool_name)


def _assert_task_runs_enabled() -> None:
    """Raise unless mutating AuditHub task runs are enabled."""
    if not _task_runs_enabled:
        raise RuntimeError(
            "AuditHub task runs are disabled. Restart the server with "
            "--enable-task-runs or AH_ENABLE_TASK_RUNS=1 to enable run_orca_task."
        )


def _assert_version_creation_enabled() -> None:
    """Raise unless mutating AuditHub version creation is enabled."""
    if not _version_creation_enabled:
        raise RuntimeError(
            "AuditHub version creation is disabled. Restart the server with "
            "--enable-version-creation or AH_ENABLE_VERSION_CREATION=1 to enable "
            "create_version_from_archive and create_version_from_url."
        )


def _build_context() -> AuditHubSdkContext:
    """Read AuditHub SDK/auth configuration from environment variables."""
    missing = [v for v in _REQUIRED_ENV_VARS if not os.environ.get(v)]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    configuration = audithub_sdk.Configuration(host=os.environ["AUDITHUB_BASE_URL"])
    auth_context = OIDCClientCredentialsContext(
        oidc_configuration_url=os.environ["AUDITHUB_OIDC_CONFIGURATION_URL"],
        client_id=os.environ["AUDITHUB_OIDC_CLIENT_ID"],
        client_secret=os.environ["AUDITHUB_OIDC_CLIENT_SECRET"],
    )
    return AuditHubSdkContext(configuration=configuration, auth_context=auth_context)


def _ctx() -> AuditHubSdkContext:
    """Return the cached SDK context."""
    if _context is None:
        raise RuntimeError(
            "AuditHub context is not initialised. "
            "Ensure all required environment variables are set before starting the server: "
            + ", ".join(_REQUIRED_ENV_VARS)
        )
    return _context


def _assert_org_allowed(organization_id: int) -> None:
    """Raise if *organization_id* is not allowlisted."""
    if organization_id not in _allowed_org_ids:
        raise RuntimeError(
            f"Organization ID {organization_id} is not in the configured allowlist. "
            "Call get_my_organizations to find the IDs you have access to."
        )


def _assert_project_allowed(project_id: int) -> None:
    """Raise if *project_id* is not allowlisted."""
    if project_id not in _allowed_project_ids:
        raise RuntimeError(
            f"Project ID {project_id} is not in the configured allowlist. "
            "Use get_project after finding a valid organization ID."
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


def _normalize_lookup_key(name: str) -> str:
    """Normalize a user-visible name into a deterministic case-insensitive lookup key."""
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
        TaskArtifact.model_validate(artifact, from_attributes=True)
        for artifact in task.artifacts
    ]


def _response_header(headers: Mapping[str, str] | None, name: str) -> str | None:
    """Read a response header without depending on a concrete header mapping type."""
    if headers is None:
        return None
    folded_name = name.casefold()
    for key, value in headers.items():
        if key.casefold() == folded_name:
            return value
    return None


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
    safe_args: dict[str, int | None] | None = None,
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
async def get_my_organizations() -> list[MyOrganization]:
    """List AuditHub organizations the authenticated user belongs to."""

    async def _run() -> list[MyOrganization]:
        organizations = await _with_api_client(
            lambda client: UsersApi(client).get_organizations_users_myorganizations_get()
        )
        orgs = _org_ta.validate_python(organizations)
        return [org for org in orgs if org.id in _allowed_org_ids]

    return await _run_tool(_run, tool_name="get_my_organizations", safe_args={})


@mcp.tool()
async def get_organization_name_index() -> list[OrganizationNameIndexEntry]:
    """List allowlisted AuditHub organizations as deterministic name lookup entries."""

    async def _run() -> list[OrganizationNameIndexEntry]:
        organizations = await _with_api_client(
            lambda client: UsersApi(client).get_organizations_users_myorganizations_get()
        )
        orgs = _org_ta.validate_python(organizations)
        entries = [
            OrganizationNameIndexEntry(
                id=org.id,
                name=org.name,
                lookup_key=_normalize_lookup_key(org.name),
            )
            for org in orgs
            if org.id in _allowed_org_ids
        ]
        return sorted(entries, key=lambda entry: (entry.lookup_key, entry.id))

    return await _run_tool(_run, tool_name="get_organization_name_index", safe_args={})


@mcp.tool()
async def get_project(organization_id: _AhId, project_id: _AhId) -> Project:
    """Get details for a specific AuditHub project."""

    async def _run() -> Project:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        project = await _with_api_client(
            lambda client: ProjectsApi(client).get_project_organizations_organization_id_projects_project_id_get(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
            )
        )
        return Project.model_validate(project)

    return await _run_tool(
        _run,
        tool_name="get_project",
        safe_args={"organization_id": organization_id, "project_id": project_id},
    )


@mcp.tool()
async def get_project_name_index(organization_id: _AhId) -> list[ProjectNameIndexEntry]:
    """List allowlisted projects in an organization as deterministic name lookup entries."""

    async def _run() -> list[ProjectNameIndexEntry]:
        _assert_org_allowed(organization_id)

        async def _fetch_project(project_id: int) -> Project:
            project = await _with_api_client(
                lambda client: ProjectsApi(client).get_project_organizations_organization_id_projects_project_id_get(  # noqa: E501
                    organization_id=organization_id,
                    project_id=project_id,
                )
            )
            return Project.model_validate(project)

        entries: list[ProjectNameIndexEntry] = []
        for project_id in sorted(_allowed_project_ids):
            try:
                validated_project = await _fetch_project(project_id)
            except Exception as exc:
                status = getattr(exc, "status", None)
                if isinstance(status, int) and status == 404:
                    continue
                raise
            entries.append(
                ProjectNameIndexEntry(
                    id=validated_project.id,
                    name=validated_project.name,
                    lookup_key=_normalize_lookup_key(validated_project.name),
                )
            )
        return sorted(entries, key=lambda entry: (entry.lookup_key, entry.id))

    return await _run_tool(
        _run,
        tool_name="get_project_name_index",
        safe_args={"organization_id": organization_id},
    )


@mcp.tool()
async def get_latest_version(organization_id: _AhId, project_id: _AhId) -> Version:
    """Get the latest version of an AuditHub project."""

    async def _run() -> Version:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        version = await _with_api_client(
            lambda client: VersionsApi(client).get_latest_version_organizations_organization_id_projects_project_id_versions_latest_get(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
            )
        )
        return Version.model_validate(version)

    return await _run_tool(
        _run,
        tool_name="get_latest_version",
        safe_args={"organization_id": organization_id, "project_id": project_id},
    )


@mcp.tool()
async def get_version_name_index(
    organization_id: _AhId, project_id: _AhId
) -> list[VersionNameIndexEntry]:
    """List project versions as deterministic name lookup entries."""

    async def _run() -> list[VersionNameIndexEntry]:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        versions = await _with_api_client(
            lambda client: VersionsApi(client).get_versions_organizations_organization_id_projects_project_id_versions_get(  # noqa: E501
                organization_id=organization_id,
                project_id=project_id,
            )
        )
        entries = [
            VersionNameIndexEntry(
                id=version.id,
                name=version.name,
                lookup_key=_normalize_lookup_key(version.name),
            )
            for version in _version_ta.validate_python(versions)
        ]
        return sorted(entries, key=lambda entry: (entry.lookup_key, entry.id))

    return await _run_tool(
        _run,
        tool_name="get_version_name_index",
        safe_args={"organization_id": organization_id, "project_id": project_id},
    )


@mcp.tool()
async def get_task_info(organization_id: _AhId, task_id: _AhId) -> Task:
    """Get status and details for an AuditHub task."""

    async def _run() -> Task:
        _assert_org_allowed(organization_id)
        task = await _with_api_client(
            lambda client: TasksApi(client).get_info_organizations_organization_id_tasks_task_id_get(  # noqa: E501
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
async def get_task_artifacts(organization_id: _AhId, task_id: _AhId) -> list[TaskArtifact]:
    """List sanitized artifact metadata for an AuditHub task."""

    async def _run() -> list[TaskArtifact]:
        _assert_org_allowed(organization_id)
        task = await _with_api_client(
            lambda client: TasksApi(client).get_info_organizations_organization_id_tasks_task_id_get(  # noqa: E501
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
    """Fetch an AuditHub task artifact as base64-encoded content."""

    async def _run() -> TaskArtifactContent:
        _assert_org_allowed(organization_id)
        response = await _with_api_client(
            lambda client: TasksApi(client).get_artifact_organizations_organization_id_tasks_task_id_artifacts_artifact_id_get_with_http_info(  # noqa: E501
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
async def get_task_logs(organization_id: _AhId, task_id: _AhId, step_code: str) -> list[str]:
    """Get logs for a specific step of an AuditHub task."""

    async def _run() -> list[str]:
        _assert_org_allowed(organization_id)
        logs = await _with_api_client(
            lambda client: TasksApi(client).get_output_organizations_organization_id_tasks_task_id_step_code_output_get(  # noqa: E501
                organization_id=organization_id,
                task_id=task_id,
                step_code=step_code,
            )
        )
        return _str_list_ta.validate_python(logs)

    return await _run_tool(
        _run,
        tool_name="get_task_logs",
        safe_args={"organization_id": organization_id, "task_id": task_id},
    )


@mcp.tool()
async def get_task_findings(organization_id: _AhId, task_id: _AhId) -> list[FIOData]:
    """Get findings produced by an AuditHub task execution."""

    async def _run() -> list[FIOData]:
        _assert_org_allowed(organization_id)
        findings = await _with_api_client(
            lambda client: TasksApi(client).get_task_findings_organizations_organization_id_tasks_task_id_findings_get(  # noqa: E501
                organization_id=organization_id,
                task_id=task_id,
            )
        )
        return _fio_data_ta.validate_python(findings)

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
            lambda client: VersionsApi(client).get_version_comments_organizations_organization_id_projects_project_id_versions_version_id_comments_get(  # noqa: E501
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
            lambda client: VersionsApi(client).get_version_comment_threads_organizations_organization_id_projects_project_id_versions_version_id_comment_threads_get(  # noqa: E501
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
            lambda client: VersionsApi(client).get_version_comments_organizations_organization_id_projects_project_id_versions_version_id_comments_get(  # noqa: E501
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
            lambda client: IssuesApi(client).get_issues_organizations_organization_id_projects_project_id_issues_get(  # noqa: E501
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
            lambda client: IssuesApi(client).get_issue_organizations_organization_id_projects_project_id_issues_issue_id_get(  # noqa: E501
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
            lambda client: ProjectsApi(client).get_project_comments_organizations_organization_id_projects_project_id_comments_get(  # noqa: E501
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
        tool_name=_TASK_RUN_TOOL_NAME,
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
        tool_name=_VERSION_CREATION_TOOL_NAMES[1],
        safe_args={"organization_id": organization_id, "project_id": project_id},
    )


async def create_version_from_archive(
    organization_id: _AhId,
    project_id: _AhId,
    version_input: VersionFromArchiveInput,
) -> VersionCreation:
    """Create an AuditHub project version by uploading a local .zip archive."""

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
        tool_name=_VERSION_CREATION_TOOL_NAMES[0],
        safe_args={"organization_id": organization_id, "project_id": project_id},
    )


async def _create_version_from_archive_with_client(
    client: AuthenticatedApiClient,
    *,
    organization_id: int,
    project_id: int,
    version_input: VersionFromArchiveInput,
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


def main() -> None:
    """Entry point for the ``ah-mcp`` console script."""
    parser = argparse.ArgumentParser(
        description="AuditHub MCP server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--allowed-org-ids",
        metavar="IDS",
        help=(
            "Comma-separated organization IDs the server may access "
            "(overrides AH_ALLOWED_ORG_IDS)."
        ),
    )
    parser.add_argument(
        "--allowed-project-ids",
        metavar="IDS",
        help=(
            "Comma-separated project IDs the server may access "
            "(overrides AH_ALLOWED_PROJECT_IDS)."
        ),
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
    args, _ = parser.parse_known_args()

    org_ids_raw = args.allowed_org_ids or os.environ.get("AH_ALLOWED_ORG_IDS", "")
    proj_ids_raw = args.allowed_project_ids or os.environ.get("AH_ALLOWED_PROJECT_IDS", "")
    task_runs_enabled = args.enable_task_runs or _parse_bool_flag(
        os.environ.get("AH_ENABLE_TASK_RUNS"), "AH_ENABLE_TASK_RUNS"
    )
    version_creation_enabled = args.enable_version_creation or _parse_bool_flag(
        os.environ.get("AH_ENABLE_VERSION_CREATION"), "AH_ENABLE_VERSION_CREATION"
    )

    if not org_ids_raw:
        sys.exit(
            "Error: allowed organization IDs are required. "
            "Set --allowed-org-ids or AH_ALLOWED_ORG_IDS."
        )
    if not proj_ids_raw:
        sys.exit(
            "Error: allowed project IDs are required. "
            "Set --allowed-project-ids or AH_ALLOWED_PROJECT_IDS."
        )

    global _allowed_org_ids, _allowed_project_ids, _context
    _allowed_org_ids = _parse_id_list(org_ids_raw, "--allowed-org-ids / AH_ALLOWED_ORG_IDS")
    _allowed_project_ids = _parse_id_list(
        proj_ids_raw, "--allowed-project-ids / AH_ALLOWED_PROJECT_IDS"
    )
    _set_task_runs_enabled(task_runs_enabled)
    _set_version_creation_enabled(version_creation_enabled)
    _context = _build_context()
    mcp.run()


if __name__ == "__main__":
    main()
