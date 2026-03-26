"""Read-only MCP server for AuditHub backed exclusively by ``audithub-sdk``.

Security model
--------------
This server is intentionally read-only. Every MCP tool is named ``get_*`` and
only invokes generated SDK methods for HTTP GET endpoints. No raw HTTP helper
or mutation-capable AuditHub client remains in this module.
"""

from __future__ import annotations

import argparse
import inspect
import os
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Annotated

import audithub_sdk
from audithub_sdk.api.issues_api import IssuesApi
from audithub_sdk.api.projects_api import ProjectsApi
from audithub_sdk.api.tasks_api import TasksApi
from audithub_sdk.api.users_api import UsersApi
from audithub_sdk.api.versions_api import VersionsApi
from audithub_sdk_ext import AuthenticatedApiClient, OIDCClientCredentialsContext
from mcp.server.fastmcp import FastMCP
from pydantic import Field, TypeAdapter

from ah_mcp.audit import log_call_error, log_call_start, log_call_success
from ah_mcp.models import (
    Comment,
    IssueDetails,
    IssueForList,
    Organization,
    OrganizationNameIndexEntry,
    Project,
    ProjectNameIndexEntry,
    Task,
    Thread,
    Version,
    VersionNameIndexEntry,
)

_AhId = Annotated[int, Field(strict=True, gt=0)]

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

_org_ta = TypeAdapter(list[Organization])
_comment_ta = TypeAdapter(list[Comment])
_thread_ta = TypeAdapter(list[Thread])
_issue_list_ta = TypeAdapter(list[IssueForList])
_project_ta = TypeAdapter(list[Project])
_version_ta = TypeAdapter(list[Version])
_str_list_ta = TypeAdapter(list[str])


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
        if tool_name:
            log_call_error(tool_name, str(exc), elapsed_ms)
            sanitized = RuntimeError(
                "An internal error occurred. Details have been logged."
                if not isinstance(getattr(exc, "status", None), int)
                else _safe_exception_message(exc)
            )
        else:
            sanitized = RuntimeError(_safe_exception_message(exc))
    raise sanitized


@mcp.tool()
async def get_my_organizations() -> list[Organization]:
    """List AuditHub organizations the authenticated user belongs to."""

    async def _run() -> list[Organization]:
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
        projects = await _with_api_client(
            lambda client: ProjectsApi(client).get_projects_organizations_organization_id_projects_get(  # noqa: E501
                organization_id=organization_id
            )
        )
        entries = [
            ProjectNameIndexEntry(
                id=project.id,
                name=project.name,
                lookup_key=_normalize_lookup_key(project.name),
            )
            for project in _project_ta.validate_python(projects)
            if project.id in _allowed_project_ids
        ]
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
        return Task.model_validate(task)

    return await _run_tool(
        _run,
        tool_name="get_task_info",
        safe_args={"organization_id": organization_id, "task_id": task_id},
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
async def get_version_comments(
    organization_id: _AhId,
    project_id: _AhId,
    version_id: _AhId,
    limit: Annotated[int, Field(ge=0)] | None = 200,
    offset: Annotated[int, Field(ge=0)] | None = 0,
) -> list[Comment]:
    """Get comments for a specific project version."""

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
    """Get all comments for an AuditHub project across all versions."""

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


def main() -> None:
    """Entry point for the ``ah-mcp`` console script."""
    parser = argparse.ArgumentParser(
        description="AuditHub read-only MCP server",
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
    args, _ = parser.parse_known_args()

    org_ids_raw = args.allowed_org_ids or os.environ.get("AH_ALLOWED_ORG_IDS", "")
    proj_ids_raw = args.allowed_project_ids or os.environ.get("AH_ALLOWED_PROJECT_IDS", "")

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
    _context = _build_context()
    mcp.run()


if __name__ == "__main__":
    main()
