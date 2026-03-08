"""Read-only MCP server for AuditHub.

.. warning::
    This MCP server is currently under-developed and has not been tested.
    Verify all tool outputs manually before acting on them.

Security model
--------------
This server is intentionally **read-only**.  All MCP tools exposed here issue
HTTP GET requests and return data; no tool can create, modify, or delete any
AuditHub resource.

The enforcement is layered:

1. **Tool surface**: every registered tool is named ``get_*`` and calls either
   a read-only Python API function or ``_get()``, the sole HTTP helper, which
   is hard-wired to the ``GET`` method constant imported from
   ``audithub_client.library.http``.  No ``POST``, ``PATCH``, ``PUT``, or
   ``DELETE`` path exists in this module.

2. **Credential handling**: OIDC credentials are read from environment
   variables once at server startup by ``main()``, validated immediately, and
   cached for the lifetime of the process.  Credentials are never echoed in
   tool return values and are not accepted as tool arguments.  ``_run_tool()``
   catches all non-``RuntimeError`` exceptions (which may include credential
   material in error messages from the underlying OIDC library) and re-raises
   them as sanitised ``RuntimeError`` instances before they reach FastMCP's
   error handler.

3. **Admin endpoint exclusion**: this server does not call ``/admin/*``
   endpoints.  The endpoints reached by ``_get()`` paths are limited to the
   non-admin thread/comment/issue subset documented in
   ``references/non_admin_thread_issue_endpoints.tsv``.  Endpoints backed by
   named ``audithub_client`` API functions (``get_task_info`` etc.) likewise
   do not touch admin paths.

4. **ID allowlisting**: the server requires explicit allowlists of permitted
   organization IDs and project IDs, configured at startup via environment
   variables or CLI flags.  All ID parameters are declared as
   ``Annotated[int, Field(strict=True, gt=0)]``, so Pydantic/FastMCP rejects
   non-integers, floats, strings, and non-positive values at the
   deserialization boundary before the tool body runs.  The allowlist check
   then confirms the validated integer is in the configured set before any
   network request is made. Error messages report the rejected ID but do not
   enumerate the full allowlist, preventing information disclosure.

Required environment variables (or CLI flags)
---------------------------------------------
``AUDITHUB_BASE_URL``
    Base URL of the AuditHub REST API, e.g. ``https://audithub.veridise.com/api/v1``.
``AUDITHUB_OIDC_CONFIGURATION_URL``
    OpenID Connect discovery document URL for the identity provider.
``AUDITHUB_OIDC_CLIENT_ID``
    OIDC client identifier.
``AUDITHUB_OIDC_CLIENT_SECRET``
    OIDC client secret.  Keep this value out of logs and shell history.
``AH_ALLOWED_ORG_IDS`` / ``--allowed-org-ids``
    Comma-separated list of numeric organization IDs the server may access,
    e.g. ``"1,2,3"``.  Required.
``AH_ALLOWED_PROJECT_IDS`` / ``--allowed-project-ids``
    Comma-separated list of numeric project IDs the server may access,
    e.g. ``"10,20"``.  Required.

For each allowlist setting the CLI flag takes precedence over the environment
variable when both are supplied.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from typing import Annotated, Any

from audithub_client.api.get_latest_version import GetLatestVersionArgs, api_get_latest_version
from audithub_client.api.get_my_organizations import api_get_my_organizations
from audithub_client.api.get_project import GetProjectArgs, api_get_project
from audithub_client.api.get_task_info import GetTaskInfoArgs, api_get_task_info
from audithub_client.api.get_task_logs import GetTaskLogsArgs, api_get_task_logs
from audithub_client.api.get_version_comments import (
    GetVersionCommentsArgs,
    api_get_version_comments,
)
from audithub_client.library.auth import authentication_retry
from audithub_client.library.context import AuditHubContext
from audithub_client.library.http import GET
from audithub_client.library.net_utils import ensure_success, response_json
from mcp.server.fastmcp import FastMCP
from pydantic import Field, TypeAdapter

from ah_mcp.models import (
    Comment,
    IssueDetails,
    IssueForList,
    Organization,
    Project,
    Task,
    Thread,
    Version,
)

#: Positive integer type used for all AuditHub ID parameters.
#: ``strict=True`` prevents string/float coercion; ``gt=0`` rejects zero and
#: negatives.  These constraints are enforced by Pydantic/FastMCP at the
#: schema-deserialization boundary before any tool body runs.
_AhId = Annotated[int, Field(strict=True, gt=0)]

mcp = FastMCP("ah")

#: Environment variables required for AuditHub connectivity.
_REQUIRED_ENV_VARS: tuple[str, ...] = (
    "AUDITHUB_BASE_URL",
    "AUDITHUB_OIDC_CONFIGURATION_URL",
    "AUDITHUB_OIDC_CLIENT_ID",
    "AUDITHUB_OIDC_CLIENT_SECRET",
)

#: Cached context built once at startup; ``None`` until ``main()`` is called.
_context: AuditHubContext | None = None

#: Allowlisted organization IDs; populated at startup.
_allowed_org_ids: frozenset[int] = frozenset()

#: Allowlisted project IDs; populated at startup.
_allowed_project_ids: frozenset[int] = frozenset()

# TypeAdapters for validating list responses from the API.
_org_ta = TypeAdapter(list[Organization])
_comment_ta = TypeAdapter(list[Comment])
_thread_ta = TypeAdapter(list[Thread])
_issue_list_ta = TypeAdapter(list[IssueForList])
_str_list_ta = TypeAdapter(list[str])


# ---------------------------------------------------------------------------
# Startup helpers
# ---------------------------------------------------------------------------


def _parse_id_list(value: str, flag: str) -> frozenset[int]:
    """Parse a comma-separated string of integers into a frozenset.

    Args:
        value: Raw string, e.g. ``"1,2,3"``.
        flag:  Name of the flag or env var for error messages.

    Returns:
        Frozenset of parsed integers.

    Raises:
        SystemExit: If any token is not a valid integer.
    """
    try:
        return frozenset(int(tok.strip()) for tok in value.split(",") if tok.strip())
    except ValueError:
        sys.exit(f"Error: {flag} must be a comma-separated list of integers, got: {value!r}")


def _build_context() -> AuditHubContext:
    """Read AuditHub credentials from the current environment and return a context.

    Raises ``RuntimeError`` listing every missing variable so the error is
    actionable and does not expose partial credential state.  Called once by
    ``main()`` at server startup.
    """
    missing = [v for v in _REQUIRED_ENV_VARS if not os.environ.get(v)]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")
    return AuditHubContext(
        base_url=os.environ["AUDITHUB_BASE_URL"],
        oidc_configuration_url=os.environ["AUDITHUB_OIDC_CONFIGURATION_URL"],
        oidc_client_id=os.environ["AUDITHUB_OIDC_CLIENT_ID"],
        oidc_client_secret=os.environ["AUDITHUB_OIDC_CLIENT_SECRET"],
    )


def _ctx() -> AuditHubContext:
    """Return the cached ``AuditHubContext``, raising if startup was skipped.

    Under normal operation the context is built and validated once in
    ``main()`` from the environment variables present when the server process
    starts.  Tools call this function to retrieve the cached value; they do
    not re-read the environment on every invocation.

    Raises ``RuntimeError`` if called before ``main()`` initialises the
    context (e.g. in tests that mock this function directly).
    """
    if _context is None:
        raise RuntimeError(
            "AuditHub context is not initialised. "
            "Ensure all required environment variables are set before starting the server: "
            + ", ".join(_REQUIRED_ENV_VARS)
        )
    return _context


# ---------------------------------------------------------------------------
# Allowlist enforcement
# ---------------------------------------------------------------------------


def _assert_org_allowed(organization_id: int) -> None:
    """Raise ``RuntimeError`` if *organization_id* is not in the allowlist.

    Type and bounds validation (strict integer, positive) are enforced by
    Pydantic at the deserialization boundary before this function is called.
    This check runs before any network request so disallowed IDs never reach
    the AuditHub API.
    """
    if organization_id not in _allowed_org_ids:
        raise RuntimeError(
            f"Organization ID {organization_id} is not in the configured allowlist."
        )


def _assert_project_allowed(project_id: int) -> None:
    """Raise ``RuntimeError`` if *project_id* is not in the allowlist.

    Type and bounds validation (strict integer, positive) are enforced by
    Pydantic at the deserialization boundary before this function is called.
    This check runs before any network request so disallowed IDs never reach
    the AuditHub API.
    """
    if project_id not in _allowed_project_ids:
        raise RuntimeError(
            f"Project ID {project_id} is not in the configured allowlist."
        )


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _get(path: str, params: dict[str, int] | None = None) -> Any:
    """Issue an authenticated HTTP **GET** request to *path* on the AuditHub API.

    This is the only HTTP helper in this module.  It is deliberately hard-wired
    to ``GET``; it does not accept an HTTP method argument and cannot be
    repurposed for mutating requests.

    Args:
        path: URL path relative to ``AUDITHUB_BASE_URL``, e.g.
            ``/organizations/1/projects/2/issues``.
        params: Optional query-string parameters.

    Returns:
        Parsed JSON response body (to be validated by the caller).

    Raises:
        RuntimeError: If credentials are missing, the OIDC flow fails, or the
            server returns a non-2xx status.
    """
    ctx = _ctx()
    response = authentication_retry(
        ctx,
        GET,
        url=f"{ctx.base_url.rstrip('/')}{path}",
        params=params,
    )
    ensure_success(response)
    return response_json(response)


def _build_pagination_params(limit: int | None, offset: int | None) -> dict[str, int] | None:
    """Build a query-params dict from optional limit/offset values.

    Returns ``None`` when both are ``None`` so callers can pass the result
    directly to ``_get(..., params=...)`` without a separate ``or None`` guard.
    """
    params: dict[str, int] = {}
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    return params or None


def _run_tool[T](fn: Callable[[], T]) -> T:
    """Execute a tool function, sanitizing exceptions to prevent credential leakage.

    ``audithub_client``'s OIDC library may include credential material in
    exception messages or chained context.  This wrapper catches all
    non-``RuntimeError`` exceptions and re-raises them as plain
    ``RuntimeError`` with only ``str(exc)`` — no traceback, no chained
    cause — before they reach FastMCP's error handler.

    ``RuntimeError`` (raised by allowlist checks, missing config, and
    AuditHub API errors) propagates unchanged; it never contains raw
    credential values.

    Args:
        fn: Zero-argument callable returning the tool's result.

    Returns:
        The return value of *fn*.

    Raises:
        RuntimeError: On any failure, with a safe error message.
    """
    sanitized: RuntimeError | None = None
    try:
        return fn()
    except RuntimeError:
        raise
    except Exception as exc:
        sanitized = RuntimeError(str(exc))
    raise sanitized  # raised outside except block so __context__ is not set


# ---------------------------------------------------------------------------
# MCP tools — read-only GET operations only
# ---------------------------------------------------------------------------


@mcp.tool()
def get_my_organizations() -> list[Organization]:
    """List all AuditHub organizations the authenticated user belongs to."""
    def _run() -> list[Organization]:
        return _org_ta.validate_python(api_get_my_organizations(_ctx()))
    return _run_tool(_run)


@mcp.tool()
def get_project(organization_id: _AhId, project_id: _AhId) -> Project:
    """Get details for a specific AuditHub project.

    Args:
        organization_id: Numeric AuditHub organization ID.
        project_id: Numeric AuditHub project ID.
    """
    def _run() -> Project:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        return Project.model_validate(
            api_get_project(
                _ctx(), GetProjectArgs(organization_id=organization_id, project_id=project_id)
            )
        )
    return _run_tool(_run)


@mcp.tool()
def get_latest_version(organization_id: _AhId, project_id: _AhId) -> Version:
    """Get the latest version of an AuditHub project.

    Args:
        organization_id: Numeric AuditHub organization ID.
        project_id: Numeric AuditHub project ID.
    """
    def _run() -> Version:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        return Version.model_validate(
            api_get_latest_version(
                _ctx(),
                GetLatestVersionArgs(organization_id=organization_id, project_id=project_id),
            )
        )
    return _run_tool(_run)


@mcp.tool()
def get_task_info(organization_id: _AhId, task_id: _AhId) -> Task:
    """Get status and details for an AuditHub task.

    Args:
        organization_id: Numeric AuditHub organization ID.
        task_id: Numeric AuditHub task ID.
    """
    def _run() -> Task:
        _assert_org_allowed(organization_id)
        return Task.model_validate(
            api_get_task_info(
                _ctx(), GetTaskInfoArgs(organization_id=organization_id, task_id=task_id)
            )
        )
    return _run_tool(_run)


@mcp.tool()
def get_task_logs(organization_id: _AhId, task_id: _AhId, step_code: str) -> list[str]:
    """Get logs for a specific step of an AuditHub task.

    Args:
        organization_id: Numeric AuditHub organization ID.
        task_id: Numeric AuditHub task ID.
        step_code: Step code identifying which task step's logs to fetch.
            Use ``get_task_info`` to discover valid step codes for a task.
    """
    def _run() -> list[str]:
        _assert_org_allowed(organization_id)
        return _str_list_ta.validate_python(
            api_get_task_logs(
                _ctx(),
                GetTaskLogsArgs(
                    organization_id=organization_id, task_id=task_id, step_code=step_code
                ),
            )
        )
    return _run_tool(_run)


@mcp.tool()
def get_version_comments(
    organization_id: _AhId,
    project_id: _AhId,
    version_id: _AhId,
    limit: int | None = 200,
    offset: int | None = 0,
) -> list[Comment]:
    """Get comments for a specific project version.

    Args:
        organization_id: Numeric AuditHub organization ID.
        project_id: Numeric AuditHub project ID.
        version_id: Numeric AuditHub version ID.
        limit: Maximum number of results to return (default 200).
        offset: Pagination offset (default 0).
    """
    def _run() -> list[Comment]:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        return _comment_ta.validate_python(
            api_get_version_comments(
                _ctx(),
                GetVersionCommentsArgs(
                    organization_id=organization_id,
                    project_id=project_id,
                    version_id=version_id,
                    limit=limit,
                    offset=offset,
                ),
            )
        )
    return _run_tool(_run)


@mcp.tool()
def get_version_comment_threads(
    organization_id: _AhId,
    project_id: _AhId,
    version_id: _AhId,
    limit: int | None = 200,
    offset: int | None = 0,
) -> list[Thread]:
    """Get comment threads for a specific project version.

    Args:
        organization_id: Numeric AuditHub organization ID.
        project_id: Numeric AuditHub project ID.
        version_id: Numeric AuditHub version ID.
        limit: Maximum number of results to return (default 200).
        offset: Pagination offset (default 0).
    """
    def _run() -> list[Thread]:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        return _thread_ta.validate_python(
            _get(
                f"/organizations/{organization_id}/projects/{project_id}/versions/{version_id}/comment-threads",
                params=_build_pagination_params(limit, offset),
            )
        )
    return _run_tool(_run)


@mcp.tool()
def get_project_issues(
    organization_id: _AhId,
    project_id: _AhId,
    limit: int | None = 200,
    offset: int | None = 0,
) -> list[IssueForList]:
    """Get all issues for an AuditHub project.

    Args:
        organization_id: Numeric AuditHub organization ID.
        project_id: Numeric AuditHub project ID.
        limit: Maximum number of results to return (default 200).
        offset: Pagination offset (default 0).
    """
    def _run() -> list[IssueForList]:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        return _issue_list_ta.validate_python(
            _get(
                f"/organizations/{organization_id}/projects/{project_id}/issues",
                params=_build_pagination_params(limit, offset),
            )
        )
    return _run_tool(_run)


@mcp.tool()
def get_project_issue(organization_id: _AhId, project_id: _AhId, issue_id: _AhId) -> IssueDetails:
    """Get a specific issue from an AuditHub project.

    Args:
        organization_id: Numeric AuditHub organization ID.
        project_id: Numeric AuditHub project ID.
        issue_id: Numeric AuditHub issue ID.
    """
    def _run() -> IssueDetails:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        return IssueDetails.model_validate(
            _get(f"/organizations/{organization_id}/projects/{project_id}/issues/{issue_id}")
        )
    return _run_tool(_run)


@mcp.tool()
def get_project_comments(
    organization_id: _AhId,
    project_id: _AhId,
    limit: int | None = 200,
    offset: int | None = 0,
) -> list[Comment]:
    """Get all comments for an AuditHub project across all versions.

    Args:
        organization_id: Numeric AuditHub organization ID.
        project_id: Numeric AuditHub project ID.
        limit: Maximum number of results to return (default 200).
        offset: Pagination offset (default 0).
    """
    def _run() -> list[Comment]:
        _assert_org_allowed(organization_id)
        _assert_project_allowed(project_id)
        return _comment_ta.validate_python(
            _get(
                f"/organizations/{organization_id}/projects/{project_id}/comments",
                params=_build_pagination_params(limit, offset),
            )
        )
    return _run_tool(_run)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the ``ah-mcp`` console script.

    Parses allowlist flags, reads and validates credentials from the
    environment, then starts the MCP event loop.  All configuration is
    validated up-front; missing or invalid settings cause an immediate exit
    with a clear error message rather than failing silently on the first tool
    call.

    Allowlists may be supplied as CLI flags or environment variables; the CLI
    flag takes precedence when both are present::

        ah-mcp --allowed-org-ids 1,2 --allowed-project-ids 10,20
        AH_ALLOWED_ORG_IDS=1,2 AH_ALLOWED_PROJECT_IDS=10,20 ah-mcp
    """
    parser = argparse.ArgumentParser(
        description="AuditHub read-only MCP server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--allowed-org-ids",
        metavar="IDS",
        help=(
            "Comma-separated organization IDs the server may access"
            " (overrides AH_ALLOWED_ORG_IDS)."
        ),
    )
    parser.add_argument(
        "--allowed-project-ids",
        metavar="IDS",
        help=(
            "Comma-separated project IDs the server may access"
            " (overrides AH_ALLOWED_PROJECT_IDS)."
        ),
    )
    # parse_known_args so any args intended for the MCP runtime are left alone.
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
