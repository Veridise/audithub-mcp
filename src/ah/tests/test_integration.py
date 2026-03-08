"""Integration tests for ah_mcp.server against the live AuditHub API.

These tests require real credentials and are skipped automatically when
``AUDITHUB_BASE_URL`` is not set (e.g. in CI without secrets configured).

Run standalone to avoid conflicts with the stub injection in test_server.py::

    pytest tests/test_integration.py -v

Or with the integration marker::

    pytest -m integration tests/test_integration.py

Credentials are loaded from ``src/ah/.env`` (via python-dotenv) or from
the process environment.  The tests operate against org 84 / project 275 on
app.audithub.dev.

OpenAPI spec validation
-----------------------
``test_openapi_schema_matches_models`` fetches the live ``/openapi.json`` spec
and checks that every field declared in our Pydantic models is present in the
corresponding schema component.  This catches model drift early, before a
mismatched field causes a silent ``None`` or a runtime validation error.
"""

from __future__ import annotations

import os

import pytest

# Skip the entire module when credentials are not available.
# This must run before any import that requires the real audithub_client library.
if not os.environ.get("AUDITHUB_BASE_URL"):
    # Try loading .env first (developer workstation usage)
    try:
        from dotenv import load_dotenv

        load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))
    except ImportError:
        pass

if not os.environ.get("AUDITHUB_BASE_URL"):
    pytest.skip("AUDITHUB_BASE_URL not set — skipping integration tests", allow_module_level=True)

try:
    import audithub_client as _ac  # noqa: F401
except ImportError:
    pytest.skip(
        "audithub_client not installed — skipping integration tests", allow_module_level=True
    )

# ---------------------------------------------------------------------------
# Real imports (only reached when credentials and library are available)
# ---------------------------------------------------------------------------

import httpx  # noqa: E402

import ah_mcp.server as server  # noqa: E402
from ah_mcp.models import (  # noqa: E402
    Comment,
    IssueDetails,
    IssueForList,
    Organization,
    Project,
    Task,
    Thread,
    Version,
)

pytestmark = pytest.mark.integration

_ORG_ID = 84
_PROJECT_ID = 275


def setup_module() -> None:
    """Configure server state for integration tests."""
    server._context = server._build_context()
    server._allowed_org_ids = frozenset({_ORG_ID})
    server._allowed_project_ids = frozenset({_PROJECT_ID})


def teardown_module() -> None:
    server._context = None
    server._allowed_org_ids = frozenset()
    server._allowed_project_ids = frozenset()


# ---------------------------------------------------------------------------
# API smoke tests
# ---------------------------------------------------------------------------


def test_list_organizations() -> None:
    orgs = server.get_my_organizations()
    assert isinstance(orgs, list)
    ids = [o.id for o in orgs]
    assert _ORG_ID in ids, f"Expected org {_ORG_ID} in response, got {ids}"
    for o in orgs:
        assert isinstance(o, Organization)


def test_get_project() -> None:
    project = server.get_project(organization_id=_ORG_ID, project_id=_PROJECT_ID)
    assert isinstance(project, Project)
    assert project.id == _PROJECT_ID


def test_get_latest_version() -> None:
    version = server.get_latest_version(organization_id=_ORG_ID, project_id=_PROJECT_ID)
    assert isinstance(version, Version)
    assert version.id > 0


def test_list_issues() -> None:
    issues = server.get_project_issues(organization_id=_ORG_ID, project_id=_PROJECT_ID, limit=10)
    assert isinstance(issues, list)
    for issue in issues:
        assert isinstance(issue, IssueForList)
        assert issue.id > 0


def test_get_issue() -> None:
    issues = server.get_project_issues(organization_id=_ORG_ID, project_id=_PROJECT_ID, limit=1)
    if not issues:
        pytest.skip("No issues found in project — cannot test get_project_issue")
    issue_id = issues[0].id
    details = server.get_project_issue(
        organization_id=_ORG_ID, project_id=_PROJECT_ID, issue_id=issue_id
    )
    assert isinstance(details, IssueDetails)
    assert details.data.id == issue_id


def test_list_comments() -> None:
    comments = server.get_project_comments(
        organization_id=_ORG_ID, project_id=_PROJECT_ID, limit=10
    )
    assert isinstance(comments, list)
    for c in comments:
        assert isinstance(c, Comment)


def test_list_threads() -> None:
    version = server.get_latest_version(organization_id=_ORG_ID, project_id=_PROJECT_ID)
    threads = server.get_version_comment_threads(
        organization_id=_ORG_ID, project_id=_PROJECT_ID, version_id=version.id, limit=10
    )
    assert isinstance(threads, list)
    for t in threads:
        assert isinstance(t, Thread)


def test_list_version_comments() -> None:
    version = server.get_latest_version(organization_id=_ORG_ID, project_id=_PROJECT_ID)
    comments = server.get_version_comments(
        organization_id=_ORG_ID, project_id=_PROJECT_ID, version_id=version.id, limit=10
    )
    assert isinstance(comments, list)
    for c in comments:
        assert isinstance(c, Comment)


def test_get_task_info_if_tasks_exist() -> None:
    """Smoke-test get_task_info if any tasks are reachable via the latest version."""
    version = server.get_latest_version(organization_id=_ORG_ID, project_id=_PROJECT_ID)
    _ = version  # we don't have a direct task list endpoint; skip if no known task
    # This test is a placeholder — expand once a known task_id is available.
    pytest.skip("No stable task_id known for this project — skipping task info test")


# ---------------------------------------------------------------------------
# OpenAPI schema drift detection
# ---------------------------------------------------------------------------


def _fetch_openapi_spec() -> dict[str, object]:
    """Fetch the live OpenAPI spec from the AuditHub API."""
    ctx = server._ctx()
    base = ctx.base_url.rstrip("/")
    # Spec is typically at the API root, one level up from /api/v1
    url = f"{base}/openapi.json"
    resp = httpx.get(url, follow_redirects=True, timeout=15)
    if resp.status_code == 404:
        # Try stripping one path segment (e.g. /api/v1 -> /api/openapi.json)
        parts = base.rsplit("/", 1)
        url = f"{parts[0]}/openapi.json"
        resp = httpx.get(url, follow_redirects=True, timeout=15)
    resp.raise_for_status()
    return resp.json()  # type: ignore[no-any-return]


def _schema_fields(spec: dict[str, object], component_name: str) -> set[str]:
    """Return the set of property names for a schema component."""
    schemas = (
        spec.get("components", {})  # type: ignore[union-attr]
        .get("schemas", {})
    )
    schema = schemas.get(component_name, {})
    return set(schema.get("properties", {}).keys())  # type: ignore[union-attr]


def test_openapi_schema_matches_models() -> None:
    """Pydantic model fields must be present in the live OpenAPI spec schemas.

    This test catches model drift: if the API renames or removes a field that
    we declare as required, it will fail here before causing a silent None or
    a runtime validation error in production.

    Strategy: for each of our key models, check that our declared fields are a
    subset of the spec's properties.  Extra fields in the spec (not in our
    model) are fine — we intentionally model only the fields we use.
    """
    try:
        spec = _fetch_openapi_spec()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Could not fetch OpenAPI spec: {exc}")

    # Map our model field names to the OpenAPI component name.
    # Component names come from the AuditHub OpenAPI spec.
    _checks: list[tuple[type, str]] = [
        (Organization, "Organization"),
        (Project, "Project"),
        (Version, "Version"),
        (Task, "Task"),
        (Comment, "Comment"),
        (Thread, "Thread"),
        (IssueForList, "IssueForList"),
    ]

    drift: list[str] = []
    for model_cls, component_name in _checks:
        spec_fields = _schema_fields(spec, component_name)
        if not spec_fields:
            # Component not found — may be renamed; flag as drift
            drift.append(f"{component_name}: not found in spec components")
            continue
        model_fields = set(model_cls.model_fields.keys())
        missing_from_spec = model_fields - spec_fields
        if missing_from_spec:
            drift.append(
                f"{component_name}: model fields not in spec: {sorted(missing_from_spec)}"
            )

    if drift:
        pytest.fail(
            "OpenAPI spec drift detected — update models.py to match the current API:\n"
            + "\n".join(f"  - {d}" for d in drift)
        )
