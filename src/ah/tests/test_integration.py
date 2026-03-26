"""Integration tests for ah_mcp.server against a live AuditHub deployment."""

from __future__ import annotations

import asyncio
import os

import pytest

if not os.environ.get("AUDITHUB_BASE_URL"):
    pytest.skip("AUDITHUB_BASE_URL not set — skipping integration tests", allow_module_level=True)

try:
    import audithub_sdk  # noqa: F401
    import audithub_sdk_ext  # noqa: F401
except ImportError:
    pytest.skip("audithub-sdk not installed — skipping integration tests", allow_module_level=True)

import ah_mcp.server as server  # noqa: E402
from ah_mcp.models import (  # noqa: E402
    Comment,
    IssueDetails,
    IssueForList,
    Organization,
    Project,
    Thread,
    Version,
)

pytestmark = pytest.mark.integration

_ORG_ID = int(os.environ.get("AH_TEST_ORG_ID", "84"))
_PROJECT_ID = int(os.environ.get("AH_TEST_PROJECT_ID", "275"))


def _run(coro):
    return asyncio.run(coro)


def setup_module() -> None:
    server._context = server._build_context()
    server._allowed_org_ids = frozenset({_ORG_ID})
    server._allowed_project_ids = frozenset({_PROJECT_ID})


def teardown_module() -> None:
    server._context = None
    server._allowed_org_ids = frozenset()
    server._allowed_project_ids = frozenset()


def test_list_organizations() -> None:
    orgs = _run(server.get_my_organizations())
    assert isinstance(orgs, list)
    assert all(isinstance(org, Organization) for org in orgs)


def test_get_project() -> None:
    project = _run(server.get_project(organization_id=_ORG_ID, project_id=_PROJECT_ID))
    assert isinstance(project, Project)
    assert project.id == _PROJECT_ID


def test_get_latest_version() -> None:
    version = _run(server.get_latest_version(organization_id=_ORG_ID, project_id=_PROJECT_ID))
    assert isinstance(version, Version)
    assert version.id > 0


def test_list_issues() -> None:
    issues = _run(
        server.get_project_issues(
            organization_id=_ORG_ID, project_id=_PROJECT_ID, limit=10
        )
    )
    assert isinstance(issues, list)
    assert all(isinstance(issue, IssueForList) for issue in issues)


def test_get_issue_if_present() -> None:
    issues = _run(
        server.get_project_issues(organization_id=_ORG_ID, project_id=_PROJECT_ID, limit=1)
    )
    if not issues:
        pytest.skip("No issues found in project — cannot test get_project_issue")
    details = _run(
        server.get_project_issue(
            organization_id=_ORG_ID, project_id=_PROJECT_ID, issue_id=issues[0].id
        )
    )
    assert isinstance(details, IssueDetails)


def test_list_project_comments() -> None:
    comments = _run(
        server.get_project_comments(
            organization_id=_ORG_ID, project_id=_PROJECT_ID, limit=10
        )
    )
    assert isinstance(comments, list)
    assert all(isinstance(comment, Comment) for comment in comments)


def test_list_version_threads() -> None:
    version = _run(server.get_latest_version(organization_id=_ORG_ID, project_id=_PROJECT_ID))
    threads = _run(
        server.get_version_comment_threads(
            organization_id=_ORG_ID, project_id=_PROJECT_ID, version_id=version.id, limit=10
        )
    )
    assert isinstance(threads, list)
    assert all(isinstance(thread, Thread) for thread in threads)
