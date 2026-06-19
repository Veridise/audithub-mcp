"""Integration tests for audithub_mcp.server against a live AuditHub deployment."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

import pytest

from audithub_mcp.config import _load_raw_config_from_path


def _bootstrap_from_config_file() -> None:
    config_file = os.environ.get("AH_MCP_CONFIG_FILE")
    if config_file:
        raw = _load_raw_config_from_path(Path(config_file))
        for key in (
            "audithub_base_url",
            "audithub_oidc_configuration_url",
            "audithub_oidc_client_id",
            "audithub_oidc_client_secret",
        ):
            value = raw.get(key)
            if value is None:
                continue
            env_key = key.upper()
            os.environ[env_key] = str(value)


_bootstrap_from_config_file()

if not os.environ.get("AUDITHUB_BASE_URL"):
    pytest.skip("AUDITHUB_BASE_URL not set — skipping integration tests", allow_module_level=True)

try:
    import audithub_sdk  # noqa: F401
    import audithub_sdk_ext  # noqa: F401
except ImportError:
    pytest.skip("audithub-sdk not installed — skipping integration tests", allow_module_level=True)

import audithub_mcp.server as server  # noqa: E402
from audithub_mcp.models import (  # noqa: E402
    Comment,
    IssueDetails,
    IssueForList,
    OrganizationLookupItem,
    Project,
    ProjectLookupItem,
    Thread,
    Version,
    VersionLookupItem,
)

pytestmark = pytest.mark.integration

_ORG_ID = int(os.environ.get("AH_TEST_ORG_ID", "84"))
_PROJECT_ID = int(os.environ.get("AH_TEST_PROJECT_ID", "275"))


def _run[T](coro: Coroutine[Any, Any, T]) -> T:
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
    orgs = _run(server.get_organizations())
    assert isinstance(orgs, list)
    assert all(isinstance(org, OrganizationLookupItem) for org in orgs)
    assert all(org.details is None for org in orgs)


def test_get_projects() -> None:
    projects = _run(server.get_projects(organization_id=_ORG_ID, filter_id=_PROJECT_ID))
    assert isinstance(projects, list)
    assert all(isinstance(project, ProjectLookupItem) for project in projects)
    assert all(project.details is None for project in projects)
    assert [project.id for project in projects] == [_PROJECT_ID]


def test_get_projects_details() -> None:
    projects = _run(
        server.get_projects(organization_id=_ORG_ID, filter_id=_PROJECT_ID, details=True)
    )
    assert isinstance(projects, list)
    assert all(isinstance(project, ProjectLookupItem) for project in projects)
    assert all(isinstance(project.details, Project) for project in projects)
    assert [project.id for project in projects] == [_PROJECT_ID]


def test_get_versions() -> None:
    versions = _run(server.get_versions(organization_id=_ORG_ID, project_id=_PROJECT_ID))
    assert isinstance(versions, list)
    assert all(isinstance(version, VersionLookupItem) for version in versions)
    assert all(version.details is None for version in versions)
    assert all(isinstance(version.latest, bool) for version in versions)
    assert any(version.latest for version in versions)


def test_get_versions_details() -> None:
    versions = _run(
        server.get_versions(organization_id=_ORG_ID, project_id=_PROJECT_ID, details=True)
    )
    assert isinstance(versions, list)
    assert all(isinstance(version, VersionLookupItem) for version in versions)
    assert all(isinstance(version.details, Version) for version in versions)
    assert all(version.id > 0 for version in versions)
    assert all(isinstance(version.latest, bool) for version in versions)
    assert any(version.latest for version in versions)


def test_list_vanguard_detectors() -> None:
    detectors = _run(server.get_defi_vanguard_detectors(organization_id=_ORG_ID))
    assert any(
        'detector: ["builtin", "hiyul/unchecked-return"]' in detector for detector in detectors
    )
    assert any('detector: ["stdlib",' in detector for detector in detectors), (
        "should have at least one custom detector"
    )


def test_list_issues() -> None:
    issues = _run(
        server.get_project_issues(organization_id=_ORG_ID, project_id=_PROJECT_ID, limit=10)
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
        server.get_project_comments(organization_id=_ORG_ID, project_id=_PROJECT_ID, limit=10)
    )
    assert isinstance(comments, list)
    assert all(isinstance(comment, Comment) for comment in comments)


def test_list_version_threads() -> None:
    versions = _run(server.get_versions(organization_id=_ORG_ID, project_id=_PROJECT_ID))
    if not versions:
        pytest.skip("No versions found in project — cannot test get_version_comment_threads")
    version_id = versions[0].id
    threads = _run(
        server.get_version_comment_threads(
            organization_id=_ORG_ID, project_id=_PROJECT_ID, version_id=version_id, limit=10
        )
    )
    assert isinstance(threads, list)
    assert all(isinstance(thread, Thread) for thread in threads)


def test_get_thread_comments_if_thread_present() -> None:
    versions = _run(server.get_versions(organization_id=_ORG_ID, project_id=_PROJECT_ID))
    if not versions:
        pytest.skip("No versions found in project — cannot test get_thread_comments")
    version_id = versions[0].id
    threads = _run(
        server.get_version_comment_threads(
            organization_id=_ORG_ID, project_id=_PROJECT_ID, version_id=version_id, limit=10
        )
    )
    if not threads:
        pytest.skip("No threads found in version — cannot test get_thread_comments")

    comments = _run(
        server.get_thread_comments(
            organization_id=_ORG_ID,
            project_id=_PROJECT_ID,
            version_id=version_id,
            thread_id=threads[0].id,
            limit=10,
        )
    )
    assert isinstance(comments, list)
    assert all(isinstance(comment, Comment) for comment in comments)
    assert all(comment.thread_id == threads[0].id for comment in comments)
