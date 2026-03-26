"""Tests for the SDK-backed ah_mcp server."""

from __future__ import annotations

import os
import unittest
from unittest.mock import AsyncMock, patch

from tests.sdk_stubs import install_sdk_stubs

install_sdk_stubs()

import ah_mcp.server as server  # noqa: E402
from ah_mcp.models import (  # noqa: E402
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
)

_TIMESTAMP = "2026-03-26T12:00:00Z"
_INPUT_INFO_DICT = {"input_type": "archive", "url": "https://example.com/archive.zip"}
_SOURCE_REFERENCE_DICT = {"version_id": 42, "relative_path": "contracts/Audit.sol"}
_ORG_DICT = {
    "id": 1,
    "name": "Acme",
    "gh_connected": True,
    "created_at": _TIMESTAMP,
}
_PROJECT_DICT = {
    "id": 10,
    "name": "Audit",
    "project_root": ".",
    "src_path": "contracts",
    "input_info": _INPUT_INFO_DICT,
    "created_at": _TIMESTAMP,
    "gh_repo": "acme/audit",
    "is_deployed": False,
}
_PROJECT_DICT_TWO = {
    **_PROJECT_DICT,
    "id": 20,
    "name": " Zebra ",
}
_PROJECT_DICT_THREE = {
    **_PROJECT_DICT,
    "id": 30,
    "name": "Ignored",
}
_VERSION_DICT = {
    "id": 42,
    "name": "v1.0",
    "created_at": _TIMESTAMP,
    "input_info": _INPUT_INFO_DICT,
    "project_revision_hash": "rev-42",
    "digest": "digest-42",
    "commit_hash": "abc123",
    "is_deployed": False,
}
_TASK_DICT = {
    "id": 99,
    "tool_name": "analysis",
    "tool_version": "1.0.0",
    "version_id": 42,
    "status": "Finished",
    "created_at": _TIMESTAMP,
}
_COMMENT_DICT = {
    "id": 5,
    "project_id": 10,
    "version_id": 42,
    "thread_id": 3,
    "data": "comment body",
    "created_at": _TIMESTAMP,
    "created_by": "auditor@example.com",
    "system_generated": False,
    "is_modified": False,
    "is_deleted": False,
}
_THREAD_DICT = {
    "id": 3,
    "project_id": 10,
    "version_id": 42,
    "type": "note",
    "subject": {"type": "project"},
    "title": "Review note",
    "created_at": _TIMESTAMP,
    "created_by": "auditor@example.com",
    "commenter_ids": ["auditor@example.com"],
    "resolved": False,
}
_ISSUE_LIST_DICT = {
    "id": 7,
    "created_at": _TIMESTAMP,
    "last_updated_at": _TIMESTAMP,
    "gh_issue_url": None,
    "gh_security_advisory_url": None,
    "externally_shared": False,
    "status": "open",
    "title": "Bug",
    "likelihood": 1,
    "impact": 1,
    "severity": 1,
}
_ISSUE_DETAILS_DICT = {
    "kind": "public",
    "data": {
        "id": 7,
        "gh_issue_url": None,
        "gh_security_advisory_url": None,
        "status": "open",
        "revision_id": 1,
        "description": "Issue description",
        "affected_files": [_SOURCE_REFERENCE_DICT],
        "type": [1],
        "title": "Bug",
        "likelihood": 1,
        "impact": 1,
        "severity": 1,
    },
}

_FULL_ENV: dict[str, str] = {
    "AUDITHUB_BASE_URL": "https://example.com/api/v1",
    "AUDITHUB_OIDC_CONFIGURATION_URL": "https://issuer/.well-known/openid-configuration",
    "AUDITHUB_OIDC_CLIENT_ID": "test-client-id",
    "AUDITHUB_OIDC_CLIENT_SECRET": "test-client-secret",
}


def setUpModule() -> None:
    server._context = None
    server._allowed_org_ids = frozenset()
    server._allowed_project_ids = frozenset()


def tearDownModule() -> None:
    server._context = None
    server._allowed_org_ids = frozenset()
    server._allowed_project_ids = frozenset()


class TestBuildContext(unittest.TestCase):
    def test_raises_when_vars_missing(self) -> None:
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError) as cm:
            server._build_context()
        self.assertIn("Missing required environment variables", str(cm.exception))

    def test_builds_sdk_configuration(self) -> None:
        with patch.dict(os.environ, _FULL_ENV, clear=True):
            ctx = server._build_context()
        self.assertEqual(ctx.configuration.host, _FULL_ENV["AUDITHUB_BASE_URL"])
        self.assertEqual(
            ctx.auth_context.oidc_configuration_url, _FULL_ENV["AUDITHUB_OIDC_CONFIGURATION_URL"]
        )

    def test_secret_not_in_error_message(self) -> None:
        env = {"AUDITHUB_OIDC_CLIENT_SECRET": "SUPER_SECRET_VALUE"}
        with patch.dict(os.environ, env, clear=True), self.assertRaises(RuntimeError) as cm:
            server._build_context()
        self.assertNotIn("SUPER_SECRET_VALUE", str(cm.exception))


class TestCtxCache(unittest.TestCase):
    def test_ctx_raises_before_init(self) -> None:
        server._context = None
        with self.assertRaises(RuntimeError):
            server._ctx()

    def test_main_initialises_context_and_allowlists(self) -> None:
        allow_env = {
            "AH_ALLOWED_ORG_IDS": "1,2",
            "AH_ALLOWED_PROJECT_IDS": "10,20",
            **_FULL_ENV,
        }
        server._context = None
        with patch.dict(os.environ, allow_env, clear=True), patch.object(server.mcp, "run"):
            server.main()
        self.assertIsNotNone(server._context)
        self.assertEqual(server._allowed_org_ids, frozenset({1, 2}))
        self.assertEqual(server._allowed_project_ids, frozenset({10, 20}))


class TestRunTool(unittest.IsolatedAsyncioTestCase):
    async def test_returns_value(self) -> None:
        self.assertEqual(await server._run_tool(lambda: {"ok": True}), {"ok": True})

    async def test_propagates_runtime_error(self) -> None:
        original = RuntimeError("allowlist rejection")

        def _raise() -> None:
            raise original

        with self.assertRaises(RuntimeError) as cm:
            await server._run_tool(_raise)
        self.assertIs(cm.exception, original)
        self.assertIsNone(cm.exception.__context__)

    async def test_sanitizes_non_runtime_error(self) -> None:
        def _raise() -> None:
            raise ValueError("secret token")

        with self.assertRaises(RuntimeError) as cm:
            await server._run_tool(_raise, tool_name="test_tool", safe_args={})
        self.assertEqual(str(cm.exception), "An internal error occurred. Details have been logged.")
        self.assertNotIn("secret token", str(cm.exception))


class TestReadOnlyToolSurface(unittest.TestCase):
    def test_all_tools_start_with_get(self) -> None:
        names = list(server.mcp._tool_manager._tools.keys())
        self.assertGreater(len(names), 0)
        for name in names:
            self.assertTrue(name.startswith("get_"))


class TestToolCalls(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._allowed_project_ids = frozenset({10})
        with patch.dict(os.environ, _FULL_ENV, clear=True):
            server._context = server._build_context()

    async def asyncTearDown(self) -> None:
        server._context = None
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()

    async def test_get_my_organizations_filters_allowlist(self) -> None:
        with patch.object(
            server.UsersApi,
            "get_organizations_users_myorganizations_get",
            AsyncMock(return_value=[_ORG_DICT, {**_ORG_DICT, "id": 99, "name": "Other"}]),
        ):
            result = await server.get_my_organizations()
        self.assertEqual([org.id for org in result], [1])
        self.assertIsInstance(result[0], Organization)

    async def test_get_organization_name_index_filters_and_sorts(self) -> None:
        with patch.object(
            server.UsersApi,
            "get_organizations_users_myorganizations_get",
            AsyncMock(
                return_value=[
                    {**_ORG_DICT, "id": 1, "name": " Zebra "},
                    {**_ORG_DICT, "id": 2, "name": "alpha"},
                    {**_ORG_DICT, "id": 99, "name": "Other"},
                ]
            ),
        ):
            server._allowed_org_ids = frozenset({1, 2})
            result = await server.get_organization_name_index()
        self.assertEqual([item.id for item in result], [2, 1])
        self.assertEqual([item.lookup_key for item in result], ["alpha", "zebra"])
        self.assertTrue(all(isinstance(item, OrganizationNameIndexEntry) for item in result))

    async def test_get_project_returns_project(self) -> None:
        with patch.object(
            server.ProjectsApi,
            "get_project_organizations_organization_id_projects_project_id_get",
            AsyncMock(return_value=_PROJECT_DICT),
        ):
            result = await server.get_project(organization_id=1, project_id=10)
        self.assertIsInstance(result, Project)
        self.assertEqual(result.id, 10)

    async def test_get_project_name_index_filters_and_sorts(self) -> None:
        with patch.object(
            server.ProjectsApi,
            "get_projects_organizations_organization_id_projects_get",
            AsyncMock(return_value=[_PROJECT_DICT_TWO, _PROJECT_DICT, _PROJECT_DICT_THREE]),
        ):
            server._allowed_project_ids = frozenset({10, 20})
            result = await server.get_project_name_index(organization_id=1)
        self.assertEqual([item.id for item in result], [10, 20])
        self.assertEqual([item.lookup_key for item in result], ["audit", "zebra"])
        self.assertTrue(all(isinstance(item, ProjectNameIndexEntry) for item in result))

    async def test_get_latest_version_returns_version(self) -> None:
        with patch.object(
            server.VersionsApi,
            "get_latest_version_organizations_organization_id_projects_project_id_versions_latest_get",  # noqa: E501
            AsyncMock(return_value=_VERSION_DICT),
        ):
            result = await server.get_latest_version(organization_id=1, project_id=10)
        self.assertIsInstance(result, Version)

    async def test_get_task_info_returns_task(self) -> None:
        with patch.object(
            server.TasksApi,
            "get_info_organizations_organization_id_tasks_task_id_get",
            AsyncMock(return_value=_TASK_DICT),
        ):
            result = await server.get_task_info(organization_id=1, task_id=99)
        self.assertIsInstance(result, Task)

    async def test_get_task_logs_returns_list(self) -> None:
        with patch.object(
            server.TasksApi,
            "get_output_organizations_organization_id_tasks_task_id_step_code_output_get",
            AsyncMock(return_value=["a", "b"]),
        ):
            result = await server.get_task_logs(organization_id=1, task_id=99, step_code="analysis")
        self.assertEqual(result, ["a", "b"])

    async def test_get_version_comments_forwards_limit_offset(self) -> None:
        mock = AsyncMock(return_value=[_COMMENT_DICT])
        with patch.object(
            server.VersionsApi,
            "get_version_comments_organizations_organization_id_projects_project_id_versions_version_id_comments_get",  # noqa: E501
            mock,
        ):
            result = await server.get_version_comments(
                organization_id=1, project_id=10, version_id=3, limit=75, offset=25
            )
        kwargs = mock.await_args.kwargs
        self.assertEqual(kwargs["limit"], 75)
        self.assertEqual(kwargs["offset"], 25)
        self.assertIsInstance(result[0], Comment)

    async def test_get_version_comment_threads_slices_client_side(self) -> None:
        mock = AsyncMock(
            return_value=[
                {**_THREAD_DICT, "id": 1},
                {**_THREAD_DICT, "id": 2},
                {**_THREAD_DICT, "id": 3},
            ]
        )
        with patch.object(
            server.VersionsApi,
            "get_version_comment_threads_organizations_organization_id_projects_project_id_versions_version_id_comment_threads_get",  # noqa: E501
            mock,
        ):
            result = await server.get_version_comment_threads(
                organization_id=1, project_id=10, version_id=3, limit=1, offset=1
            )
        self.assertEqual([item.id for item in result], [2])
        self.assertIsInstance(result[0], Thread)

    async def test_get_project_issues_slices_client_side(self) -> None:
        with patch.object(
            server.IssuesApi,
            "get_issues_organizations_organization_id_projects_project_id_issues_get",
            AsyncMock(
                return_value=[
                    {**_ISSUE_LIST_DICT, "id": 1},
                    {**_ISSUE_LIST_DICT, "id": 2},
                    {**_ISSUE_LIST_DICT, "id": 3},
                ]
            ),
        ):
            result = await server.get_project_issues(
                organization_id=1, project_id=10, limit=2, offset=1
            )
        self.assertEqual([item.id for item in result], [2, 3])
        self.assertIsInstance(result[0], IssueForList)

    async def test_get_project_issue_returns_issue_details(self) -> None:
        with patch.object(
            server.IssuesApi,
            "get_issue_organizations_organization_id_projects_project_id_issues_issue_id_get",
            AsyncMock(return_value=_ISSUE_DETAILS_DICT),
        ):
            result = await server.get_project_issue(organization_id=1, project_id=10, issue_id=7)
        self.assertIsInstance(result, IssueDetails)
        self.assertEqual(result.kind, "public")

    async def test_get_project_comments_returns_comment_list(self) -> None:
        with patch.object(
            server.ProjectsApi,
            "get_project_comments_organizations_organization_id_projects_project_id_comments_get",
            AsyncMock(return_value=[_COMMENT_DICT]),
        ):
            result = await server.get_project_comments(organization_id=1, project_id=10)
        self.assertIsInstance(result[0], Comment)

    async def test_allowlist_rejection_prevents_sdk_call(self) -> None:
        mock = AsyncMock(return_value=[_ISSUE_LIST_DICT])
        with patch.object(
            server.IssuesApi,
            "get_issues_organizations_organization_id_projects_project_id_issues_get",
            mock,
        ), self.assertRaises(RuntimeError):
            await server.get_project_issues(organization_id=99, project_id=10)
        mock.assert_not_awaited()

    async def test_get_project_name_index_rejection_prevents_sdk_call(self) -> None:
        mock = AsyncMock(return_value=[_PROJECT_DICT])
        with patch.object(
            server.ProjectsApi,
            "get_projects_organizations_organization_id_projects_get",
            mock,
        ), self.assertRaises(RuntimeError):
            await server.get_project_name_index(organization_id=99)
        mock.assert_not_awaited()

    async def test_non_runtime_error_is_sanitized(self) -> None:
        with patch.object(
            server.UsersApi,
            "get_organizations_users_myorganizations_get",
            AsyncMock(side_effect=OSError("network secret")),
        ), self.assertRaises(RuntimeError) as cm:
            await server.get_my_organizations()
        self.assertNotIn("network secret", str(cm.exception))

    def test_normalize_lookup_key(self) -> None:
        self.assertEqual(server._normalize_lookup_key("  AcMe DAO  "), "acme dao")


class TestFastMCPSchemaValidation(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._allowed_project_ids = frozenset({10})
        with patch.dict(os.environ, _FULL_ENV, clear=True):
            server._context = server._build_context()

    async def asyncTearDown(self) -> None:
        server._context = None
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()

    async def test_string_org_id_rejected(self) -> None:
        from mcp.shared.exceptions import McpError

        with self.assertRaises((McpError, Exception)) as cm:
            await server.mcp._tool_manager.call_tool(
                "get_project", {"organization_id": "1", "project_id": 10}
            )
        self.assertIn("validation error", str(cm.exception).lower())


if __name__ == "__main__":
    unittest.main()
