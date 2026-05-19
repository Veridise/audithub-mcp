"""Tests for the SDK-backed ah_mcp server."""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from pydantic import ValidationError

from tests.sdk_stubs import install_sdk_stubs

install_sdk_stubs()

import ah_mcp.server as server  # noqa: E402
from ah_mcp.models import (  # noqa: E402
    Comment,
    FIOData,
    IssueDetails,
    IssueForList,
    MyOrganization,
    OrCaFuzzingBlacklistEntry,
    OrCaParametersInput,
    OrCaTaskInput,
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
_VERSION_DICT_TWO = {
    **_VERSION_DICT,
    "id": 43,
    "name": " Release Candidate ",
}
_VERSION_DICT_THREE = {
    **_VERSION_DICT,
    "id": 44,
    "name": "alpha",
}
_VERSION_CREATION_DICT = {"id": 45, "message": "Version created"}
_TASK_DICT = {
    "id": 99,
    "tool_name": "analysis",
    "tool_version": "1.0.0",
    "version_id": 42,
    "status": "Finished",
    "created_at": _TIMESTAMP,
}
_ARTIFACT_DICT = {
    "id": "artifact-1",
    "name": "reports/result.json",
    "step_code": "analysis",
    "mime_type": "application/json",
    "is_fio": False,
    "presigned_url": "https://example.com/private?token=SECRET",
}
_TASK_WITH_ARTIFACTS_DICT = {
    **_TASK_DICT,
    "artifacts": [_ARTIFACT_DICT],
}
_TASK_CREATION_DICT = {
    "task_id": 123,
    "message": "Task created",
}
_FINDING_DICT = {
    "state_digest": 123,
    "analysis_result_id": "analysis-1",
    "is_filtered": False,
    "data": {"title": "Unchecked call return value"},
    "actions": [],
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
    server._set_task_runs_enabled(False)


def tearDownModule() -> None:
    server._context = None
    server._allowed_org_ids = frozenset()
    server._allowed_project_ids = frozenset()
    server._set_task_runs_enabled(False)


def _orca_task_input() -> OrCaTaskInput:
    return OrCaTaskInput(
        name="or-ca-test",
        specs_override=[OrCaVersionSpecReference(relative_path="specs/invariant.spec")],
        parameters=OrCaParametersInput(
            fuzz_pure=True,
            fuzz_targets=["Vault.deposit"],
            fuzzing_blacklist=[
                OrCaFuzzingBlacklistEntry(contract="Vault", function="emergencyWithdraw")
            ],
            timeout=30,
        ),
    )


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

    def test_orca_task_input_enables_on_chain_when_deployment_info_is_provided(self) -> None:
        task_input = OrCaTaskInput(
            specs_override=[OrCaVersionSpecReference(relative_path="specs/invariant.spec")],
            deployment_info_file="orca/onchain.deployment.json",
        )
        self.assertTrue(task_input.on_chain)

    def test_orca_task_input_requires_deployment_info_for_on_chain(self) -> None:
        with self.assertRaises(ValidationError) as cm:
            OrCaTaskInput(
                specs_override=[OrCaVersionSpecReference(relative_path="specs/invariant.spec")],
                on_chain=True,
            )
        self.assertIn("deployment_info_file", str(cm.exception))

    def test_orca_task_input_rejects_non_deployment_json_files(self) -> None:
        with self.assertRaises(ValidationError) as cm:
            OrCaTaskInput(
                specs_override=[OrCaVersionSpecReference(relative_path="specs/invariant.spec")],
                deployment_info_file="orca/onchain.json",
            )
        self.assertIn(".deployment.json", str(cm.exception))

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
        self.assertFalse(server._task_runs_enabled)
        self.assertFalse(server._version_creation_enabled)
        self.assertFalse(server._is_tool_registered("run_orca_task"))
        self.assertFalse(server._is_tool_registered("create_version_from_archive"))
        self.assertFalse(server._is_tool_registered("create_version_from_url"))

    def test_main_enables_task_runs_from_env(self) -> None:
        allow_env = {
            "AH_ALLOWED_ORG_IDS": "1",
            "AH_ALLOWED_PROJECT_IDS": "10",
            "AH_ENABLE_TASK_RUNS": "1",
            **_FULL_ENV,
        }
        server._context = None
        try:
            with patch.dict(os.environ, allow_env, clear=True), patch.object(server.mcp, "run"):
                server.main()
            self.assertTrue(server._task_runs_enabled)
            self.assertTrue(server._is_tool_registered("run_orca_task"))
        finally:
            server._set_task_runs_enabled(False)

    def test_main_enables_version_creation_from_env(self) -> None:
        allow_env = {
            "AH_ALLOWED_ORG_IDS": "1",
            "AH_ALLOWED_PROJECT_IDS": "10",
            "AH_ENABLE_VERSION_CREATION": "1",
            **_FULL_ENV,
        }
        server._context = None
        try:
            with patch.dict(os.environ, allow_env, clear=True), patch.object(server.mcp, "run"):
                server.main()
            self.assertTrue(server._version_creation_enabled)
            self.assertTrue(server._is_tool_registered("create_version_from_archive"))
            self.assertTrue(server._is_tool_registered("create_version_from_url"))
        finally:
            server._set_version_creation_enabled(False)

    def test_main_enables_task_runs_from_cli_flag(self) -> None:
        allow_env = {
            "AH_ALLOWED_ORG_IDS": "1",
            "AH_ALLOWED_PROJECT_IDS": "10",
            **_FULL_ENV,
        }
        server._context = None
        argv = ["ah-mcp", "--enable-task-runs"]
        try:
            with (
                patch.dict(os.environ, allow_env, clear=True),
                patch.object(sys, "argv", argv),
                patch.object(server.mcp, "run"),
            ):
                server.main()
            self.assertTrue(server._task_runs_enabled)
            self.assertTrue(server._is_tool_registered("run_orca_task"))
        finally:
            server._set_task_runs_enabled(False)

    def test_main_enables_version_creation_from_cli_flag(self) -> None:
        allow_env = {
            "AH_ALLOWED_ORG_IDS": "1",
            "AH_ALLOWED_PROJECT_IDS": "10",
            **_FULL_ENV,
        }
        server._context = None
        argv = ["ah-mcp", "--enable-version-creation"]
        try:
            with (
                patch.dict(os.environ, allow_env, clear=True),
                patch.object(sys, "argv", argv),
                patch.object(server.mcp, "run"),
            ):
                server.main()
            self.assertTrue(server._version_creation_enabled)
            self.assertTrue(server._is_tool_registered("create_version_from_archive"))
            self.assertTrue(server._is_tool_registered("create_version_from_url"))
        finally:
            server._set_version_creation_enabled(False)


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
    def tearDown(self) -> None:
        server._set_task_runs_enabled(False)
        server._set_version_creation_enabled(False)

    def test_default_tools_start_with_get(self) -> None:
        server._set_task_runs_enabled(False)
        server._set_version_creation_enabled(False)
        names = list(server.mcp._tool_manager._tools.keys())
        self.assertGreater(len(names), 0)
        self.assertNotIn("run_orca_task", names)
        self.assertNotIn("create_version_from_archive", names)
        self.assertNotIn("create_version_from_url", names)
        for name in names:
            self.assertTrue(name.startswith("get_"))

    def test_run_orca_task_registers_only_when_enabled(self) -> None:
        server._set_task_runs_enabled(True)
        names = list(server.mcp._tool_manager._tools.keys())
        self.assertIn("run_orca_task", names)

    def test_create_version_from_archive_registers_only_when_enabled(self) -> None:
        server._set_version_creation_enabled(True)
        names = list(server.mcp._tool_manager._tools.keys())
        self.assertIn("create_version_from_archive", names)

    def test_create_version_from_url_registers_only_when_enabled(self) -> None:
        server._set_version_creation_enabled(True)
        names = list(server.mcp._tool_manager._tools.keys())
        self.assertIn("create_version_from_url", names)


class TestToolCalls(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._allowed_project_ids = frozenset({10})
        server._set_task_runs_enabled(False)
        server._set_version_creation_enabled(False)
        with patch.dict(os.environ, _FULL_ENV, clear=True):
            server._context = server._build_context()

    async def asyncTearDown(self) -> None:
        server._context = None
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()
        server._set_task_runs_enabled(False)
        server._set_version_creation_enabled(False)

    async def test_get_my_organizations_filters_allowlist(self) -> None:
        with patch.object(
            server.UsersApi,
            "get_organizations_users_myorganizations_get",
            AsyncMock(return_value=[_ORG_DICT, {**_ORG_DICT, "id": 99, "name": "Other"}]),
        ):
            result = await server.get_my_organizations()
        self.assertEqual([org.id for org in result], [1])
        self.assertIsInstance(result[0], MyOrganization)

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
        mock = AsyncMock(side_effect=[_PROJECT_DICT_TWO, _PROJECT_DICT])
        with patch.object(
            server.ProjectsApi,
            "get_project_organizations_organization_id_projects_project_id_get",
            mock,
        ):
            server._allowed_project_ids = frozenset({10, 20})
            result = await server.get_project_name_index(organization_id=1)
        self.assertEqual([item.id for item in result], [10, 20])
        self.assertEqual([item.lookup_key for item in result], ["audit", "zebra"])
        self.assertTrue(all(isinstance(item, ProjectNameIndexEntry) for item in result))
        self.assertEqual(
            [call.kwargs for call in mock.await_args_list],
            [
                {"organization_id": 1, "project_id": 10},
                {"organization_id": 1, "project_id": 20},
            ],
        )

    async def test_get_project_name_index_skips_404_projects(self) -> None:
        class _NotFoundError(Exception):
            status = 404

        mock = AsyncMock(side_effect=[_PROJECT_DICT, _NotFoundError()])
        with patch.object(
            server.ProjectsApi,
            "get_project_organizations_organization_id_projects_project_id_get",
            mock,
        ):
            server._allowed_project_ids = frozenset({10, 20})
            result = await server.get_project_name_index(organization_id=1)
        self.assertEqual([item.id for item in result], [10])

    async def test_get_latest_version_returns_version(self) -> None:
        with patch.object(
            server.VersionsApi,
            "get_latest_version_organizations_organization_id_projects_project_id_versions_latest_get",  # noqa: E501
            AsyncMock(return_value=_VERSION_DICT),
        ):
            result = await server.get_latest_version(organization_id=1, project_id=10)
        self.assertIsInstance(result, Version)

    async def test_get_version_name_index_filters_and_sorts(self) -> None:
        with patch.object(
            server.VersionsApi,
            "get_versions_organizations_organization_id_projects_project_id_versions_get",
            AsyncMock(return_value=[_VERSION_DICT_TWO, _VERSION_DICT, _VERSION_DICT_THREE]),
        ):
            result = await server.get_version_name_index(organization_id=1, project_id=10)
        self.assertEqual([item.id for item in result], [44, 43, 42])
        self.assertEqual(
            [item.lookup_key for item in result],
            ["alpha", "release candidate", "v1.0"],
        )
        self.assertTrue(all(isinstance(item, VersionNameIndexEntry) for item in result))

    async def test_get_task_info_returns_task(self) -> None:
        with patch.object(
            server.TasksApi,
            "get_info_organizations_organization_id_tasks_task_id_get",
            AsyncMock(return_value=_TASK_DICT),
        ):
            result = await server.get_task_info(organization_id=1, task_id=99)
        self.assertIsInstance(result, Task)

    async def test_get_task_info_sanitizes_artifact_presigned_urls(self) -> None:
        with patch.object(
            server.TasksApi,
            "get_info_organizations_organization_id_tasks_task_id_get",
            AsyncMock(return_value=_TASK_WITH_ARTIFACTS_DICT),
        ):
            result = await server.get_task_info(organization_id=1, task_id=99)
        self.assertIsNotNone(result.artifacts)
        assert result.artifacts is not None
        self.assertIsNone(result.artifacts[0].presigned_url)

    async def test_get_task_artifacts_returns_sanitized_metadata(self) -> None:
        with patch.object(
            server.TasksApi,
            "get_info_organizations_organization_id_tasks_task_id_get",
            AsyncMock(return_value=_TASK_WITH_ARTIFACTS_DICT),
        ):
            result = await server.get_task_artifacts(organization_id=1, task_id=99)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], TaskArtifact)
        self.assertEqual(result[0].id, "artifact-1")
        self.assertFalse(hasattr(result[0], "presigned_url"))

    async def test_get_task_artifact_returns_base64_content(self) -> None:
        response = SimpleNamespace(
            raw_data=b'{"ok": true}',
            headers={"content-type": "application/json"},
        )
        with patch.object(
            server.TasksApi,
            "get_artifact_organizations_organization_id_tasks_task_id_artifacts_artifact_id_get_with_http_info",  # noqa: E501
            AsyncMock(return_value=response),
        ) as mock_get:
            result = await server.get_task_artifact(
                organization_id=1,
                task_id=99,
                artifact_id="artifact-1",
            )
        self.assertIsInstance(result, TaskArtifactContent)
        self.assertEqual(result.artifact_id, "artifact-1")
        self.assertEqual(result.content_type, "application/json")
        self.assertEqual(result.content_length, 12)
        self.assertEqual(result.content_base64, "eyJvayI6IHRydWV9")
        self.assertEqual(result.content_encoding, "base64")
        self.assertEqual(mock_get.await_args.kwargs["artifact_id"], "artifact-1")

    async def test_get_task_artifact_rejects_oversized_content(self) -> None:
        response = SimpleNamespace(raw_data=b"abcd", headers={})
        with patch.object(
            server.TasksApi,
            "get_artifact_organizations_organization_id_tasks_task_id_artifacts_artifact_id_get_with_http_info",  # noqa: E501
            AsyncMock(return_value=response),
        ), self.assertRaises(RuntimeError) as cm:
            await server.get_task_artifact(
                organization_id=1,
                task_id=99,
                artifact_id="artifact-1",
                max_bytes=3,
            )
        self.assertIn("exceeding max_bytes=3", str(cm.exception))

    async def test_get_task_logs_returns_list(self) -> None:
        with patch.object(
            server.TasksApi,
            "get_output_organizations_organization_id_tasks_task_id_step_code_output_get",
            AsyncMock(return_value=["a", "b"]),
        ):
            result = await server.get_task_logs(organization_id=1, task_id=99, step_code="analysis")
        self.assertEqual(result, ["a", "b"])

    async def test_get_task_findings_returns_list(self) -> None:
        with patch.object(
            server.TasksApi,
            "get_task_findings_organizations_organization_id_tasks_task_id_findings_get",
            AsyncMock(return_value=[_FINDING_DICT]),
        ):
            result = await server.get_task_findings(organization_id=1, task_id=99)
        self.assertEqual(result[0].analysis_result_id, "analysis-1")
        self.assertIsInstance(result[0], FIOData)

    async def test_run_orca_task_disabled_prevents_sdk_call(self) -> None:
        mock = AsyncMock(return_value=_TASK_CREATION_DICT)
        with patch.object(
            server.ToolsApi,
            "post_tool_orca_organizations_organization_id_projects_project_id_versions_version_id_tools_orca_post",  # noqa: E501
            mock,
        ), self.assertRaises(RuntimeError) as cm:
            await server.run_orca_task(
                organization_id=1,
                project_id=10,
                version_id=42,
                task_input=_orca_task_input(),
            )
        self.assertIn("task runs are disabled", str(cm.exception))
        mock.assert_not_awaited()

    async def test_run_orca_task_returns_task_creation(self) -> None:
        server._set_task_runs_enabled(True)
        mock = AsyncMock(return_value=_TASK_CREATION_DICT)
        with patch.object(
            server.ToolsApi,
            "post_tool_orca_organizations_organization_id_projects_project_id_versions_version_id_tools_orca_post",  # noqa: E501
            mock,
        ):
            result = await server.run_orca_task(
                organization_id=1,
                project_id=10,
                version_id=42,
                task_input=_orca_task_input(),
            )
        self.assertIsInstance(result, TaskCreation)
        self.assertEqual(result.task_id, 123)
        kwargs = mock.await_args.kwargs
        self.assertEqual(kwargs["organization_id"], 1)
        self.assertEqual(kwargs["project_id"], 10)
        self.assertEqual(kwargs["version_id"], 42)
        sdk_input = kwargs["or_ca_input"]
        self.assertEqual(sdk_input.name, "or-ca-test")
        self.assertEqual(sdk_input.parameters.timeout, 30)
        spec = sdk_input.specs_override[0].actual_instance
        self.assertEqual(spec.relative_path, "specs/invariant.spec")

    async def test_create_version_from_url_disabled_prevents_sdk_call(self) -> None:
        mock = AsyncMock(return_value=_VERSION_CREATION_DICT)
        with patch.object(
            server.VersionsApi,
            "post_version_with_url_organizations_organization_id_projects_project_id_versions_url_post",  # noqa: E501
            mock,
        ), self.assertRaises(RuntimeError) as cm:
            await server.create_version_from_url(
                organization_id=1,
                project_id=10,
                version_input=VersionFromUrlInput(
                    name="v2.0",
                    input_type="git",
                    url="https://github.com/acme/audit",
                    revision="main",
                ),
            )
        self.assertIn("version creation is disabled", str(cm.exception))
        mock.assert_not_awaited()

    async def test_create_version_from_archive_disabled_prevents_sdk_call(self) -> None:
        mock = AsyncMock(return_value=_VERSION_CREATION_DICT)
        with patch.object(
            server,
            "_create_version_from_archive_with_client",
            mock,
        ), self.assertRaises(RuntimeError) as cm:
            await server.create_version_from_archive(
                organization_id=1,
                project_id=10,
                version_input=VersionFromArchiveInput(
                    name="v2.0",
                    archive="ARCHIVE_CONTENTS",
                    commit_hash="def456",
                ),
            )
        self.assertIn("version creation is disabled", str(cm.exception))
        mock.assert_not_awaited()

    async def test_create_version_from_archive_uses_multipart_upload(self) -> None:
        server._set_version_creation_enabled(True)

        class _FakeResponse:
            status = 200
            headers: dict[str, str] = {}
            data = b'{"id":45,"message":"Version created"}'

            async def read(self) -> None:
                return None

        class _FakeClient:
            def __init__(self) -> None:
                self.param_serialize_kwargs: dict[str, object] | None = None
                self.call_api_args: tuple[object, ...] | None = None
                self.response_deserialize_args: tuple[object, ...] | None = None

            class _FakeVersionResponse:
                def model_dump(self) -> dict[str, object]:
                    return _VERSION_CREATION_DICT

            def param_serialize(self, **kwargs: object) -> tuple[object, ...]:
                self.param_serialize_kwargs = kwargs
                return ("POST", "https://example.invalid", {}, None, [])

            async def call_api(self, *args: object) -> _FakeResponse:
                self.call_api_args = args
                return _FakeResponse()

            def response_deserialize(
                self,
                response_data: _FakeResponse,
                response_types_map: dict[str, str],
            ) -> SimpleNamespace:
                self.response_deserialize_args = (response_data, response_types_map)
                return SimpleNamespace(data=self._FakeVersionResponse())

        client = _FakeClient()
        result = await server._create_version_from_archive_with_client(
            client,
            organization_id=1,
            project_id=10,
            version_input=VersionFromArchiveInput(
                name="v2.0",
                archive="/tmp/archive.zip",
                commit_hash="def456",
                is_deployed=True,
            ),
        )
        self.assertIsInstance(result, VersionCreation)
        self.assertEqual(result.id, 45)
        self.assertIsNotNone(client.param_serialize_kwargs)
        self.assertEqual(
            client.param_serialize_kwargs["header_params"],
            {
                "Accept": "application/json",
                "Content-Type": "multipart/form-data",
            },
        )
        self.assertEqual(
            client.param_serialize_kwargs["files"],
            {"archive": "/tmp/archive.zip"},
        )
        self.assertEqual(
            client.param_serialize_kwargs["post_params"],
            [
                ("name", "v2.0"),
                ("commit_hash", "def456"),
                ("is_deployed", True),
            ],
        )
        self.assertIsNotNone(client.call_api_args)
        self.assertIsNotNone(client.response_deserialize_args)

    async def test_create_version_from_url_returns_version_creation(self) -> None:
        server._set_version_creation_enabled(True)
        mock = AsyncMock(return_value=_VERSION_CREATION_DICT)
        with patch.object(
            server.VersionsApi,
            "post_version_with_url_organizations_organization_id_projects_project_id_versions_url_post",  # noqa: E501
            mock,
        ):
            result = await server.create_version_from_url(
                organization_id=1,
                project_id=10,
                version_input=VersionFromUrlInput(
                    name="v2.0",
                    input_type="git",
                    url="https://github.com/acme/audit",
                    commit_hash="def456",
                    is_deployed=True,
                    revision="main",
                    includes_submodules=True,
                ),
            )
        self.assertIsInstance(result, VersionCreation)
        self.assertEqual(result.id, 45)
        kwargs = mock.await_args.kwargs
        self.assertEqual(kwargs["organization_id"], 1)
        self.assertEqual(kwargs["project_id"], 10)
        self.assertEqual(kwargs["name"], "v2.0")
        self.assertEqual(kwargs["input_type"], "git")
        self.assertEqual(kwargs["url"], "https://github.com/acme/audit")
        self.assertEqual(kwargs["commit_hash"], "def456")
        self.assertTrue(kwargs["is_deployed"])
        self.assertEqual(kwargs["revision"], "main")
        self.assertTrue(kwargs["includes_submodules"])

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

    async def test_get_thread_comments_forwards_thread_limit_offset(self) -> None:
        mock = AsyncMock(return_value=[_COMMENT_DICT])
        with patch.object(
            server.VersionsApi,
            "get_version_comments_organizations_organization_id_projects_project_id_versions_version_id_comments_get",  # noqa: E501
            mock,
        ):
            result = await server.get_thread_comments(
                organization_id=1,
                project_id=10,
                version_id=3,
                thread_id=7,
                limit=75,
                offset=25,
            )
        kwargs = mock.await_args.kwargs
        self.assertEqual(kwargs["thread_id"], 7)
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
            "get_project_organizations_organization_id_projects_project_id_get",
            mock,
        ), self.assertRaises(RuntimeError):
            await server.get_project_name_index(organization_id=99)
        mock.assert_not_awaited()

    async def test_get_version_name_index_rejection_prevents_sdk_call(self) -> None:
        mock = AsyncMock(return_value=[_VERSION_DICT])
        with patch.object(
            server.VersionsApi,
            "get_versions_organizations_organization_id_projects_project_id_versions_get",
            mock,
        ), self.assertRaises(RuntimeError):
            await server.get_version_name_index(organization_id=1, project_id=99)
        mock.assert_not_awaited()

    async def test_get_thread_comments_rejection_prevents_sdk_call(self) -> None:
        mock = AsyncMock(return_value=[_COMMENT_DICT])
        with patch.object(
            server.VersionsApi,
            "get_version_comments_organizations_organization_id_projects_project_id_versions_version_id_comments_get",  # noqa: E501
            mock,
        ), self.assertRaises(RuntimeError):
            await server.get_thread_comments(
                organization_id=99, project_id=10, version_id=3, thread_id=7
            )
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

    async def test_string_thread_id_rejected(self) -> None:
        from mcp.shared.exceptions import McpError

        with self.assertRaises((McpError, Exception)) as cm:
            await server.mcp._tool_manager.call_tool(
                "get_thread_comments",
                {
                    "organization_id": 1,
                    "project_id": 10,
                    "version_id": 42,
                    "thread_id": "3",
                },
            )
        self.assertIn("validation error", str(cm.exception).lower())


if __name__ == "__main__":
    unittest.main()
