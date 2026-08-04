"""Security-focused tests for the SDK-backed audithub_mcp server."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import audithub_mcp.server as server  # noqa: E402
import audithub_mcp.vanguard as vanguard  # noqa: E402
from audithub_mcp.models import (  # noqa: E402
    DefiVanguardV2TaskInput,
    OrCaAdHocHintReference,
    OrCaAdHocSpecReference,
    OrCaParametersInput,
    OrCaTaskInput,
    PaqlValidationResult,
    VersionFromFileInput,
    VersionFromUrlInput,
)


def _orca_task_input() -> OrCaTaskInput:
    return OrCaTaskInput(
        specs_override=[
            OrCaAdHocSpecReference(filename="secret.spec", contents="SECRET_SPEC_CONTENT")
        ],
        hints_override=[
            OrCaAdHocHintReference(filename="secret.hint", contents="SECRET_HINT_CONTENT")
        ],
        parameters=OrCaParametersInput(timeout=60),
    )


def _vanguard_task_input() -> DefiVanguardV2TaskInput:
    return DefiVanguardV2TaskInput(
        organization_id=1,
        project_id=10,
        version_id=42,
        detectors=[("builtin", "hiyul/unchecked-return")],
    )


class TestDisallowedIds(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._allowed_project_ids = frozenset({10})
        vanguard.reset_builtin_vanguard_v2_detectors_cache()

    async def asyncTearDown(self) -> None:
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()
        vanguard.reset_builtin_vanguard_v2_detectors_cache()
        server._set_task_runs_enabled(False)
        server._set_version_creation_enabled(False)
        server._set_edit_custom_detectors_enabled(False)

    async def test_get_project_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await server.get_projects(organization_id=999, filter_id=10)
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))

    async def test_get_projects_disallowed_project(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await server.get_projects(organization_id=1, filter_id=999)
        self.assertIn("999", str(cm.exception))

    async def test_rejected_call_does_not_reach_sdk(self) -> None:
        mock = AsyncMock(return_value={"id": 10, "name": "Audit"})
        with (
            patch.object(
                server.ProjectsApi,
                "get_projects_organizations_organization_id_projects_get",
                mock,
            ),
            self.assertRaises(RuntimeError),
        ):
            await server.get_projects(organization_id=999)
        mock.assert_not_awaited()

    async def test_task_findings_disallowed_org(self) -> None:
        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "findings.json"
            with self.assertRaises(RuntimeError) as cm:
                await server.get_task_findings(
                    organization_id=999,
                    task_id=10,
                    output_file_path=str(output_path),
                )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))

    async def test_task_findings_rejected_call_does_not_reach_sdk(self) -> None:
        mock = AsyncMock(return_value=[])
        with (
            patch.object(
                server.TasksApi,
                "get_task_findings_organizations_organization_id_tasks_task_id_findings_get",
                mock,
            ),
            self.assertRaises(RuntimeError),
            TemporaryDirectory() as tmpdir,
        ):
            output_path = Path(tmpdir) / "findings.json"
            await server.get_task_findings(
                organization_id=999,
                task_id=10,
                output_file_path=str(output_path),
            )
        mock.assert_not_awaited()

    async def test_task_logs_disallowed_org(self) -> None:
        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "logs.txt"
            with self.assertRaises(RuntimeError) as cm:
                await server.get_task_logs(
                    organization_id=999,
                    task_id=10,
                    step_codes=["analysis"],
                    output_paths=[str(output_path)],
                )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))

    async def test_task_logs_writes_to_output_file(self) -> None:
        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "logs.txt"
            mock = AsyncMock(return_value=["line 1", "line 2"])
            with patch.object(server, "_with_api_client", mock):
                result = await server.get_task_logs(
                    organization_id=1,
                    task_id=10,
                    step_codes=["analysis"],
                    output_paths=[str(output_path)],
                )
            self.assertEqual(result.num_logs, 2)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "line 1\nline 2\n")

    async def test_upload_custom_detector_disallowed_org(self) -> None:
        server._set_edit_custom_detectors_enabled(True)
        with TemporaryDirectory() as tmpdir:
            detector_path = Path(tmpdir) / "detector.luau"
            detector_path.write_text("rule body\n", encoding="utf-8")
            mock = AsyncMock(return_value=SimpleNamespace(id=77, message="created"))
            with (
                patch.object(
                    server.CustomDetectorsOrgLibApi,
                    "post_custom_detector_organizations_organization_id_custom_detectors_post",
                    mock,
                ),
                self.assertRaises(RuntimeError) as cm,
            ):
                await server.upload_custom_detector(
                    organization_id=999,
                    file_path=str(detector_path),
                    filename="detector.luau",
                )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))
        mock.assert_not_awaited()

    async def test_task_artifacts_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await server.get_task_artifacts(organization_id=999, task_id=10)
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))

    async def test_task_artifacts_rejected_call_does_not_reach_sdk(self) -> None:
        mock = AsyncMock(return_value=[])
        with (
            patch.object(
                server.TasksApi,
                "get_info_organizations_organization_id_tasks_task_id_get",
                mock,
            ),
            self.assertRaises(RuntimeError),
        ):
            await server.get_task_artifacts(organization_id=999, task_id=10)
        mock.assert_not_awaited()

    async def test_wait_for_task_completion_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await server.wait_for_task_completion(organization_id=999, task_id=10)
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))

    async def test_wait_for_task_completion_rejected_call_does_not_reach_sdk(self) -> None:
        mock = AsyncMock(return_value={"id": 10, "status": "Pending", "steps": []})
        with (
            patch.object(
                server.TasksApi,
                "get_info_organizations_organization_id_tasks_task_id_get",
                mock,
            ),
            self.assertRaises(RuntimeError),
        ):
            await server.wait_for_task_completion(organization_id=999, task_id=10)
        mock.assert_not_awaited()

    async def test_task_artifact_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await server.get_task_artifact(
                organization_id=999,
                task_id=10,
                artifact_id="artifact-1",
            )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))

    async def test_task_artifact_rejected_call_does_not_reach_sdk(self) -> None:
        mock = AsyncMock(return_value=SimpleNamespace(raw_data=b"", headers={}))
        with (
            patch.object(
                server.TasksApi,
                "get_artifact_organizations_organization_id_tasks_task_id_artifacts_artifact_id_get_with_http_info",  # noqa: E501
                mock,
            ),
            self.assertRaises(RuntimeError),
        ):
            await server.get_task_artifact(
                organization_id=999,
                task_id=10,
                artifact_id="artifact-1",
            )
        mock.assert_not_awaited()

    async def test_project_name_index_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await server.get_projects(organization_id=999)
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))

    async def test_get_projects_rejected_call_does_not_reach_sdk(self) -> None:
        mock = AsyncMock(return_value=[{"id": 10, "name": "Audit"}])
        with (
            patch.object(
                server.ProjectsApi,
                "get_projects_organizations_organization_id_projects_get",
                mock,
            ),
            self.assertRaises(RuntimeError),
        ):
            await server.get_projects(organization_id=999)
        mock.assert_not_awaited()

    async def test_versions_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await server.get_versions(organization_id=999, project_id=10)
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))

    async def test_versions_disallowed_project(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await server.get_versions(organization_id=1, project_id=999)
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))

    async def test_get_versions_rejected_call_does_not_reach_sdk(self) -> None:
        mock = AsyncMock(return_value=[{"id": 42, "name": "v1.0"}])
        with (
            patch.object(
                server.VersionsApi,
                "get_versions_organizations_organization_id_projects_project_id_versions_get",
                mock,
            ),
            self.assertRaises(RuntimeError),
        ):
            await server.get_versions(organization_id=999, project_id=10)
        mock.assert_not_awaited()

    async def test_run_orca_disallowed_org_rejected_before_sdk_call(self) -> None:
        server._set_task_runs_enabled(True)
        mock = AsyncMock(return_value={"task_id": 1, "message": "created"})
        with (
            patch.object(
                server.ToolsApi,
                "post_tool_orca_organizations_organization_id_projects_project_id_versions_version_id_tools_orca_post",  # noqa: E501
                mock,
            ),
            self.assertRaises(RuntimeError) as cm,
        ):
            await server.run_orca_task(
                organization_id=999,
                project_id=10,
                version_id=42,
                task_input=_orca_task_input(),
            )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))
        mock.assert_not_awaited()

    async def test_run_orca_disallowed_project_rejected_before_sdk_call(self) -> None:
        server._set_task_runs_enabled(True)
        mock = AsyncMock(return_value={"task_id": 1, "message": "created"})
        with (
            patch.object(
                server.ToolsApi,
                "post_tool_orca_organizations_organization_id_projects_project_id_versions_version_id_tools_orca_post",  # noqa: E501
                mock,
            ),
            self.assertRaises(RuntimeError) as cm,
        ):
            await server.run_orca_task(
                organization_id=1,
                project_id=999,
                version_id=42,
                task_input=_orca_task_input(),
            )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))
        mock.assert_not_awaited()

    async def test_defi_vanguard_detectors_disallowed_org_rejected_before_sdk_call(self) -> None:
        config_mock = AsyncMock(return_value={"vanguard_v2_defi_detectors": []})
        custom_mock = AsyncMock(return_value=[])
        stdlib_mock = AsyncMock(return_value={})
        with (
            patch.object(
                server.ConfigurationApi, "get_configuration_configuration_get", config_mock
            ),
            patch.object(
                server.CustomDetectorsOrgLibApi,
                "get_custom_detectors_organizations_organization_id_custom_detectors_get",
                custom_mock,
            ),
            patch.object(
                server.CustomDetectorsStdLibApi,
                "get_custom_detectors_library_custom_detectors_library_get",
                stdlib_mock,
            ),
            self.assertRaises(RuntimeError) as cm,
        ):
            await server.get_defi_vanguard_detectors(organization_id=999)
        self.assertIn("999", str(cm.exception))
        config_mock.assert_not_awaited()
        custom_mock.assert_not_awaited()
        stdlib_mock.assert_not_awaited()

    async def test_run_defi_vanguard_disallowed_org_rejected_before_sdk_call(self) -> None:
        server._set_task_runs_enabled(True)
        mock = AsyncMock(return_value={"task_id": 1, "message": "created"})
        with (
            patch.object(
                server.ToolsApi,
                "post_tool_vanguard_v2_organizations_organization_id_projects_project_id_versions_version_id_tools_vanguard_v2_post",
                mock,
            ),
            self.assertRaises(RuntimeError) as cm,
        ):
            task_input = _vanguard_task_input()
            await server.run_defi_vanguard_task(
                organization_id=999,
                project_id=10,
                version_id=42,
                detectors=task_input.detectors,
                name=task_input.name,
                input_limit=task_input.input_limit,
                cross_version_triage=task_input.cross_version_triage,
                solc=task_input.solc,
                ignore_build_system=task_input.ignore_build_system,
            )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))
        mock.assert_not_awaited()

    async def test_run_defi_vanguard_disallowed_project_rejected_before_sdk_call(self) -> None:
        server._set_task_runs_enabled(True)
        mock = AsyncMock(return_value={"task_id": 1, "message": "created"})
        with (
            patch.object(
                server.ToolsApi,
                "post_tool_vanguard_v2_organizations_organization_id_projects_project_id_versions_version_id_tools_vanguard_v2_post",
                mock,
            ),
            self.assertRaises(RuntimeError) as cm,
        ):
            task_input = _vanguard_task_input()
            await server.run_defi_vanguard_task(
                organization_id=1,
                project_id=999,
                version_id=42,
                detectors=task_input.detectors,
                name=task_input.name,
                input_limit=task_input.input_limit,
                cross_version_triage=task_input.cross_version_triage,
                solc=task_input.solc,
                ignore_build_system=task_input.ignore_build_system,
            )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))
        mock.assert_not_awaited()

    async def test_create_version_disallowed_org_rejected_before_sdk_call(self) -> None:
        server._set_version_creation_enabled(True)
        mock = AsyncMock(return_value={"id": 1, "message": "created"})
        with (
            patch.object(
                server.VersionsApi,
                "post_version_with_url_organizations_organization_id_projects_project_id_versions_url_post",  # noqa: E501
                mock,
            ),
            self.assertRaises(RuntimeError) as cm,
        ):
            await server.create_version_from_url(
                organization_id=999,
                project_id=10,
                version_input=VersionFromUrlInput(
                    name="v2.0",
                    input_type="git",
                    url="https://github.com/acme/audit",
                ),
            )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))
        mock.assert_not_awaited()

    async def test_create_version_archive_disallowed_org_rejected_before_sdk_call(self) -> None:
        server._set_version_creation_enabled(True)
        mock = AsyncMock(return_value={"id": 1, "message": "created"})
        with (
            patch.object(
                server,
                "_create_version_from_archive_with_client",
                mock,
            ),
            self.assertRaises(RuntimeError) as cm,
        ):
            await server.create_version_from_file(
                organization_id=999,
                project_id=10,
                version_input=VersionFromFileInput(
                    name="v2.0",
                    archive="ARCHIVE_CONTENTS",
                ),
            )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))
        mock.assert_not_awaited()

    async def test_create_version_archive_disallowed_project_rejected_before_sdk_call(self) -> None:
        server._set_version_creation_enabled(True)
        mock = AsyncMock(return_value={"id": 1, "message": "created"})
        with (
            patch.object(
                server,
                "_create_version_from_archive_with_client",
                mock,
            ),
            self.assertRaises(RuntimeError) as cm,
        ):
            await server.create_version_from_file(
                organization_id=1,
                project_id=999,
                version_input=VersionFromFileInput(
                    name="v2.0",
                    archive="ARCHIVE_CONTENTS",
                ),
            )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))
        mock.assert_not_awaited()

    async def test_create_version_disallowed_project_rejected_before_sdk_call(self) -> None:
        server._set_version_creation_enabled(True)
        mock = AsyncMock(return_value={"id": 1, "message": "created"})
        with (
            patch.object(
                server.VersionsApi,
                "post_version_with_url_organizations_organization_id_projects_project_id_versions_url_post",  # noqa: E501
                mock,
            ),
            self.assertRaises(RuntimeError) as cm,
        ):
            await server.create_version_from_url(
                organization_id=1,
                project_id=999,
                version_input=VersionFromUrlInput(
                    name="v2.0",
                    input_type="git",
                    url="https://github.com/acme/audit",
                ),
            )
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))
        mock.assert_not_awaited()


class TestPaqlPrivacy(unittest.IsolatedAsyncioTestCase):
    async def test_paql_source_not_in_audit_log(self) -> None:
        import audithub_mcp.audit as audit_mod

        source = "FIND Contract SECRET_PAQL_SOURCE"
        with (
            patch.object(
                server.paql,
                "validate_source",
                AsyncMock(return_value=PaqlValidationResult(success=True)),
            ),
            patch.object(audit_mod.logger, "info") as mock_info,
        ):
            await server.validate_paql(source)

        rendered_calls = " ".join(str(call) for call in mock_info.call_args_list)
        self.assertNotIn("SECRET_PAQL_SOURCE", rendered_calls)


class TestStepCodePrivacy(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._context = server.AuditHubSdkContext(
            configuration=server.audithub_sdk.Configuration(host="https://example.com/api/v1"),
            auth_context=server.OIDCClientCredentialsContext(
                oidc_configuration_url="https://issuer/.well-known/openid-configuration",
                client_id="client-id",
                client_secret="client-secret",
            ),
        )

    async def asyncTearDown(self) -> None:
        server._allowed_org_ids = frozenset()
        server._context = None
        server._set_task_runs_enabled(False)
        server._set_edit_custom_detectors_enabled(False)

    async def test_step_code_not_in_audit_log(self) -> None:
        import audithub_mcp.audit as audit_mod

        step_code = "../../../etc/passwd"
        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "logs.txt"
            with (
                patch.object(
                    server.TasksApi,
                    "get_output_organizations_organization_id_tasks_task_id_step_code_output_get",
                    AsyncMock(return_value=[]),
                ),
                patch.object(audit_mod.logger, "info") as mock_info,
            ):
                await server.get_task_logs(
                    organization_id=1,
                    task_id=1,
                    step_codes=[step_code],
                    output_paths=[str(output_path)],
                )
        for call in mock_info.call_args_list:
            args = " ".join(str(arg) for arg in call.args)
            self.assertNotIn(step_code, args)


class TestArtifactPrivacy(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._context = server.AuditHubSdkContext(
            configuration=server.audithub_sdk.Configuration(host="https://example.com/api/v1"),
            auth_context=server.OIDCClientCredentialsContext(
                oidc_configuration_url="https://issuer/.well-known/openid-configuration",
                client_id="client-id",
                client_secret="client-secret",
            ),
        )

    async def asyncTearDown(self) -> None:
        server._allowed_org_ids = frozenset()
        server._context = None

    async def test_artifact_id_not_in_audit_log(self) -> None:
        import audithub_mcp.audit as audit_mod

        artifact_id = "SECRET_ARTIFACT_ID"
        response = SimpleNamespace(raw_data=b"artifact", headers={"content-type": "text/plain"})
        with (
            patch.object(
                server.TasksApi,
                "get_artifact_organizations_organization_id_tasks_task_id_artifacts_artifact_id_get_with_http_info",  # noqa: E501
                AsyncMock(return_value=response),
            ),
            patch.object(audit_mod.logger, "info") as mock_info,
        ):
            await server.get_task_artifact(
                organization_id=1,
                task_id=1,
                artifact_id=artifact_id,
            )
        for call in mock_info.call_args_list:
            args = " ".join(str(arg) for arg in call.args)
            self.assertNotIn(artifact_id, args)


class TestOrCaTaskPrivacy(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._allowed_project_ids = frozenset({10})
        server._set_task_runs_enabled(True)
        server._context = server.AuditHubSdkContext(
            configuration=server.audithub_sdk.Configuration(host="https://example.com/api/v1"),
            auth_context=server.OIDCClientCredentialsContext(
                oidc_configuration_url="https://issuer/.well-known/openid-configuration",
                client_id="client-id",
                client_secret="client-secret",
            ),
        )

    async def asyncTearDown(self) -> None:
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()
        server._context = None
        server._set_task_runs_enabled(False)
        server._set_version_creation_enabled(False)
        server._set_edit_custom_detectors_enabled(False)

    async def test_orca_payload_not_in_audit_log(self) -> None:
        import audithub_mcp.audit as audit_mod

        with (
            patch.object(
                server.ToolsApi,
                "post_tool_orca_organizations_organization_id_projects_project_id_versions_version_id_tools_orca_post",  # noqa: E501
                AsyncMock(return_value={"task_id": 1, "message": "created"}),
            ),
            patch.object(audit_mod.logger, "info") as mock_info,
        ):
            await server.run_orca_task(
                organization_id=1,
                project_id=10,
                version_id=42,
                task_input=_orca_task_input(),
            )
        for call in mock_info.call_args_list:
            args = " ".join(str(arg) for arg in call.args)
            self.assertNotIn("SECRET_SPEC_CONTENT", args)
            self.assertNotIn("SECRET_HINT_CONTENT", args)

    async def test_orca_payload_not_in_error_log(self) -> None:
        import audithub_mcp.audit as audit_mod

        with (
            patch.object(
                server.ToolsApi,
                "post_tool_orca_organizations_organization_id_projects_project_id_versions_version_id_tools_orca_post",  # noqa: E501
                AsyncMock(side_effect=ValueError("SECRET_SPEC_CONTENT SECRET_HINT_CONTENT")),
            ),
            patch.object(audit_mod.logger, "error") as mock_error,
            self.assertRaises(RuntimeError),
        ):
            await server.run_orca_task(
                organization_id=1,
                project_id=10,
                version_id=42,
                task_input=_orca_task_input(),
            )
        for call in mock_error.call_args_list:
            args = " ".join(str(arg) for arg in call.args)
            self.assertNotIn("SECRET_SPEC_CONTENT", args)
            self.assertNotIn("SECRET_HINT_CONTENT", args)


class TestVersionCreationPrivacy(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._allowed_project_ids = frozenset({10})
        server._set_version_creation_enabled(True)
        server._context = server.AuditHubSdkContext(
            configuration=server.audithub_sdk.Configuration(host="https://example.com/api/v1"),
            auth_context=server.OIDCClientCredentialsContext(
                oidc_configuration_url="https://issuer/.well-known/openid-configuration",
                client_id="client-id",
                client_secret="client-secret",
            ),
        )

    async def asyncTearDown(self) -> None:
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()
        server._context = None
        server._set_version_creation_enabled(False)
        server._set_edit_custom_detectors_enabled(False)

    async def test_version_url_not_in_audit_log(self) -> None:
        import audithub_mcp.audit as audit_mod

        url = "https://example.com/private/archive.zip?token=SECRET_URL_TOKEN"
        with (
            patch.object(
                server.VersionsApi,
                "post_version_with_url_organizations_organization_id_projects_project_id_versions_url_post",  # noqa: E501
                AsyncMock(return_value={"id": 1, "message": "created"}),
            ),
            patch.object(audit_mod.logger, "info") as mock_info,
        ):
            await server.create_version_from_url(
                organization_id=1,
                project_id=10,
                version_input=VersionFromUrlInput(
                    name="secret-version",
                    input_type="archive",
                    url=url,
                ),
            )
        for call in mock_info.call_args_list:
            args = " ".join(str(arg) for arg in call.args)
            self.assertNotIn(url, args)
            self.assertNotIn("SECRET_URL_TOKEN", args)

    async def test_version_archive_not_in_audit_log(self) -> None:
        import audithub_mcp.audit as audit_mod

        archive = "SECRET_ARCHIVE_CONTENTS"
        with (
            patch.object(
                server,
                "_create_version_from_archive_with_client",
                AsyncMock(return_value={"id": 1, "message": "created"}),
            ),
            patch.object(audit_mod.logger, "info") as mock_info,
        ):
            await server.create_version_from_file(
                organization_id=1,
                project_id=10,
                version_input=VersionFromFileInput(
                    name="secret-version",
                    archive=archive,
                ),
            )
        for call in mock_info.call_args_list:
            args = " ".join(str(arg) for arg in call.args)
            self.assertNotIn(archive, args)


class TestErrorSanitization(unittest.IsolatedAsyncioTestCase):
    async def test_non_runtime_error_sanitized(self) -> None:
        def _raise() -> None:
            raise ValueError("secret=abc123 token=xyz")

        with self.assertRaises(RuntimeError) as cm:
            await server._run_tool(_raise)
        self.assertNotIn("secret=abc123", str(cm.exception))
        self.assertNotIn("token=xyz", str(cm.exception))
        self.assertIsNone(cm.exception.__cause__)
        self.assertIsNone(cm.exception.__context__)


if __name__ == "__main__":
    unittest.main()
