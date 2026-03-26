"""Security-focused tests for the SDK-backed ah_mcp server."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from tests.sdk_stubs import install_sdk_stubs

install_sdk_stubs()

import ah_mcp.server as server  # noqa: E402


class TestDisallowedIds(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._allowed_project_ids = frozenset({10})

    async def asyncTearDown(self) -> None:
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()

    async def test_get_project_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await server.get_project(organization_id=999, project_id=10)
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("frozenset", str(cm.exception))

    async def test_get_project_disallowed_project(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await server.get_project(organization_id=1, project_id=999)
        self.assertIn("999", str(cm.exception))

    async def test_rejected_call_does_not_reach_sdk(self) -> None:
        mock = AsyncMock(return_value={"id": 10, "name": "Audit"})
        with patch.object(
            server.ProjectsApi,
            "get_project_organizations_organization_id_projects_project_id_get",
            mock,
        ), self.assertRaises(RuntimeError):
            await server.get_project(organization_id=999, project_id=10)
        mock.assert_not_awaited()


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

    async def test_step_code_not_in_audit_log(self) -> None:
        import ah_mcp.audit as audit_mod

        step_code = "../../../etc/passwd"
        with patch.object(
            server.TasksApi,
            "get_output_organizations_organization_id_tasks_task_id_step_code_output_get",
            AsyncMock(return_value=[]),
        ), patch.object(audit_mod.logger, "info") as mock_info:
            await server.get_task_logs(organization_id=1, task_id=1, step_code=step_code)
        for call in mock_info.call_args_list:
            args = " ".join(str(arg) for arg in call.args)
            self.assertNotIn(step_code, args)


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
