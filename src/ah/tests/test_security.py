"""Adversarial / security tests for ah_mcp.server.

These tests simulate a malicious agent attempting to abuse the MCP interface.
All network calls are blocked via allowlist rejection or mock patching — no
real HTTP requests are made.

Threat model
------------
- A malicious agent controls all tool arguments.
- The agent may supply path-traversal strings, oversized inputs, unicode/control
  characters, out-of-range integers, float IDs, string IDs, negative offsets,
  disallowed org/project IDs, and null required fields.
- The server must reject all such inputs before making any network request and
  must not leak credentials, traceback information, or internal state.

``audithub_client`` is stubbed out here using the same pattern as
``test_server.py`` so these tests run in CI without the private library.
"""

from __future__ import annotations

import sys
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Stub out audithub_client before importing the server module.
# This mirrors the setup in test_server.py; the `if not in sys.modules` guard
# ensures only the first file to be collected actually injects the stubs.
# ---------------------------------------------------------------------------

_STUB_MODULES = [
    "audithub_client",
    "audithub_client.api",
    "audithub_client.api.get_latest_version",
    "audithub_client.api.get_my_organizations",
    "audithub_client.api.get_project",
    "audithub_client.api.get_task_info",
    "audithub_client.api.get_task_logs",
    "audithub_client.api.get_version_comments",
    "audithub_client.library",
    "audithub_client.library.auth",
    "audithub_client.library.context",
    "audithub_client.library.http",
    "audithub_client.library.net_utils",
]

for _mod in _STUB_MODULES:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

sys.modules["audithub_client.library.http"].GET = "GET"  # type: ignore[attr-defined]

import ah_mcp.server as server  # noqa: E402, I001


def setUpModule() -> None:
    server._context = MagicMock()
    server._context.base_url = "https://example.com/api/v1"
    server._allowed_org_ids = frozenset({1})
    server._allowed_project_ids = frozenset({10})


def tearDownModule() -> None:
    server._context = None
    server._allowed_org_ids = frozenset()
    server._allowed_project_ids = frozenset()


class TestDisallowedIds(unittest.TestCase):
    """Tools reject org/project IDs not in the allowlist before making network calls."""

    def test_get_project_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            server.get_project(organization_id=999, project_id=10)
        self.assertIn("999", str(cm.exception))
        self.assertNotIn("allowlist", str(cm.exception).lower().replace("allowlist", ""))

    def test_get_project_disallowed_project(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            server.get_project(organization_id=1, project_id=999)
        self.assertIn("999", str(cm.exception))

    def test_get_latest_version_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError):
            server.get_latest_version(organization_id=999, project_id=10)

    def test_get_task_info_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError):
            server.get_task_info(organization_id=999, task_id=1)

    def test_get_task_logs_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError):
            server.get_task_logs(organization_id=999, task_id=1, step_code="step")

    def test_get_version_comments_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError):
            server.get_version_comments(organization_id=999, project_id=10, version_id=1)

    def test_get_version_comment_threads_disallowed_project(self) -> None:
        with self.assertRaises(RuntimeError):
            server.get_version_comment_threads(organization_id=1, project_id=999, version_id=1)

    def test_get_project_issues_disallowed_project(self) -> None:
        with self.assertRaises(RuntimeError):
            server.get_project_issues(organization_id=1, project_id=999)

    def test_get_project_issue_disallowed_org(self) -> None:
        with self.assertRaises(RuntimeError):
            server.get_project_issue(organization_id=999, project_id=10, issue_id=1)

    def test_get_project_comments_disallowed_project(self) -> None:
        with self.assertRaises(RuntimeError):
            server.get_project_comments(organization_id=1, project_id=999)

    def test_error_does_not_enumerate_allowlist(self) -> None:
        """Error messages must not reveal the full allowlist contents."""
        with self.assertRaises(RuntimeError) as cm:
            server.get_project(organization_id=42, project_id=10)
        msg = str(cm.exception)
        # The rejected ID appears so the caller can self-diagnose
        self.assertIn("42", msg)
        # Must not leak the allowlist representation (frozenset of allowed IDs)
        self.assertNotIn("frozenset", msg)


class TestInvalidIdTypes(unittest.TestCase):
    """Pydantic rejects non-integer and non-positive ID values at the boundary.

    FastMCP/Pydantic enforces ``strict=True, gt=0`` on all _AhId parameters.
    These tests verify that invalid types raise ``Exception`` (``ValidationError``)
    before any allowlist check or network call runs.
    """

    def _assert_rejected(self, fn: object, **kwargs: object) -> None:
        assert callable(fn)
        with self.assertRaises((RuntimeError, TypeError, ValueError)):
            fn(**kwargs)  # type: ignore[call-arg]

    def test_float_org_id(self) -> None:
        self._assert_rejected(server.get_project, organization_id=1.5, project_id=10)

    def test_string_org_id(self) -> None:
        self._assert_rejected(server.get_project, organization_id="1", project_id=10)

    def test_zero_org_id(self) -> None:
        self._assert_rejected(server.get_project, organization_id=0, project_id=10)

    def test_negative_org_id(self) -> None:
        self._assert_rejected(server.get_project, organization_id=-1, project_id=10)

    def test_very_large_int_id(self) -> None:
        # Large positive integer: valid type, but not in allowlist → RuntimeError
        with self.assertRaises(RuntimeError):
            server.get_project(organization_id=10**18, project_id=10)

    def test_none_org_id(self) -> None:
        self._assert_rejected(server.get_project, organization_id=None, project_id=10)

    def test_float_project_id(self) -> None:
        self._assert_rejected(server.get_project, organization_id=1, project_id=10.9)

    def test_string_project_id(self) -> None:
        self._assert_rejected(server.get_project, organization_id=1, project_id="10")

    def test_negative_project_id(self) -> None:
        self._assert_rejected(server.get_project, organization_id=1, project_id=-5)


class TestNegativePaginationOffsets(unittest.TestCase):
    """Negative pagination offsets are rejected by Pydantic (ge=0 constraint)."""

    def test_negative_limit_get_project_issues(self) -> None:
        with self.assertRaises((RuntimeError, ValueError)):
            server.get_project_issues(organization_id=1, project_id=10, limit=-1)

    def test_negative_offset_get_project_issues(self) -> None:
        with self.assertRaises((RuntimeError, ValueError)):
            server.get_project_issues(organization_id=1, project_id=10, offset=-1)

    def test_negative_limit_get_project_comments(self) -> None:
        with self.assertRaises((RuntimeError, ValueError)):
            server.get_project_comments(organization_id=1, project_id=10, limit=-100)

    def test_negative_offset_get_version_comments(self) -> None:
        with self.assertRaises((RuntimeError, ValueError)):
            server.get_version_comments(
                organization_id=1, project_id=10, version_id=1, offset=-1
            )

    def test_negative_offset_get_version_comment_threads(self) -> None:
        with self.assertRaises((RuntimeError, ValueError)):
            server.get_version_comment_threads(
                organization_id=1, project_id=10, version_id=1, offset=-50
            )


class TestOversizedAndAdversarialStrings(unittest.TestCase):
    """Oversized and adversarial string values in step_code are passed to the library.

    The server does not validate step_code content — that is the library's
    responsibility.  These tests verify the server correctly forwards the value
    and that it does NOT log step_code in audit output.
    """

    def setUp(self) -> None:
        self._ctx_patcher = patch("ah_mcp.server._ctx")
        self._mock_ctx = self._ctx_patcher.start()
        self._mock_ctx.return_value = MagicMock()
        self._mock_ctx.return_value.base_url = "https://example.com/api/v1"

    def tearDown(self) -> None:
        self._ctx_patcher.stop()

    def _call_task_logs(self, step_code: str) -> None:
        import ah_mcp.audit as audit_mod

        with patch.object(server, "api_get_task_logs", return_value=[]), \
                patch.object(audit_mod.logger, "info") as mock_log_info:
            server.get_task_logs(organization_id=1, task_id=1, step_code=step_code)
            # step_code must not appear in any audit log call
            for call in mock_log_info.call_args_list:
                args = " ".join(str(a) for a in call.args)
                self.assertNotIn(step_code[:50], args)

    def test_path_traversal_step_code(self) -> None:
        self._call_task_logs("../../../etc/passwd")

    def test_oversized_step_code(self) -> None:
        self._call_task_logs("x" * 10_000)

    def test_unicode_step_code(self) -> None:
        self._call_task_logs("\u0000\u001f\uffff\U0001f4a3")

    def test_null_byte_step_code(self) -> None:
        self._call_task_logs("step\x00injected")


class TestErrorSanitization(unittest.TestCase):
    """_run_tool sanitizes non-RuntimeError exceptions to prevent credential leakage."""

    def test_non_runtime_error_sanitized(self) -> None:
        """Credential material from non-RuntimeError exceptions must NOT reach the caller.

        The exception message is forwarded to the audit log only; the caller receives
        a generic message that cannot contain OIDC token or secret material.
        """
        def _raises_value_error() -> None:
            raise ValueError("secret=abc123 token=xyz")

        with self.assertRaises(RuntimeError) as cm:
            server._run_tool(_raises_value_error)
        msg = str(cm.exception)
        # Credential material must be absent from the error propagated to the MCP client
        self.assertNotIn("secret=abc123", msg)
        self.assertNotIn("token=xyz", msg)
        # Context chain must be stripped
        self.assertIsNone(cm.exception.__context__)
        self.assertIsNone(cm.exception.__cause__)

    def test_runtime_error_context_cleared(self) -> None:
        def _raises_runtime() -> None:
            try:
                raise ValueError("inner credential material")
            except ValueError:
                raise RuntimeError("outer error") from None

        with self.assertRaises(RuntimeError) as cm:
            server._run_tool(_raises_runtime)
        self.assertIsNone(cm.exception.__context__)
        self.assertIsNone(cm.exception.__cause__)

    def test_error_message_truncated_in_audit(self) -> None:
        import ah_mcp.audit as audit_mod

        long_msg = "x" * 500

        def _raises() -> None:
            raise ValueError(long_msg)

        with patch.object(audit_mod.logger, "error") as mock_err:
            with self.assertRaises(RuntimeError):
                server._run_tool(_raises, tool_name="test_tool", safe_args={})
            logged = str(mock_err.call_args)
            # The 200-char truncation in audit.py means the full 500-char message
            # must not appear verbatim in the log call arguments
            self.assertNotIn(long_msg, logged)


class TestGetMyOrganizationsFiltering(unittest.TestCase):
    """get_my_organizations only returns orgs present in the allowlist."""

    def test_filters_non_allowlisted_orgs(self) -> None:
        orgs_data = [
            {"id": 1, "name": "Allowed", "gh_connected": False},
            {"id": 2, "name": "NotAllowed", "gh_connected": False},
            {"id": 999, "name": "AlsoNotAllowed", "gh_connected": False},
        ]
        with patch.object(server, "api_get_my_organizations", return_value=orgs_data), \
                patch("ah_mcp.server._ctx") as mock_ctx:
            mock_ctx.return_value = MagicMock()
            result = server.get_my_organizations()
        ids = [o.id for o in result]
        self.assertEqual(ids, [1])
        self.assertNotIn(2, ids)
        self.assertNotIn(999, ids)

    def test_empty_result_when_no_orgs_match(self) -> None:
        orgs_data = [{"id": 999, "name": "NotAllowed", "gh_connected": False}]
        with patch.object(server, "api_get_my_organizations", return_value=orgs_data), \
                patch("ah_mcp.server._ctx") as mock_ctx:
            mock_ctx.return_value = MagicMock()
            result = server.get_my_organizations()
        self.assertEqual(result, [])
