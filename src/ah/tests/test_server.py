"""Tests for ah_mcp.server.

Security focus
--------------
The test suite verifies the four core security properties of the MCP server:

1. **Read-only tool surface** – every registered MCP tool is named ``get_*``;
   no mutation-named tool is present.

2. **GET-only HTTP helper** – ``_get()`` always calls ``authentication_retry``
   with the ``GET`` method constant and cannot be redirected to a mutating
   method.

3. **Credential isolation** – ``_ctx()`` fails loudly when environment
   variables are absent; ``_run_tool()`` catches all non-RuntimeError
   exceptions (which may contain OIDC credential material) and re-raises them
   as sanitised ``RuntimeError`` instances before they reach FastMCP.

4. **ID allowlisting** – every tool that accepts ``organization_id`` or
   ``project_id`` rejects IDs that are not in the allowlists configured at
   startup, before making any network request.  All ID parameters are
   declared as ``Annotated[int, Field(strict=True, gt=0)]`` so Pydantic
   enforces strict integer type and positive-integer bounds at the
   deserialization boundary; the allowlist check then confirms the value is
   permitted.

``audithub_client`` is stubbed out via ``sys.modules`` before the server
module is imported, so these tests run in CI without the private library
being installed.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Stub out audithub_client before importing server.
# All sub-modules must be registered so that `from ... import ...` statements
# in server.py resolve to the stubs rather than raising ImportError.
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

_stubs: dict[str, MagicMock] = {}
for _mod in _STUB_MODULES:
    if _mod not in sys.modules:
        _stubs[_mod] = MagicMock()
        sys.modules[_mod] = _stubs[_mod]

# The GET constant must be a real string so that equality assertions work.
sys.modules["audithub_client.library.http"].GET = "GET"  # type: ignore[attr-defined]

# Now it is safe to import the server.
import ah_mcp.server as server  # noqa: E402, I001
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


# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

_NOW = datetime(2024, 1, 1, tzinfo=UTC)

_ORG_DICT = {"id": 1, "name": "Acme", "gh_connected": True}

_PROJECT_DICT = {
    "id": 10,
    "name": "Audit",
    "project_root": "/root",
    "src_path": "/root/src",
    "created_at": _NOW.isoformat(),
    "input_info": {"input_type": "git", "url": "https://github.com/example/repo"},
}

_VERSION_DICT = {
    "id": 42,
    "name": "v1.0",
    "created_at": _NOW.isoformat(),
    "project_revision_hash": "abc123",
    "digest": None,
    "commit_hash": None,
    "input_info": {"input_type": "git", "url": "https://github.com/example/repo"},
}

_TASK_DICT = {
    "id": 99,
    "tool_name": "orca",
    "tool_version": "1.0",
    "version_id": 42,
    "status": "Finished",
    "created_at": _NOW.isoformat(),
}

_COMMENT_DICT = {
    "id": 5,
    "project_id": 10,
    "thread_id": 3,
    "data": "hello",
    "created_at": _NOW.isoformat(),
    "created_by": "alice",
    "is_modified": False,
    "is_deleted": False,
}

_THREAD_DICT = {
    "id": 3,
    "project_id": 10,
    "type": "note",
    "subject": {"type": "project"},
    "created_at": _NOW.isoformat(),
    "created_by": "alice",
}

_ISSUE_LIST_DICT = {
    "id": 7,
    "title": "Bug",
    "status": "open",
    "likelihood": 3,
    "impact": 4,
    "severity": 5,
    "internally_shared": False,
    "externally_shared": False,
    "created_at": _NOW.isoformat(),
    "last_updated_at": _NOW.isoformat(),
    "gh_issue_url": None,
    "gh_security_advisory_url": None,
}

_ISSUE_DETAILS_DICT = {
    "kind": "public",
    "data": {
        "id": 7,
        "title": "Bug",
        "status": "open",
        "description": "A bug",
        "likelihood": 3,
        "impact": 4,
        "severity": 5,
        "revision_id": 1,
        "affected_files": [{"version_id": 42, "relative_path": "src/Foo.sol"}],
        "type": [1],
        "gh_issue_url": None,
        "gh_security_advisory_url": None,
    },
    "functions": [],
}

_FULL_ENV: dict[str, str] = {
    "AUDITHUB_BASE_URL": "https://example.com/api/v1",
    "AUDITHUB_OIDC_CONFIGURATION_URL": "https://idp.example.com/.well-known/openid-configuration",
    "AUDITHUB_OIDC_CLIENT_ID": "test-client-id",
    "AUDITHUB_OIDC_CLIENT_SECRET": "test-client-secret",
}


def _make_ctx_mock(base_url: str = "https://example.com/api/v1") -> MagicMock:
    ctx = MagicMock()
    ctx.base_url = base_url
    return ctx


def setUpModule() -> None:
    """Ensure all module-level state is clean before any test runs."""
    server._context = None
    server._allowed_org_ids = frozenset()
    server._allowed_project_ids = frozenset()


def tearDownModule() -> None:
    """Restore clean state after all tests complete."""
    server._context = None
    server._allowed_org_ids = frozenset()
    server._allowed_project_ids = frozenset()


# ---------------------------------------------------------------------------
# 1. Credential / configuration validation
# ---------------------------------------------------------------------------


class TestBuildContext(unittest.TestCase):
    """_build_context() reads env vars and constructs an AuditHubContext."""

    def test_raises_when_all_vars_missing(self) -> None:
        env = {k: "" for k in server._REQUIRED_ENV_VARS}
        with patch.dict(os.environ, env), self.assertRaises(RuntimeError) as cm:
            server._build_context()
        self.assertIn("Missing required environment variables", str(cm.exception))

    def test_raises_lists_missing_var_names(self) -> None:
        env = {k: "" for k in server._REQUIRED_ENV_VARS}
        env["AUDITHUB_BASE_URL"] = "https://example.com"
        with patch.dict(os.environ, env), self.assertRaises(RuntimeError) as cm:
            server._build_context()
        msg = str(cm.exception)
        for var in (
            "AUDITHUB_OIDC_CONFIGURATION_URL",
            "AUDITHUB_OIDC_CLIENT_ID",
            "AUDITHUB_OIDC_CLIENT_SECRET",
        ):
            self.assertIn(var, msg, f"Expected missing var '{var}' to appear in error: {msg}")

    def test_succeeds_when_all_vars_present(self) -> None:
        with patch.dict(os.environ, _FULL_ENV):
            ctx = server._build_context()
        self.assertIsNotNone(ctx)

    def test_base_url_passed_to_context(self) -> None:
        mock_ctx_cls = MagicMock()
        with patch.dict(os.environ, _FULL_ENV), \
                patch.object(server, "AuditHubContext", mock_ctx_cls):
            server._build_context()
        call_kwargs = mock_ctx_cls.call_args.kwargs
        self.assertEqual(call_kwargs["base_url"], _FULL_ENV["AUDITHUB_BASE_URL"])

    def test_secret_not_in_error_message(self) -> None:
        """Credential values must not appear in the missing-vars error message."""
        env = {k: "" for k in server._REQUIRED_ENV_VARS}
        env["AUDITHUB_OIDC_CLIENT_SECRET"] = "SUPER_SECRET_VALUE"
        with patch.dict(os.environ, env), self.assertRaises(RuntimeError) as cm:
            server._build_context()
        self.assertNotIn("SUPER_SECRET_VALUE", str(cm.exception))


class TestCtxCache(unittest.TestCase):
    """_ctx() returns the cached context set by main(); raises if uninitialised."""

    def setUp(self) -> None:
        server._context = None

    def tearDown(self) -> None:
        server._context = None

    def test_raises_when_context_not_initialised(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            server._ctx()
        self.assertIn("not initialised", str(cm.exception))

    def test_returns_cached_context(self) -> None:
        mock_ctx = _make_ctx_mock()
        server._context = mock_ctx
        self.assertIs(server._ctx(), mock_ctx)

    def test_main_initialises_context_from_env(self) -> None:
        mock_ctx = _make_ctx_mock()
        allowlist_env = {"AH_ALLOWED_ORG_IDS": "1,2", "AH_ALLOWED_PROJECT_IDS": "10,20"}
        with patch.dict(os.environ, allowlist_env), \
                patch.object(server, "_build_context", return_value=mock_ctx), \
                patch.object(server.mcp, "run"):
            server.main()
        self.assertIs(server._context, mock_ctx)
        self.assertEqual(server._allowed_org_ids, frozenset({1, 2}))
        self.assertEqual(server._allowed_project_ids, frozenset({10, 20}))


# ---------------------------------------------------------------------------
# 2. Exception sanitization wrapper
# ---------------------------------------------------------------------------


class TestRunTool(unittest.TestCase):
    """_run_tool() must propagate RuntimeError and sanitize all other exceptions."""

    def test_returns_value_from_fn(self) -> None:
        result = server._run_tool(lambda: {"key": "value"})
        self.assertEqual(result, {"key": "value"})

    def test_propagates_runtime_error_unchanged(self) -> None:
        original = RuntimeError("allowlist rejection")
        def _raise() -> None:
            raise original
        with self.assertRaises(RuntimeError) as cm:
            server._run_tool(_raise)
        self.assertIs(cm.exception, original)
        self.assertIsNone(cm.exception.__context__)

    def test_sanitizes_non_runtime_error(self) -> None:
        def raises() -> None:
            raise ValueError("unexpected detail")
        with self.assertRaises(RuntimeError):
            server._run_tool(raises)

    def test_sanitized_exception_has_no_cause(self) -> None:
        """Chained context (__cause__ / __context__) must be stripped."""
        def raises() -> None:
            raise OSError("network failure")
        with self.assertRaises(RuntimeError) as cm:
            server._run_tool(raises)
        self.assertIsNone(cm.exception.__cause__)
        self.assertIsNone(cm.exception.__context__)

    def test_sanitized_exception_uses_generic_message(self) -> None:
        """Non-RuntimeError exceptions produce a generic message, not the original.

        The original message may contain credential material from the OIDC library,
        so it must not be forwarded to the MCP client.  It is logged separately.
        """
        def raises() -> None:
            raise ValueError("descriptive error text")
        with self.assertRaises(RuntimeError) as cm:
            server._run_tool(raises, tool_name="test_tool", safe_args={})
        msg = str(cm.exception)
        self.assertNotIn("descriptive error text", msg)
        self.assertEqual(msg, "An internal error occurred. Details have been logged.")

    def test_sanitized_exception_no_tool_name_no_logged_claim(self) -> None:
        """When tool_name is empty, error is not logged so message must not claim it was."""
        def raises() -> None:
            raise ValueError("internal detail")
        with self.assertRaises(RuntimeError) as cm:
            server._run_tool(raises)  # no tool_name
        self.assertEqual(str(cm.exception), "An internal error occurred.")
        self.assertNotIn("logged", str(cm.exception))

    def test_sanitized_exception_no_tool_name_no_audit_log(self) -> None:
        """When tool_name is empty, audit logger must not be called."""
        import ah_mcp.audit as audit_mod

        def raises() -> None:
            raise ValueError("internal detail")

        with patch.object(audit_mod.logger, "error") as mock_err, \
                patch.object(audit_mod.logger, "info") as mock_info, \
                self.assertRaises(RuntimeError):
            server._run_tool(raises)
        mock_err.assert_not_called()
        mock_info.assert_not_called()

    def test_runtime_error_cause_is_cleared(self) -> None:
        """RuntimeError propagated through _run_tool must have __cause__ cleared."""
        original = RuntimeError("allowlist rejection")
        def _raise() -> None:
            raise original
        with self.assertRaises(RuntimeError) as cm:
            server._run_tool(_raise)
        self.assertIsNone(cm.exception.__cause__)

    def test_memory_error_is_sanitized(self) -> None:
        def raises() -> None:
            raise MemoryError("OOM")
        with self.assertRaises(RuntimeError) as cm:
            server._run_tool(raises)
        # Internal details (OOM) are withheld from the caller for safety
        self.assertNotIn("OOM", str(cm.exception))


# ---------------------------------------------------------------------------
# 3. Read-only tool surface
# ---------------------------------------------------------------------------


class TestReadOnlyToolSurface(unittest.TestCase):
    """Every registered MCP tool must be a read-only (get_*) operation."""

    def _tool_names(self) -> list[str]:
        try:
            return list(server.mcp._tool_manager._tools.keys())
        except AttributeError:
            self.skipTest("Cannot introspect FastMCP tool registry in this mcp version")
            return []

    def test_at_least_one_tool_registered(self) -> None:
        self.assertGreater(len(self._tool_names()), 0)

    def test_all_tools_start_with_get(self) -> None:
        for name in self._tool_names():
            self.assertTrue(
                name.startswith("get_"),
                f"Tool '{name}' does not start with 'get_' — it may be a mutation tool",
            )



# ---------------------------------------------------------------------------
# 4. IssueDetails model validator
# ---------------------------------------------------------------------------


class TestIssueDetailsModelValidator(unittest.TestCase):
    """_parse_data_by_kind selects Issue or IssueComplete based on kind."""

    _ISSUE_COMPLETE_DICT = {
        "kind": "complete",
        "data": {
            "id": 7,
            "title": "Bug",
            "status": "open",
            "description": "A bug",
            "likelihood": 3,
            "impact": 4,
            "severity": 5,
            "revision_id": 1,
            "affected_files": [{"version_id": 42, "relative_path": "src/Foo.sol"}],
            "type": [1],
            "created_at": _NOW.isoformat(),
            "last_updated_at": _NOW.isoformat(),
            "created_by": "alice",
            "last_updated_by": "bob",
            "internally_shared": True,
            "externally_shared": False,
            "raised_by": ["alice"],
        },
        "functions": [],
    }

    def test_kind_public_produces_issue_instance(self) -> None:
        from ah_mcp.models import Issue, IssueDetails
        result = IssueDetails.model_validate(_ISSUE_DETAILS_DICT)
        self.assertIsInstance(result.data, Issue)
        self.assertEqual(result.kind, "public")

    def test_kind_complete_produces_issue_complete_instance(self) -> None:
        from ah_mcp.models import IssueComplete, IssueDetails
        result = IssueDetails.model_validate(self._ISSUE_COMPLETE_DICT)
        self.assertIsInstance(result.data, IssueComplete)
        self.assertEqual(result.kind, "complete")

    def test_kind_complete_data_has_audit_fields(self) -> None:
        from ah_mcp.models import IssueDetails
        result = IssueDetails.model_validate(self._ISSUE_COMPLETE_DICT)
        self.assertEqual(result.data.created_by, "alice")  # type: ignore[union-attr]

    def test_unknown_kind_rejected_by_pydantic(self) -> None:
        """Unknown kind values are rejected before the model validator runs."""
        from pydantic import ValidationError

        from ah_mcp.models import IssueDetails
        payload = dict(_ISSUE_DETAILS_DICT, kind="restricted")
        with self.assertRaises(ValidationError):
            IssueDetails.model_validate(payload)

    def test_missing_data_raises_validation_error(self) -> None:
        from pydantic import ValidationError

        from ah_mcp.models import IssueDetails
        with self.assertRaises(ValidationError):
            IssueDetails.model_validate({"kind": "public", "functions": []})

    def test_non_dict_input_raises_validation_error(self) -> None:
        """_parse_data_by_kind must raise a clear error on non-dict input."""
        from pydantic import ValidationError

        from ah_mcp.models import IssueDetails
        for bad_input in [["item"], "string", 42, None]:
            with self.subTest(bad_input=bad_input), \
                    self.assertRaises((ValidationError, TypeError)):
                IssueDetails.model_validate(bad_input)

    def test_non_empty_functions_list(self) -> None:
        from ah_mcp.models import IssueDetails
        payload = dict(
            _ISSUE_DETAILS_DICT,
            functions=[{
                "id": 1,
                "code": "resolve",
                "caption": "Resolve",
                "has_comment": False,
                "has_pr": False,
                "optional_comment": False,
                "pre_populated_extra": None,
                "available_to_developers": True,
            }],
        )
        result = IssueDetails.model_validate(payload)
        self.assertEqual(len(result.functions), 1)
        self.assertEqual(result.functions[0].code, "resolve")


# ---------------------------------------------------------------------------
# 5. _build_pagination_params helper
# ---------------------------------------------------------------------------


class TestBuildPaginationParams(unittest.TestCase):
    """_build_pagination_params() must build correct dicts and return None when empty."""

    def test_both_values_present(self) -> None:
        result = server._build_pagination_params(50, 100)
        self.assertEqual(result, {"limit": 50, "offset": 100})

    def test_only_limit(self) -> None:
        result = server._build_pagination_params(50, None)
        self.assertEqual(result, {"limit": 50})

    def test_only_offset(self) -> None:
        result = server._build_pagination_params(None, 10)
        self.assertEqual(result, {"offset": 10})

    def test_both_none_returns_none(self) -> None:
        result = server._build_pagination_params(None, None)
        self.assertIsNone(result)

    def test_zero_offset_included(self) -> None:
        result = server._build_pagination_params(200, 0)
        self.assertEqual(result, {"limit": 200, "offset": 0})

    def test_zero_limit_included(self) -> None:
        result = server._build_pagination_params(0, None)
        self.assertEqual(result, {"limit": 0})


# ---------------------------------------------------------------------------
# 5. _get() always uses GET
# ---------------------------------------------------------------------------


class TestGetHelperIsReadOnly(unittest.TestCase):
    """_get() must call authentication_retry with the GET method and never a mutating one."""

    def _call_get(
        self, path: str = "/test", base_url: str = "https://example.com/api/v1"
    ) -> unittest.mock._CallList:
        mock_ctx = _make_ctx_mock(base_url)
        mock_response = MagicMock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(
                    server, "authentication_retry", return_value=mock_response
                ) as mock_auth, \
                patch.object(server, "ensure_success"), \
                patch.object(server, "response_json", return_value={}):
            server._get(path)
        return mock_auth.call_args

    def test_uses_get_method_constant(self) -> None:
        call_args = self._call_get()
        http_method = call_args.args[1]
        self.assertEqual(http_method, "GET")

    def test_raises_if_path_missing_leading_slash(self) -> None:
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                self.assertRaises(ValueError) as cm:
            server._get("organizations/1")
        self.assertIn("/", str(cm.exception))

    def test_strips_trailing_slash_from_base_url(self) -> None:
        call_args = self._call_get(path="/foo", base_url="https://example.com/api/v1/")
        url: str = call_args.kwargs["url"]
        self.assertFalse(
            url.startswith("https://example.com/api/v1//"),
            f"Double slash in constructed URL: {url}",
        )

    def test_url_concatenation(self) -> None:
        call_args = self._call_get(path="/organizations/1/projects/2/issues")
        url: str = call_args.kwargs["url"]
        self.assertEqual(url, "https://example.com/api/v1/organizations/1/projects/2/issues")

    def test_passes_params(self) -> None:
        mock_ctx = _make_ctx_mock()
        mock_response = MagicMock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(
                    server, "authentication_retry", return_value=mock_response
                ) as mock_auth, \
                patch.object(server, "ensure_success"), \
                patch.object(server, "response_json", return_value={}):
            server._get("/path", params={"limit": 50, "offset": 10})
        self.assertEqual(mock_auth.call_args.kwargs["params"], {"limit": 50, "offset": 10})

    def test_none_params_passed_through(self) -> None:
        mock_ctx = _make_ctx_mock()
        mock_response = MagicMock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(
                    server, "authentication_retry", return_value=mock_response
                ) as mock_auth, \
                patch.object(server, "ensure_success"), \
                patch.object(server, "response_json", return_value={}):
            server._get("/path", params=None)
        self.assertIsNone(mock_auth.call_args.kwargs["params"])


# ---------------------------------------------------------------------------
# 6. Individual tool smoke tests — return typed models
# ---------------------------------------------------------------------------


class TestToolCallsUnderlyingApi(unittest.TestCase):
    """Each MCP tool must delegate to the correct API and return a typed model."""

    def setUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._allowed_project_ids = frozenset({10})

    def tearDown(self) -> None:
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()

    def test_get_my_organizations_returns_org_list(self) -> None:
        mock_api = MagicMock(return_value=[_ORG_DICT])
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_my_organizations", mock_api):
            result = server.get_my_organizations()
        mock_api.assert_called_once_with(mock_ctx)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], Organization)
        self.assertEqual(result[0].id, 1)

    def test_get_my_organizations_returns_empty_list(self) -> None:
        mock_api = MagicMock(return_value=[])
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_my_organizations", mock_api):
            result = server.get_my_organizations()
        self.assertEqual(result, [])

    def test_get_my_organizations_filters_by_allowlist(self) -> None:
        """Orgs not in the allowlist must be excluded from the result."""
        allowed_org = dict(_ORG_DICT, id=1)
        disallowed_org = dict(_ORG_DICT, id=99, name="Other")
        mock_api = MagicMock(return_value=[allowed_org, disallowed_org])
        mock_ctx = _make_ctx_mock()
        server._allowed_org_ids = frozenset({1})
        try:
            with patch.object(server, "_ctx", return_value=mock_ctx), \
                    patch.object(server, "api_get_my_organizations", mock_api):
                result = server.get_my_organizations()
        finally:
            server._allowed_org_ids = frozenset()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, 1)

    def test_get_project_returns_project(self) -> None:
        mock_api = MagicMock(return_value=_PROJECT_DICT)
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_project", mock_api):
            result = server.get_project(organization_id=1, project_id=10)
        mock_api.assert_called_once()
        self.assertIsInstance(result, Project)
        self.assertEqual(result.id, 10)

    def test_get_latest_version_returns_version(self) -> None:
        mock_api = MagicMock(return_value=_VERSION_DICT)
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_latest_version", mock_api):
            result = server.get_latest_version(organization_id=1, project_id=10)
        mock_api.assert_called_once()
        self.assertIsInstance(result, Version)
        self.assertEqual(result.id, 42)

    def test_get_task_info_returns_task(self) -> None:
        mock_api = MagicMock(return_value=_TASK_DICT)
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_task_info", mock_api):
            result = server.get_task_info(organization_id=1, task_id=99)
        mock_api.assert_called_once()
        self.assertIsInstance(result, Task)
        self.assertEqual(result.id, 99)
        self.assertEqual(result.status, "Finished")

    def test_get_task_logs_returns_str_list(self) -> None:
        mock_api = MagicMock(return_value=["log line 1", "log line 2"])
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_task_logs", mock_api):
            result = server.get_task_logs(organization_id=1, task_id=99, step_code="analysis")
        mock_api.assert_called_once()
        self.assertEqual(result, ["log line 1", "log line 2"])

    def test_get_version_comments_returns_comment_list(self) -> None:
        mock_api = MagicMock(return_value=[_COMMENT_DICT])
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_version_comments", mock_api):
            result = server.get_version_comments(organization_id=1, project_id=10, version_id=3)
        mock_api.assert_called_once()
        self.assertIsInstance(result[0], Comment)
        self.assertEqual(result[0].id, 5)

    def test_get_version_comment_threads_returns_thread_list(self) -> None:
        mock_get = MagicMock(return_value=[_THREAD_DICT])
        with patch.object(server, "_get", mock_get):
            result = server.get_version_comment_threads(
                organization_id=1, project_id=10, version_id=3
            )
        mock_get.assert_called_once()
        path_arg: str = mock_get.call_args.args[0]
        self.assertIn("comment-threads", path_arg)
        self.assertIn("/organizations/1/projects/10/versions/3", path_arg)
        self.assertIsInstance(result[0], Thread)
        self.assertEqual(result[0].id, 3)

    def test_get_project_issues_returns_issue_list(self) -> None:
        mock_get = MagicMock(return_value=[_ISSUE_LIST_DICT])
        with patch.object(server, "_get", mock_get):
            result = server.get_project_issues(organization_id=1, project_id=10)
        mock_get.assert_called_once()
        path_arg: str = mock_get.call_args.args[0]
        self.assertIn("/issues", path_arg)
        self.assertIsInstance(result[0], IssueForList)
        self.assertEqual(result[0].id, 7)

    def test_get_project_issue_returns_issue_details(self) -> None:
        mock_get = MagicMock(return_value=_ISSUE_DETAILS_DICT)
        with patch.object(server, "_get", mock_get):
            result = server.get_project_issue(organization_id=1, project_id=10, issue_id=7)
        mock_get.assert_called_once()
        path_arg: str = mock_get.call_args.args[0]
        self.assertIn("/issues/7", path_arg)
        self.assertIsInstance(result, IssueDetails)
        self.assertEqual(result.kind, "public")
        self.assertEqual(result.data.id, 7)

    def test_get_project_comments_returns_comment_list(self) -> None:
        mock_get = MagicMock(return_value=[_COMMENT_DICT])
        with patch.object(server, "_get", mock_get):
            result = server.get_project_comments(organization_id=1, project_id=10)
        mock_get.assert_called_once()
        path_arg: str = mock_get.call_args.args[0]
        self.assertIn("/comments", path_arg)
        self.assertIsInstance(result[0], Comment)

    def test_tool_raises_runtime_error_on_api_failure(self) -> None:
        """API errors must propagate as RuntimeError, not be silently swallowed."""
        mock_api = MagicMock(side_effect=RuntimeError("HTTP 403 Forbidden"))
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_my_organizations", mock_api), \
                self.assertRaises(RuntimeError) as cm:
            server.get_my_organizations()
        self.assertIn("403", str(cm.exception))

    def test_non_runtime_error_from_api_is_sanitized(self) -> None:
        """Non-RuntimeError exceptions must be re-raised as RuntimeError with no chain."""
        mock_api = MagicMock(side_effect=OSError("network failure"))
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_my_organizations", mock_api), \
                self.assertRaises(RuntimeError) as cm:
            server.get_my_organizations()
        exc = cm.exception
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        # Internal error details must not be forwarded to the MCP client
        self.assertNotIn("network failure", str(exc))
        self.assertEqual(str(exc), "An internal error occurred. Details have been logged.")


# ---------------------------------------------------------------------------
# 7. Pagination parameter forwarding
# ---------------------------------------------------------------------------


class TestPaginationParams(unittest.TestCase):
    """Limit and offset values must be forwarded to the API, not silently dropped."""

    def setUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._allowed_project_ids = frozenset({10})

    def tearDown(self) -> None:
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()

    def test_get_project_issues_forwards_limit_and_offset(self) -> None:
        mock_get = MagicMock(return_value=[])
        with patch.object(server, "_get", mock_get):
            server.get_project_issues(organization_id=1, project_id=10, limit=50, offset=100)
        params = mock_get.call_args.kwargs["params"]
        self.assertEqual(params["limit"], 50)
        self.assertEqual(params["offset"], 100)

    def test_get_version_comments_forwards_limit_and_offset(self) -> None:
        mock_api = MagicMock(return_value=[])
        mock_args_cls = MagicMock()
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_version_comments", mock_api), \
                patch.object(server, "GetVersionCommentsArgs", mock_args_cls):
            server.get_version_comments(
                organization_id=1, project_id=10, version_id=3, limit=75, offset=25
            )
        kwargs = mock_args_cls.call_args.kwargs
        self.assertEqual(kwargs["limit"], 75)
        self.assertEqual(kwargs["offset"], 25)

    def test_get_version_comment_threads_forwards_limit_and_offset(self) -> None:
        mock_get = MagicMock(return_value=[])
        with patch.object(server, "_get", mock_get):
            server.get_version_comment_threads(
                organization_id=1, project_id=10, version_id=3, limit=10, offset=20
            )
        params = mock_get.call_args.kwargs["params"]
        self.assertEqual(params["limit"], 10)
        self.assertEqual(params["offset"], 20)

    def test_get_project_comments_forwards_limit_and_offset(self) -> None:
        mock_get = MagicMock(return_value=[])
        with patch.object(server, "_get", mock_get):
            server.get_project_comments(organization_id=1, project_id=10, limit=25, offset=50)
        params = mock_get.call_args.kwargs["params"]
        self.assertEqual(params["limit"], 25)
        self.assertEqual(params["offset"], 50)

    def test_none_limit_excluded_from_params(self) -> None:
        mock_get = MagicMock(return_value=[])
        with patch.object(server, "_get", mock_get):
            server.get_project_issues(organization_id=1, project_id=10, limit=None, offset=None)
        params_arg = mock_get.call_args.kwargs["params"]
        self.assertIsNone(params_arg)

    def test_default_limit_and_offset_forwarded(self) -> None:
        """Default limit=200, offset=0 must be forwarded to the API."""
        mock_get = MagicMock(return_value=[])
        with patch.object(server, "_get", mock_get):
            server.get_project_issues(organization_id=1, project_id=10)
        params = mock_get.call_args.kwargs["params"]
        self.assertEqual(params["limit"], 200)
        self.assertEqual(params["offset"], 0)


# ---------------------------------------------------------------------------
# 8. Allowlist configuration
# ---------------------------------------------------------------------------


class TestParseIdList(unittest.TestCase):
    """_parse_id_list() must parse valid inputs and exit on invalid ones."""

    def test_single_id(self) -> None:
        self.assertEqual(server._parse_id_list("42", "flag"), frozenset({42}))

    def test_multiple_ids(self) -> None:
        self.assertEqual(server._parse_id_list("1,2,3", "flag"), frozenset({1, 2, 3}))

    def test_whitespace_around_ids(self) -> None:
        self.assertEqual(server._parse_id_list(" 1 , 2 , 3 ", "flag"), frozenset({1, 2, 3}))

    def test_invalid_non_integer_exits(self) -> None:
        with self.assertRaises(SystemExit):
            server._parse_id_list("1,abc,3", "flag")

    def test_empty_string_returns_empty_frozenset(self) -> None:
        self.assertEqual(server._parse_id_list("", "flag"), frozenset())

    def test_zero_id_exits(self) -> None:
        with self.assertRaises(SystemExit):
            server._parse_id_list("1,0,3", "flag")

    def test_negative_id_exits(self) -> None:
        with self.assertRaises(SystemExit):
            server._parse_id_list("1,-5,3", "flag")


class TestMainAllowlistValidation(unittest.TestCase):
    """main() must exit immediately when allowlists are not configured."""

    def setUp(self) -> None:
        server._context = None
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()

    def tearDown(self) -> None:
        server._context = None
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()

    def _run_main(self, argv: list[str], extra_env: dict[str, str] | None = None) -> None:
        env = {k: "" for k in ("AH_ALLOWED_ORG_IDS", "AH_ALLOWED_PROJECT_IDS")}
        env.update(extra_env or {})
        with patch("sys.argv", ["ah-mcp"] + argv), \
                patch.dict(os.environ, env), \
                patch.object(server, "_build_context", return_value=_make_ctx_mock()), \
                patch.object(server.mcp, "run"):
            server.main()

    def test_exits_when_org_ids_missing(self) -> None:
        with self.assertRaises(SystemExit):
            self._run_main(["--allowed-project-ids", "10"])

    def test_exits_when_project_ids_missing(self) -> None:
        with self.assertRaises(SystemExit):
            self._run_main(["--allowed-org-ids", "1"])

    def test_cli_flag_sets_org_allowlist(self) -> None:
        self._run_main(["--allowed-org-ids", "1,2", "--allowed-project-ids", "10"])
        self.assertEqual(server._allowed_org_ids, frozenset({1, 2}))

    def test_cli_flag_sets_project_allowlist(self) -> None:
        self._run_main(["--allowed-org-ids", "1", "--allowed-project-ids", "10,20"])
        self.assertEqual(server._allowed_project_ids, frozenset({10, 20}))

    def test_env_var_sets_org_allowlist(self) -> None:
        self._run_main([], extra_env={"AH_ALLOWED_ORG_IDS": "5,6", "AH_ALLOWED_PROJECT_IDS": "99"})
        self.assertEqual(server._allowed_org_ids, frozenset({5, 6}))

    def test_cli_flag_takes_precedence_over_env_var(self) -> None:
        self._run_main(
            ["--allowed-org-ids", "1"],
            extra_env={"AH_ALLOWED_ORG_IDS": "99,100", "AH_ALLOWED_PROJECT_IDS": "10"},
        )
        self.assertEqual(server._allowed_org_ids, frozenset({1}))


# ---------------------------------------------------------------------------
# 9. Per-tool allowlist enforcement
# ---------------------------------------------------------------------------


class TestAllowlistEnforcement(unittest.TestCase):
    """Tools must reject disallowed org/project IDs before any network call."""

    def setUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._allowed_project_ids = frozenset({10})

    def tearDown(self) -> None:
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()

    def _assert_blocked(self, fn: object, *args: object, **kwargs: object) -> None:
        with self.assertRaises(RuntimeError) as cm:
            fn(*args, **kwargs)  # type: ignore[operator]
        self.assertIn("not in the configured allowlist", str(cm.exception))

    def test_get_project_blocks_unlisted_org(self) -> None:
        self._assert_blocked(server.get_project, organization_id=99, project_id=10)

    def test_get_project_blocks_unlisted_project(self) -> None:
        self._assert_blocked(server.get_project, organization_id=1, project_id=99)

    def test_get_project_allows_listed_ids(self) -> None:
        mock_api = MagicMock(return_value=_PROJECT_DICT)
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_project", mock_api):
            result = server.get_project(organization_id=1, project_id=10)
        self.assertIsInstance(result, Project)
        mock_api.assert_called_once()

    def test_get_latest_version_blocks_unlisted_org(self) -> None:
        self._assert_blocked(server.get_latest_version, organization_id=99, project_id=10)

    def test_get_latest_version_blocks_unlisted_project(self) -> None:
        self._assert_blocked(server.get_latest_version, organization_id=1, project_id=99)

    def test_get_task_info_blocks_unlisted_org(self) -> None:
        self._assert_blocked(server.get_task_info, organization_id=99, task_id=1)

    def test_get_task_info_does_not_check_task_id(self) -> None:
        mock_api = MagicMock(return_value=_TASK_DICT)
        mock_ctx = _make_ctx_mock()
        with patch.object(server, "_ctx", return_value=mock_ctx), \
                patch.object(server, "api_get_task_info", mock_api):
            result = server.get_task_info(organization_id=1, task_id=9999)
        self.assertIsInstance(result, Task)
        mock_api.assert_called_once()

    def test_get_version_comments_blocks_unlisted_org(self) -> None:
        self._assert_blocked(
            server.get_version_comments, organization_id=99, project_id=10, version_id=1
        )

    def test_get_version_comments_blocks_unlisted_project(self) -> None:
        self._assert_blocked(
            server.get_version_comments, organization_id=1, project_id=99, version_id=1
        )

    def test_get_version_comment_threads_blocks_unlisted_org(self) -> None:
        self._assert_blocked(
            server.get_version_comment_threads, organization_id=99, project_id=10, version_id=1
        )

    def test_get_project_issues_blocks_unlisted_org(self) -> None:
        self._assert_blocked(server.get_project_issues, organization_id=99, project_id=10)

    def test_get_project_issue_blocks_unlisted_org(self) -> None:
        self._assert_blocked(
            server.get_project_issue, organization_id=99, project_id=10, issue_id=5
        )

    def test_get_project_issue_blocks_unlisted_project(self) -> None:
        self._assert_blocked(server.get_project_issue, organization_id=1, project_id=99, issue_id=5)

    def test_get_project_comments_blocks_unlisted_project(self) -> None:
        self._assert_blocked(server.get_project_comments, organization_id=1, project_id=99)

    def test_get_task_logs_blocks_unlisted_org(self) -> None:
        self._assert_blocked(server.get_task_logs, organization_id=99, task_id=1, step_code="s")

    def test_get_version_comment_threads_blocks_unlisted_project(self) -> None:
        self._assert_blocked(
            server.get_version_comment_threads, organization_id=1, project_id=99, version_id=1
        )

    def test_get_project_issues_blocks_unlisted_project(self) -> None:
        self._assert_blocked(server.get_project_issues, organization_id=1, project_id=99)

    def test_get_project_comments_blocks_unlisted_org(self) -> None:
        self._assert_blocked(server.get_project_comments, organization_id=99, project_id=10)

    def test_error_does_not_reveal_other_allowlisted_ids(self) -> None:
        """The error message must not leak the full allowlist contents."""
        server._allowed_org_ids = frozenset({100, 200, 300})
        with self.assertRaises(RuntimeError) as cm:
            server.get_project(organization_id=999, project_id=10)
        error = str(cm.exception)
        self.assertIn("999", error)
        # The full allowlist must not be disclosed to prevent enumeration
        self.assertNotIn("100", error)
        self.assertNotIn("200", error)
        self.assertNotIn("300", error)
        self.assertNotIn("AUDITHUB", error)

    def test_network_not_called_on_allowlist_rejection(self) -> None:
        """Rejected calls must not reach the AuditHub API."""
        with patch.object(server, "authentication_retry") as mock_net, \
                self.assertRaises(RuntimeError):
            server.get_project_issues(organization_id=99, project_id=10)
        mock_net.assert_not_called()


# ---------------------------------------------------------------------------
# 10. Allowlist-only enforcement for assert helpers
# ---------------------------------------------------------------------------


class TestAssertOrgAllowed(unittest.TestCase):
    """_assert_org_allowed() checks the frozenset; type/bounds enforced by Pydantic."""

    def setUp(self) -> None:
        server._allowed_org_ids = frozenset({1, 2})

    def tearDown(self) -> None:
        server._allowed_org_ids = frozenset()

    def test_passes_for_allowed_id(self) -> None:
        server._assert_org_allowed(1)  # should not raise

    def test_raises_for_unlisted_id(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            server._assert_org_allowed(99)
        self.assertIn("not in the configured allowlist", str(cm.exception))

    def test_error_includes_rejected_id(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            server._assert_org_allowed(99)
        self.assertIn("99", str(cm.exception))


class TestAssertProjectAllowed(unittest.TestCase):
    """_assert_project_allowed() checks the frozenset; type/bounds enforced by Pydantic."""

    def setUp(self) -> None:
        server._allowed_project_ids = frozenset({10, 20})

    def tearDown(self) -> None:
        server._allowed_project_ids = frozenset()

    def test_passes_for_allowed_id(self) -> None:
        server._assert_project_allowed(10)  # should not raise

    def test_raises_for_unlisted_id(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            server._assert_project_allowed(99)
        self.assertIn("not in the configured allowlist", str(cm.exception))

    def test_error_includes_rejected_id(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            server._assert_project_allowed(99)
        self.assertIn("99", str(cm.exception))


# ---------------------------------------------------------------------------
# 11. FastMCP schema validation (_AhId enforced at the tool-call boundary)
# ---------------------------------------------------------------------------


class TestFastMCPSchemaValidation(unittest.IsolatedAsyncioTestCase):
    """FastMCP must enforce _AhId constraints before calling tool bodies."""

    def setUp(self) -> None:
        server._allowed_org_ids = frozenset({1})
        server._allowed_project_ids = frozenset({10})
        server._context = _make_ctx_mock()

    def tearDown(self) -> None:
        server._allowed_org_ids = frozenset()
        server._allowed_project_ids = frozenset()
        server._context = None

    async def _call(self, tool: str, **kwargs: object) -> object:
        return await server.mcp._tool_manager.call_tool(tool, kwargs)

    async def _assert_validation_error(self, tool: str, **kwargs: object) -> None:
        from mcp.shared.exceptions import McpError
        with self.assertRaises((McpError, Exception)) as cm:
            await self._call(tool, **kwargs)
        self.assertIn("validation error", str(cm.exception).lower())

    async def test_string_org_id_rejected(self) -> None:
        await self._assert_validation_error("get_project", organization_id="1", project_id=10)

    async def test_float_org_id_rejected(self) -> None:
        await self._assert_validation_error("get_project", organization_id=1.0, project_id=10)

    async def test_zero_org_id_rejected(self) -> None:
        await self._assert_validation_error("get_project", organization_id=0, project_id=10)

    async def test_negative_org_id_rejected(self) -> None:
        await self._assert_validation_error("get_project", organization_id=-1, project_id=10)

    async def test_string_project_id_rejected(self) -> None:
        await self._assert_validation_error("get_project", organization_id=1, project_id="10")

    async def test_zero_project_id_rejected(self) -> None:
        await self._assert_validation_error("get_project", organization_id=1, project_id=0)

    async def test_valid_ids_pass_schema_validation(self) -> None:
        """Valid integer IDs must pass Pydantic validation and reach the tool body."""
        mock_api = MagicMock(return_value=_PROJECT_DICT)
        with patch.object(server, "api_get_project", mock_api):
            await self._call("get_project", organization_id=1, project_id=10)
        mock_api.assert_called_once()


if __name__ == "__main__":
    unittest.main()
