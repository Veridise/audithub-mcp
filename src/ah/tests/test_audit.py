"""Direct unit tests for ah_mcp.audit logging functions."""

from __future__ import annotations

import logging
import unittest
from unittest.mock import patch

import ah_mcp.audit as audit


class TestLogCallStart(unittest.TestCase):
    """log_call_start emits a structured INFO record."""

    def test_tool_name_in_log(self) -> None:
        with patch.object(audit.logger, "info") as mock_info:
            audit.log_call_start("get_project", {"organization_id": 1, "project_id": 10})
        call_str = str(mock_info.call_args)
        self.assertIn("get_project", call_str)

    def test_safe_args_in_log(self) -> None:
        with patch.object(audit.logger, "info") as mock_info:
            audit.log_call_start("get_project", {"organization_id": 84, "project_id": 275})
        # The formatted arg_str should contain the key=value pairs
        format_str, tool_name, arg_str = mock_info.call_args.args
        self.assertIn("84", arg_str)
        self.assertIn("275", arg_str)
        self.assertIn("organization_id", arg_str)

    def test_empty_args_no_error(self) -> None:
        """Empty safe_args must not raise and should not produce malformed output."""
        with patch.object(audit.logger, "info") as mock_info:
            audit.log_call_start("get_my_organizations", {})
        mock_info.assert_called_once()
        _, tool_name, arg_str = mock_info.call_args.args
        self.assertEqual(tool_name, "get_my_organizations")
        self.assertEqual(arg_str, "")  # empty — no trailing garbage

    def test_none_value_in_args(self) -> None:
        """None values (for optional limit/offset) are safe to log."""
        with patch.object(audit.logger, "info") as mock_info:
            audit.log_call_start("get_project_issues", {"limit": None, "offset": 0})
        mock_info.assert_called_once()

    def test_log_level_is_info(self) -> None:
        with self.assertLogs("ah_mcp.audit", level=logging.INFO) as ctx:
            audit.log_call_start("get_project", {"organization_id": 1})
        self.assertTrue(any("INFO" in r for r in ctx.output))


class TestLogCallSuccess(unittest.TestCase):
    """log_call_success emits status=ok with elapsed_ms."""

    def test_status_ok_in_log(self) -> None:
        with patch.object(audit.logger, "info") as mock_info:
            audit.log_call_success("get_project", 42.5)
        call_str = str(mock_info.call_args)
        self.assertIn("status=ok", call_str)

    def test_elapsed_ms_in_log(self) -> None:
        with patch.object(audit.logger, "info") as mock_info:
            audit.log_call_success("get_project", 123.456)
        # Logging passes args lazily; check the positional args to the call
        pos_args = mock_info.call_args.args
        self.assertIn(123.456, pos_args)

    def test_tool_name_in_log(self) -> None:
        with patch.object(audit.logger, "info") as mock_info:
            audit.log_call_success("get_latest_version", 0.1)
        call_str = str(mock_info.call_args)
        self.assertIn("get_latest_version", call_str)

    def test_log_level_is_info(self) -> None:
        with self.assertLogs("ah_mcp.audit", level=logging.INFO) as ctx:
            audit.log_call_success("get_project", 10.0)
        self.assertTrue(any("INFO" in r for r in ctx.output))


class TestLogCallError(unittest.TestCase):
    """log_call_error emits status=error, truncates at 200 chars, logs at ERROR."""

    def test_status_error_in_log(self) -> None:
        with patch.object(audit.logger, "error") as mock_err:
            audit.log_call_error("get_project", "something failed", 99.9)
        call_str = str(mock_err.call_args)
        self.assertIn("status=error", call_str)

    def test_tool_name_in_log(self) -> None:
        with patch.object(audit.logger, "error") as mock_err:
            audit.log_call_error("get_project_issue", "not found", 5.0)
        call_str = str(mock_err.call_args)
        self.assertIn("get_project_issue", call_str)

    def test_elapsed_ms_in_log(self) -> None:
        with patch.object(audit.logger, "error") as mock_err:
            audit.log_call_error("get_project", "err", 77.7)
        call_str = str(mock_err.call_args)
        self.assertIn("77.7", call_str)

    def test_short_message_not_truncated(self) -> None:
        """A 200-char message must appear verbatim (not truncated)."""
        msg_200 = "x" * 200
        with patch.object(audit.logger, "error") as mock_err:
            audit.log_call_error("t", msg_200, 1.0)
        _, _, _, truncated = mock_err.call_args.args
        self.assertEqual(truncated, msg_200)

    def test_long_message_truncated_at_200(self) -> None:
        """A 201-char message is truncated; chars beyond 200 do not appear."""
        msg_201 = "a" * 200 + "Z"
        with patch.object(audit.logger, "error") as mock_err:
            audit.log_call_error("t", msg_201, 1.0)
        _, _, _, truncated = mock_err.call_args.args
        self.assertEqual(len(truncated), 200)
        self.assertNotIn("Z", truncated)

    def test_500_char_message_truncated(self) -> None:
        msg = "b" * 500
        with patch.object(audit.logger, "error") as mock_err:
            audit.log_call_error("t", msg, 1.0)
        _, _, _, truncated = mock_err.call_args.args
        self.assertEqual(len(truncated), 200)

    def test_log_level_is_error(self) -> None:
        with self.assertLogs("ah_mcp.audit", level=logging.ERROR) as ctx:
            audit.log_call_error("get_project", "failed", 1.0)
        self.assertTrue(any("ERROR" in r for r in ctx.output))

    def test_empty_message(self) -> None:
        with patch.object(audit.logger, "error") as mock_err:
            audit.log_call_error("t", "", 0.0)
        mock_err.assert_called_once()
