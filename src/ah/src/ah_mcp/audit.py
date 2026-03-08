"""Structured audit logging for AuditHub MCP tool calls.

Records tool invocations, completion times, and sanitized errors to the
``ah_mcp.audit`` logger.  Never logs: step_code content, response bodies,
or credential values.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("ah_mcp.audit")

_MAX_ERROR_LEN: int = 200


def log_call_start(tool_name: str, safe_args: dict[str, int | None]) -> None:
    """Log the start of a tool call at INFO level.

    Args:
        tool_name: Name of the MCP tool being called.
        safe_args: Numeric tool arguments safe to include in logs.  Restricted to
            ``int | None`` values to prevent accidental logging of free-text API
            response content that could carry prompt-injection payloads.
    """
    arg_str = " ".join(f"{k}={v!r}" for k, v in safe_args.items())
    logger.info("tool=%s %s", tool_name, arg_str)


def log_call_success(tool_name: str, elapsed_ms: float) -> None:
    """Log successful completion of a tool call at INFO level.

    Args:
        tool_name: Name of the MCP tool.
        elapsed_ms: Wall-clock milliseconds from call start to completion.
    """
    logger.info("tool=%s elapsed_ms=%.1f status=ok", tool_name, elapsed_ms)


def log_call_error(tool_name: str, error_msg: str, elapsed_ms: float) -> None:
    """Log a tool call error at ERROR level.

    The error message is truncated to 200 characters to bound log size and
    reduce the risk of leaking verbose exception context.

    Args:
        tool_name: Name of the MCP tool.
        error_msg: Sanitized error message (no credentials, no response bodies).
        elapsed_ms: Wall-clock milliseconds from call start to failure.
    """
    truncated = error_msg[:_MAX_ERROR_LEN]
    logger.error(
        "tool=%s elapsed_ms=%.1f status=error error=%r",
        tool_name,
        elapsed_ms,
        truncated,
    )
