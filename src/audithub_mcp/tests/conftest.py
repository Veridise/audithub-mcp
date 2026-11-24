"""Fixtures for MCP tools that require organization write access."""

from collections.abc import Iterator
from functools import partial
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from audithub_sdk_ext import AuthenticatedApiClient, OIDCTokenProvider

from audithub_mcp import server
from audithub_mcp.config import load_config_from_path


@pytest.fixture
def org_write_scope(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(server, "_allowed_org_ids", frozenset({1, 2}))
    monkeypatch.setattr(server, "_writable_org_ids", frozenset({1}))
    monkeypatch.setattr(server, "_allowed_project_ids", frozenset({10}))
    server._set_project_creation_enabled(False)
    server._set_task_runs_enabled(False)
    yield
    server._set_project_creation_enabled(False)
    server._set_task_runs_enabled(False)


@pytest.fixture
def audithub_http(monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Send authenticated SDK requests to the test's HTTP handler."""
    handler = Mock()
    context = load_config_from_path(Path("tests/dummy_config.yaml")).context
    monkeypatch.setattr(server, "_context", context)
    monkeypatch.setattr(OIDCTokenProvider, "get_token", AsyncMock(return_value="TEST_TOKEN"))
    monkeypatch.setattr(
        server,
        "AuthenticatedApiClient",
        partial(
            AuthenticatedApiClient,
            _rest_client_factory=partial(httpx.AsyncClient, transport=httpx.MockTransport(handler)),
        ),
    )
    return handler
