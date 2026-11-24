"""MCP and SDK boundary tests for Scout task submission."""

import json
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from mcp.client import Client
from mcp.server.mcpserver.exceptions import ToolError

from audithub_mcp import server

pytestmark = pytest.mark.usefixtures("org_write_scope")


async def test_registration_requires_task_runs() -> None:
    async with Client(server.mcp) as client:
        assert "run_scout_task" not in {tool.name for tool in (await client.list_tools()).tools}
        server._set_project_creation_enabled(True)
        assert "run_scout_task" not in {tool.name for tool in (await client.list_tools()).tools}
        server._set_project_creation_enabled(False)

        server._set_task_runs_enabled(True)
        assert "run_scout_task" in {tool.name for tool in (await client.list_tools()).tools}


@pytest.mark.parametrize("enabled,org", [(False, 1), (True, 2), (True, 3)])
async def test_write_gates_precede_authentication(
    monkeypatch: pytest.MonkeyPatch, enabled: bool, org: int
) -> None:
    network = AsyncMock()
    monkeypatch.setattr(server, "_with_api_client", network)
    server._set_task_runs_enabled(enabled)
    with pytest.raises(ToolError):
        await server.run_scout_task(org, 10, 42, "standard")
    network.assert_not_called()


async def test_scout_rejects_unapproved_project(monkeypatch: pytest.MonkeyPatch) -> None:
    network = AsyncMock()
    monkeypatch.setattr(server, "_with_api_client", network)
    server._set_task_runs_enabled(True)
    with pytest.raises(ToolError, match="Project ID 20"):
        await server.run_scout_task(1, 20, 42, "standard")
    network.assert_not_called()


@pytest.mark.parametrize(
    "arguments",
    [
        {"organization_id": 1, "project_id": 10, "version_id": 0, "budget": "standard"},
        {"organization_id": 1, "project_id": 10, "version_id": 42, "budget": " "},
    ],
)
async def test_invalid_inputs_precede_network(
    monkeypatch: pytest.MonkeyPatch, arguments: dict[str, object]
) -> None:
    server._set_task_runs_enabled(True)
    network = AsyncMock()
    monkeypatch.setattr(server, "_with_api_client", network)
    async with Client(server.mcp) as client:
        assert (await client.call_tool("run_scout_task", arguments)).is_error
    network.assert_not_called()


@pytest.mark.parametrize("forbidden", [False, True])
async def test_sdk_requests_and_remote_authorization(
    audithub_http: Mock, forbidden: bool, caplog: pytest.LogCaptureFixture
) -> None:
    server._set_task_runs_enabled(True)
    audithub_http.return_value = (
        httpx.Response(403, json={"detail": "PRIVATE_DENIAL"})
        if forbidden
        else httpx.Response(200, json={"task_id": 77, "message": "Queued"})
    )
    async with Client(server.mcp) as client:
        task = await client.call_tool(
            "run_scout_task",
            {
                "organization_id": 1,
                "project_id": 10,
                "version_id": 42,
                "budget": "standard",
                "name": "PRIVATE_TASK",
                "input_limit": ["src/file.sol"],
            },
        )
    if forbidden:
        assert task.is_error
        assert "403" in str(task.content)
        assert "PRIVATE_DENIAL" not in str(task.content)
    else:
        assert not task.is_error and task.structured_content == {"task_id": 77, "message": "Queued"}
    audithub_http.assert_called_once()
    request = audithub_http.call_args.args[0]
    assert request.url.path == "/api/v1/organizations/1/projects/10/versions/42/tools/agent"
    assert request.method == "POST"
    assert request.headers["Authorization"] == "Bearer TEST_TOKEN"
    assert json.loads(request.content) == {
        "name": "PRIVATE_TASK",
        "budget": "standard",
        "parameters": {"input_limit": ["src/file.sol"], "generate_pocs": False},
    }
    for private in ("TEST_TOKEN", "PRIVATE_TASK", "PRIVATE_DENIAL"):
        assert private not in caplog.text
