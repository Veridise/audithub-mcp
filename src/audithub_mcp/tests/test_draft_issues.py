"""Draft-only creation boundary tests."""

from collections.abc import Awaitable, Callable, Iterator
from unittest.mock import AsyncMock, MagicMock

import pytest
from audithub_sdk.models.id_and_message_response import IdAndMessageResponse
from audithub_sdk.models.source_reference import SourceReference
from mcp.client import Client
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import ValidationError

from audithub_mcp import server
from audithub_mcp.models import DraftIssueInput

ENDPOINT = "post_issue_organizations_organization_id_projects_project_id_issues_post"


@pytest.fixture
def issue() -> DraftIssueInput:
    return DraftIssueInput(
        title="Issue",
        description="PRIVATE_DESCRIPTION",
        raised_by=["auditor"],
        affected_files=[SourceReference(version_id=42, relative_path="src/a.sol")],
        likelihood=1,
        impact=1,
        severity=1,
    )


@pytest.fixture(autouse=True)
def scope(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(server, "_allowed_org_ids", frozenset({1}))
    monkeypatch.setattr(server, "_allowed_project_ids", frozenset({10}))
    server._set_draft_issue_creation_enabled(False)
    yield
    server._set_draft_issue_creation_enabled(False)


@pytest.mark.parametrize("field", ["status", "visibility", "visible_to_client", "is_draft"])
def test_no_workflow_inputs(issue: DraftIssueInput, field: str) -> None:
    with pytest.raises(ValidationError):
        DraftIssueInput.model_validate({**issue.model_dump(), field: True})


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled,org,project", [(False, 1, 10), (True, 999, 10), (True, 1, 999)])
async def test_gates_before_network(
    monkeypatch: pytest.MonkeyPatch, issue: DraftIssueInput, enabled: bool, org: int, project: int
) -> None:
    server._set_draft_issue_creation_enabled(enabled)
    network = AsyncMock()
    monkeypatch.setattr(server, "_with_api_client", network)
    with pytest.raises(ToolError):
        await server.create_draft_issue(org, project, issue)
    network.assert_not_called()


@pytest.mark.asyncio
async def test_creation_calls_only_creation_endpoint(
    monkeypatch: pytest.MonkeyPatch, issue: DraftIssueInput
) -> None:
    server._set_draft_issue_creation_enabled(True)
    api = MagicMock()
    endpoint = AsyncMock(return_value={"id": 123, "message": "Created"})
    setattr(api, ENDPOINT, endpoint)
    monkeypatch.setattr(server, "IssuesApi", lambda client: api)

    async def with_client(
        fn: Callable[[object], Awaitable[IdAndMessageResponse]],
    ) -> IdAndMessageResponse:
        return await fn(object())

    monkeypatch.setattr(server, "_with_api_client", with_client)
    result = await server.create_draft_issue(1, 10, issue)
    assert result.id == 123
    endpoint.assert_awaited_once()
    assert len(api.mock_calls) == 1
    args = endpoint.call_args.kwargs
    assert args["organization_id"] == 1
    assert args["project_id"] == 10
    assert args["issue_info_base_complete"].to_dict() == issue.model_dump()


@pytest.mark.asyncio
async def test_surface_and_rejection(
    monkeypatch: pytest.MonkeyPatch, issue: DraftIssueInput
) -> None:
    assert not server._is_tool_registered("create_draft_issue")
    server._set_draft_issue_creation_enabled(True)
    network = AsyncMock()
    monkeypatch.setattr(server, "_with_api_client", network)
    async with Client(server.mcp) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools.tools}
        assert "create_draft_issue" in names
        assert not any(n.startswith(("publish_", "share_", "update_issue")) for n in names)
        result = await client.call_tool(
            "create_draft_issue",
            {
                "organization_id": 1,
                "project_id": 10,
                "issue_input": {**issue.model_dump(), "status": "Open"},
            },
        )
        assert result.is_error
    network.assert_not_called()


@pytest.mark.asyncio
async def test_error_sanitization(
    monkeypatch: pytest.MonkeyPatch, issue: DraftIssueInput, caplog: pytest.LogCaptureFixture
) -> None:
    server._set_draft_issue_creation_enabled(True)
    monkeypatch.setattr(server, "_with_api_client", AsyncMock(side_effect=ValueError("SECRET")))
    with pytest.raises(ToolError) as error:
        await server.create_draft_issue(1, 10, issue)
    assert "SECRET" not in str(error.value)
    assert "PRIVATE_DESCRIPTION" not in caplog.text


def test_capability_config_and_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    from pathlib import Path

    from audithub_mcp.config import (
        AuditHubInputConfig,
        CapabilitiesConfig,
        load_config_from_path,
        update_input_config_from_env,
    )

    assert not CapabilitiesConfig().draft_issue_creation
    config = AuditHubInputConfig.model_construct(capabilities=CapabilitiesConfig())
    monkeypatch.setenv("AH_ENABLE_DRAFT_ISSUE_CREATION", "true")
    update_input_config_from_env(config)
    assert config.capabilities.draft_issue_creation
    monkeypatch.setenv("AH_ENABLE_DRAFT_ISSUE_CREATION", "false")
    update_input_config_from_env(config)
    assert not config.capabilities.draft_issue_creation
    settings = load_config_from_path(Path("tests/dummy_config.yaml"))
    assert not settings.draft_issue_creation_enabled
    args = server._build_arg_parser().parse_args(["--enable-draft-issue-creation"])
    assert server._apply_cli_args_to_config(settings, args).draft_issue_creation_enabled
