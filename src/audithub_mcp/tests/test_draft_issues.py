"""Draft-only creation boundary tests."""

from collections.abc import Awaitable, Callable, Iterator
from unittest.mock import AsyncMock, MagicMock, call

import pytest
from audithub_sdk.models.id_and_message_response import IdAndMessageResponse
from audithub_sdk.models.issue_type_info import IssueTypeInfo
from audithub_sdk.models.source_reference import SourceReference
from mcp.client import Client
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import ValidationError

from audithub_mcp import server
from audithub_mcp.models import DraftIssueInput, IssueTypeReference

ENDPOINT = "post_issue_organizations_organization_id_projects_project_id_issues_post"
LIST_TYPES = "get_organization_issue_types_organizations_organization_id_issue_types_get"
CREATE_TYPE = "post_issue_type_organizations_organization_id_issue_types_post"


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
        await server.create_draft_issue(
            org, project, issue.model_copy(update={"type": ["New type"]})
        )
    network.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("types", [[], [1, 2]])
async def test_creation_calls_only_creation_endpoint(
    monkeypatch: pytest.MonkeyPatch, issue: DraftIssueInput, types: list[int]
) -> None:
    issue = issue.model_copy(update={"type": types})
    server._set_draft_issue_creation_enabled(True)
    api = MagicMock()
    endpoint = AsyncMock(return_value={"id": 123, "message": "Created"})
    setattr(api, ENDPOINT, endpoint)
    monkeypatch.setattr(server, "IssuesApi", lambda client: api)
    organization_api = MagicMock()
    monkeypatch.setattr(server, "OrganizationsApi", organization_api)

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
    organization_api.assert_not_called()


@pytest.fixture
def issue_api(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    server._set_draft_issue_creation_enabled(True)
    api = MagicMock()
    setattr(api, ENDPOINT, AsyncMock(return_value={"id": 123, "message": "Created"}))
    setattr(
        api,
        LIST_TYPES,
        AsyncMock(
            return_value=[{"id": 7, "caption": "Existing", "is_organization_specific": False}]
        ),
    )
    setattr(
        api,
        CREATE_TYPE,
        AsyncMock(side_effect=[{"id": 8, "message": "Created"}, {"id": 9, "message": "Created"}]),
    )
    monkeypatch.setattr(server, "IssuesApi", lambda client: api)
    monkeypatch.setattr(server, "OrganizationsApi", lambda client: api)

    async def with_client(
        fn: Callable[[object], Awaitable[IdAndMessageResponse]],
    ) -> IdAndMessageResponse:
        return await fn(object())

    monkeypatch.setattr(server, "_with_api_client", with_client)
    return api


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "types,expected_ids,new_names",
    [
        (["Existing"], [7], []),
        (["New"], [8], ["New"]),
        ([1, "Existing", " New ", "New", "Another"], [1, 7, 8, 8, 9], ["New", "Another"]),
        (["existing"], [8], ["existing"]),
        (["42"], [8], ["42"]),
    ],
)
async def test_resolves_issue_type_names_before_creation(
    issue_api: MagicMock,
    issue: DraftIssueInput,
    types: list[IssueTypeReference],
    expected_ids: list[int],
    new_names: list[str],
) -> None:
    issue = DraftIssueInput.model_validate({**issue.model_dump(), "type": types})
    result = await server.create_draft_issue(1, 10, issue)
    assert result.id == 123
    endpoint = getattr(issue_api, ENDPOINT)
    payload = endpoint.call_args.kwargs["issue_info_base_complete"]
    assert payload.to_dict() == {**issue.model_dump(), "type": expected_ids}
    assert issue_api.mock_calls == [
        getattr(call, LIST_TYPES)(organization_id=1),
        *[
            getattr(call, CREATE_TYPE)(
                organization_id=1, issue_type_info=IssueTypeInfo(caption=name)
            )
            for name in new_names
        ],
        getattr(call, ENDPOINT)(organization_id=1, project_id=10, issue_info_base_complete=payload),
    ]


@pytest.mark.parametrize("name", ["", " ", "\t\n"])
def test_rejects_blank_issue_type_names(issue: DraftIssueInput, name: str) -> None:
    with pytest.raises(ValidationError):
        DraftIssueInput.model_validate({**issue.model_dump(), "type": [name]})


@pytest.mark.asyncio
@pytest.mark.parametrize("failing_endpoint", [LIST_TYPES, CREATE_TYPE, ENDPOINT])
async def test_issue_type_failure_stops_creation_and_sanitizes_errors(
    issue_api: MagicMock,
    issue: DraftIssueInput,
    failing_endpoint: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    getattr(issue_api, failing_endpoint).side_effect = ValueError("SECRET")
    issue = issue.model_copy(update={"type": ["PRIVATE_TYPE"]})
    with pytest.raises(ToolError) as error:
        await server.create_draft_issue(1, 10, issue)
    if failing_endpoint != ENDPOINT:
        getattr(issue_api, ENDPOINT).assert_not_called()
    if failing_endpoint == LIST_TYPES:
        getattr(issue_api, CREATE_TYPE).assert_not_called()
    for private_text in ("SECRET", "PRIVATE_TYPE", "PRIVATE_DESCRIPTION"):
        assert private_text not in str(error.value)
        assert private_text not in caplog.text


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
