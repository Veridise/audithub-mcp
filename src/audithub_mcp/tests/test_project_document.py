from unittest.mock import AsyncMock, MagicMock, call

import pytest
from audithub_sdk.api.project_documents_api import ProjectDocumentsApi
from audithub_sdk.models.project_document import ProjectDocument
from mcp.client import Client
from mcp.server.mcpserver.exceptions import ToolError

from audithub_mcp import server


@pytest.fixture(autouse=True)
def scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "_allowed_org_ids", frozenset({1}))
    monkeypatch.setattr(server, "_allowed_project_ids", frozenset({10}))


async def test_get_project_document_returns_text_over_mcp(monkeypatch: pytest.MonkeyPatch) -> None:
    texts = ["# Notes\n\nDocument contents.", "Other document"]
    endpoint = AsyncMock(side_effect=[ProjectDocument.model_construct(data=t) for t in texts])
    monkeypatch.setattr(
        ProjectDocumentsApi,
        "get_document_organizations_organization_id_projects_project_id_documents_document_id_get",
        endpoint,
    )
    monkeypatch.setattr(server, "_ctx", MagicMock())
    monkeypatch.setattr(server, "AuthenticatedApiClient", MagicMock())
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "get_project_document", {"organization_id": 1, "project_id": 10, "document_ids": [7, 3]}
        )
    assert not result.is_error
    assert result.structured_content == {"result": texts}
    assert endpoint.await_args_list == [
        call(organization_id=1, project_id=10, document_id=i) for i in [7, 3]
    ]


@pytest.mark.parametrize("org,project", [(2, 10), (1, 20)])
async def test_denied_document_skips_sdk(
    monkeypatch: pytest.MonkeyPatch, org: int, project: int
) -> None:
    sdk = AsyncMock()
    monkeypatch.setattr(server, "_with_api_client", sdk)
    with pytest.raises(ToolError):
        await server.get_project_document(org, project, [7])
    with pytest.raises(ToolError):
        await server.get_project_documents(org, project)
    with pytest.raises(ToolError):
        await server.get_all_project_documents(org, project)
    sdk.assert_not_called()


@pytest.mark.parametrize("tool_name", ["get_project_documents", "get_all_project_documents"])
@pytest.mark.parametrize("names", [[], ["architecture.md", "notes.md"]])
async def test_get_project_documents_over_mcp(
    monkeypatch: pytest.MonkeyPatch, names: list[str], tool_name: str
) -> None:
    documents = [
        ProjectDocument.model_validate(
            {
                "id": i,
                "project_id": 10,
                "name": name,
                "data": f"Contents of {name}",
                "created_at": "2026-01-01T00:00:00Z",
                "created_by": "author",
                "is_deleted": False,
            }
        )
        for i, name in enumerate(names, start=1)
    ]
    endpoint = AsyncMock(return_value=documents)
    monkeypatch.setattr(
        ProjectDocumentsApi,
        "get_documents_organizations_organization_id_projects_project_id_documents_get",
        endpoint,
    )
    monkeypatch.setattr(server, "_ctx", MagicMock())
    monkeypatch.setattr(server, "AuthenticatedApiClient", MagicMock())
    async with Client(server.mcp) as client:
        result = await client.call_tool(tool_name, {"organization_id": 1, "project_id": 10})
    assert not result.is_error
    assert result.structured_content == {"result": [d.model_dump(mode="json") for d in documents]}
    endpoint.assert_awaited_once_with(organization_id=1, project_id=10)
