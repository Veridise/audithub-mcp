"""MCP and SDK boundary tests for project creation."""

import base64
import json
import logging
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qsl
from zipfile import ZipFile

import httpx
import pytest
from audithub_sdk.models.project_info_input import ProjectInfoInput
from mcp.client import Client
from mcp.server.mcpserver.exceptions import ToolError

from audithub_mcp import server
from audithub_mcp.config import StartupConfigError, load_config_from_path, validate_startup_config
from audithub_mcp.models import ProjectGitSource

pytestmark = pytest.mark.usefixtures("org_write_scope")


@pytest.fixture
def project_api(audithub_http: Mock) -> Mock:
    server._set_project_creation_enabled(True)
    return audithub_http


async def test_registration_requires_project_creation() -> None:
    async with Client(server.mcp) as client:
        assert "create_project" not in {tool.name for tool in (await client.list_tools()).tools}
        server._set_task_runs_enabled(True)
        assert "create_project" not in {tool.name for tool in (await client.list_tools()).tools}
        server._set_task_runs_enabled(False)

        server._set_project_creation_enabled(True)
        assert "create_project" in {tool.name for tool in (await client.list_tools()).tools}


@pytest.mark.parametrize("enabled,org", [(False, 1), (True, 2), (True, 3)])
async def test_write_gates_precede_authentication(
    monkeypatch: pytest.MonkeyPatch, enabled: bool, org: int
) -> None:
    network = AsyncMock()
    monkeypatch.setattr(server, "_with_api_client", network)
    server._set_project_creation_enabled(enabled)
    with pytest.raises(ToolError):
        await server.create_project(org, "Example", archive="/unread.zip")
    network.assert_not_called()


@pytest.mark.parametrize(
    "arguments",
    [
        {"organization_id": True, "name": "Example"},
        {"organization_id": 1, "name": "  "},
        {"organization_id": 1, "name": "Example", "src_path": "../outside"},
    ],
)
async def test_invalid_inputs_precede_network(
    monkeypatch: pytest.MonkeyPatch, arguments: dict[str, object]
) -> None:
    server._set_project_creation_enabled(True)
    network = AsyncMock()
    monkeypatch.setattr(server, "_with_api_client", network)
    async with Client(server.mcp) as client:
        assert (await client.call_tool("create_project", arguments)).is_error
    network.assert_not_called()


@pytest.mark.parametrize("forbidden", [False, True])
async def test_sdk_requests_and_remote_authorization(
    project_api: Mock, forbidden: bool, caplog: pytest.LogCaptureFixture
) -> None:
    projects = "/api/v1/organizations/1/projects"
    project_api.return_value = (
        httpx.Response(403, json={"detail": "PRIVATE_DENIAL"})
        if forbidden
        else httpx.Response(200, json={"id": 55, "message": "Created"})
    )
    async with Client(server.mcp) as client:
        project = await client.call_tool(
            "create_project", {"organization_id": 1, "name": "PRIVATE_PROJECT", "src_path": "src"}
        )
    if forbidden:
        assert project.is_error
        assert "403" in str(project.content)
        assert "PRIVATE_DENIAL" not in str(project.content)
    else:
        assert not project.is_error and project.structured_content == {
            "id": 55,
            "message": "Created",
        }
    project_api.assert_called_once()
    request = project_api.call_args.args[0]
    assert request.url.path == projects
    assert request.method == "POST"
    assert request.headers["Authorization"] == "Bearer TEST_TOKEN"
    assert json.loads(request.content) == {
        "name": "PRIVATE_PROJECT",
        "src_path": "src",
        "project_root": ".",
        "input_info": {"input_type": "archive"},
    }
    assert 55 not in server._allowed_project_ids
    for private in ("TEST_TOKEN", "PRIVATE_PROJECT", "PRIVATE_DENIAL"):
        assert private not in caplog.text


def test_write_configuration(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    baseline = Path("tests/dummy_config.yaml").read_text()
    config_path.write_text(baseline + "  project_creation: true\nwritable_org_ids: [1]\n")
    settings = load_config_from_path(config_path)
    assert settings.writable_org_ids == {1} and settings.project_creation_enabled
    # An operator can create the organization's first project with an empty project allowlist.
    validate_startup_config(replace(settings, allowed_project_ids=frozenset()))

    monkeypatch.setenv("AH_WRITABLE_ORG_IDS", "2")
    monkeypatch.setenv("AH_ENABLE_PROJECT_CREATION", "false")
    settings = load_config_from_path(config_path, override_from_env_vars=True)
    assert settings.writable_org_ids == {2} and not settings.project_creation_enabled

    args = server._build_arg_parser().parse_args(
        ["--writable-org-ids", "1", "--enable-project-creation"]
    )
    settings = server._apply_cli_args_to_config(settings, args)
    assert settings.writable_org_ids == {1} and settings.project_creation_enabled
    with pytest.raises(StartupConfigError, match="subset"):
        validate_startup_config(replace(settings, writable_org_ids=frozenset({3})))

    defaults = load_config_from_path(Path("tests/dummy_config.yaml"))
    assert not defaults.writable_org_ids and not defaults.project_creation_enabled


def test_first_project_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "audithub-mcp",
            "--config",
            "tests/dummy_config.yaml",
            "--no-env-config",
            "--enable-project-creation",
            "--writable-org-ids",
            "2",
            "--allowed-project-ids",
            "",
        ],
    )
    monkeypatch.setattr(server, "_context", None)
    monkeypatch.setattr(server.mcp, "run", lambda: None)
    server.main()
    assert server._writable_org_ids == {2}
    assert not server._allowed_project_ids
    assert server._is_tool_registered("create_project")


ORG_PATH = "/api/v1/organizations/1"
STAGED = {
    "id": "17",
    "archive_catalog": {
        "name": ".",
        "type": "d",
        "contents": [{"name": "A.sol", "type": "f", "size": 16}],
    },
}


@pytest.mark.parametrize("method", ["git", "archive_url", "archive_upload", "inline_zip", "staged"])
async def test_create_project_with_sources(
    project_api: Mock, tmp_path: Path, method: str, caplog: pytest.LogCaptureFixture
) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == ORG_PATH + "/projects":
            return httpx.Response(200, json={"id": 55, "message": "Created"})
        return httpx.Response(200, json=STAGED)

    project_api.side_effect = handle
    caplog.set_level(logging.INFO, logger="audithub_mcp.audit")
    settings = {
        "name": "Contracts",
        "project_root": "pkg",
        "src_path": "src",
        "include_path": "lib",
        "specs_path": "specs",
        "hints_path": "hints",
        "build_system": "hardhat-ignition",
        "deployment_script_path": "scripts/deploy.ts",
        "contents": ["circom", "solidity", "picus", "llzk"],
        "env_vars": [{"name": "RPC_KEY", "value": "PRIVATE_ENV_VALUE"}],
        "dependencies": {
            "npm": {"tool": "pnpm", "lockfile": False, "node_version": "22"},
            "foundry": True,
        },
    }
    args: dict[str, object] = {"organization_id": 1, "version_name": "release 1", **settings}
    assert set(ProjectInfoInput.model_fields) == {*settings, "input_info"}
    source: dict[str, object] = {"input_type": "archive"}
    archive = tmp_path / "contracts.zip"
    if method in ("git", "staged"):
        source = {
            "input_type": "git",
            "url": "https://github.com/example/contracts.git",
            "revision": "v1",
            "includes_submodules": True,
        }
        args["input_info"] = source
    elif method == "archive_url":
        source["url"] = "https://example.invalid/contracts.zip"
        args["input_info"] = source
    else:
        with ZipFile(archive, "w") as file:
            file.writestr("A.sol", "contract A {}")
        args["archive"] = (
            {
                "filename": archive.name,
                "content_base64": base64.b64encode(archive.read_bytes()).decode(),
            }
            if method == "inline_zip"
            else str(archive)
        )
    if method == "staged":
        args["temp_version_id"] = "17"
    else:
        args.update(commit_hash="abc123", is_deployed=True)

    async with Client(server.mcp) as client:
        result = await client.call_tool("create_project", args)
    assert not result.is_error, result.content
    assert result.structured_content == {"id": 55, "message": "Created"}
    final = requests[-1]
    assert final.url.path == ORG_PATH + "/projects"
    assert dict(final.url.params) == {"version_name": "release 1", "temp_version_id": "17"}
    assert json.loads(final.content) == {**settings, "input_info": source}
    assert len(requests) == (1 if method == "staged" else 2)
    assert "PRIVATE_ENV_VALUE" not in caplog.text
    assert 55 not in server._allowed_project_ids
    for request in requests:
        assert request.method == "POST"
        assert request.headers["Authorization"] == "Bearer TEST_TOKEN"
    if method in ("git", "archive_url"):
        stage = requests[0]
        assert stage.url.path == ORG_PATH + "/temp-versions-url"
        form = dict(parse_qsl(stage.content.decode()))
        assert form == {
            **source,
            **({"includes_submodules": "true"} if method == "git" else {}),
            "name": "release 1",
            "commit_hash": "abc123",
            "is_deployed": "true",
        }
    elif method in ("archive_upload", "inline_zip"):
        stage = requests[0]
        assert stage.url.path == ORG_PATH + "/temp-versions"
        assert stage.headers["Content-Type"].startswith("multipart/form-data; boundary=")
        assert b'name="archive"; filename="contracts.zip"' in stage.content
        assert b"Content-Type: application/zip" in stage.content
        assert archive.read_bytes() in stage.content
        for key, value in [
            (b"name", b"release 1"),
            (b"commit_hash", b"abc123"),
            (b"is_deployed", b"true"),
        ]:
            assert b'name="' + key + b'"\r\n\r\n' + value in stage.content.lower()


@pytest.mark.parametrize(
    "options",
    [
        {
            "archive": "/unused.zip",
            "input_info": {"input_type": "git", "url": "https://github.com/example/repo"},
        },
        {"archive": "/unused.zip", "temp_version_id": "17"},
        {"temp_version_id": "17", "is_deployed": False},
        {"input_info": {"input_type": "archive", "revision": "main"}},
        {"version_name": "first"},
        {"commit_hash": "abc"},
        {"build_system": "unknown"},
        {"temp_version_id": "0"},
    ],
)
async def test_invalid_project_sources_fail_before_network(
    monkeypatch: pytest.MonkeyPatch, options: dict[str, object]
) -> None:
    server._set_project_creation_enabled(True)
    network = AsyncMock()
    monkeypatch.setattr(server, "_with_api_client", network)
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "create_project", {"organization_id": 1, "name": "P", **options}
        )
    assert result.is_error
    network.assert_not_called()


@pytest.mark.parametrize("fail_stage", [False, True])
async def test_staging_failure_and_resume(
    project_api: Mock, fail_stage: bool, caplog: pytest.LogCaptureFixture
) -> None:
    paths: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if len(paths) == 1 and not fail_stage:
            return httpx.Response(200, json=STAGED)
        if len(paths) == 3:
            return httpx.Response(200, json={"id": 55, "message": "Created"})
        return httpx.Response(403, json={"detail": "PRIVATE_DENIAL"})

    project_api.side_effect = handle
    source = ProjectGitSource(url="https://github.com/example/repo")
    with pytest.raises(ToolError, match="403") as error:
        await server.create_project(1, "P", input_info=source)
    expected = [ORG_PATH + "/temp-versions-url"]
    if not fail_stage:
        assert "temp_version_id=17" in str(error.value)
        result = await server.create_project(1, "P", input_info=source, temp_version_id="17")
        assert result.id == 55
        expected.extend([ORG_PATH + "/projects", ORG_PATH + "/projects"])
    assert paths == expected
    assert "PRIVATE_DENIAL" not in caplog.text and "PRIVATE_DENIAL" not in str(error.value)


@pytest.mark.parametrize("archive", [{"content_base64": "%%%"}, {"content_base64": "aGVsbG8="}])
async def test_invalid_zip_uploads_stop_before_post(
    project_api: Mock, archive: dict[str, str]
) -> None:
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "create_project", {"organization_id": 1, "name": "P", "archive": archive}
        )
    assert result.is_error and "ZIP" in str(result.content)
    project_api.assert_not_called()
