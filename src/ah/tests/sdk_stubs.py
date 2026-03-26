"""Helpers for stubbing the AuditHub SDK in tests."""

from __future__ import annotations

import sys
import types
from typing import Any

from pydantic import BaseModel, ConfigDict


class _BaseSdkModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class Organization(_BaseSdkModel):
    id: int
    name: str
    gh_connected: bool


class Project(_BaseSdkModel):
    id: int
    name: str


class Version(_BaseSdkModel):
    id: int
    name: str


class Task(_BaseSdkModel):
    id: int
    status: str


class Comment(_BaseSdkModel):
    id: int
    project_id: int
    thread_id: int


class Thread(_BaseSdkModel):
    id: int
    project_id: int
    type: str
    subject: dict[str, Any]


class IssueForList(_BaseSdkModel):
    id: int
    title: str


class IssueDetails(_BaseSdkModel):
    kind: str
    data: dict[str, Any]


class Configuration:
    def __init__(self, *, host: str) -> None:
        self.host = host


class OIDCClientCredentialsContext:
    def __init__(
        self,
        *,
        oidc_configuration_url: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        self.oidc_configuration_url = oidc_configuration_url
        self.client_id = client_id
        self.client_secret = client_secret


class AuthenticatedApiClient:
    def __init__(self, configuration: Configuration, *, auth_context: OIDCClientCredentialsContext):
        self.configuration = configuration
        self.auth_context = auth_context

    async def __aenter__(self) -> AuthenticatedApiClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _ApiBase:
    def __init__(self, api_client: AuthenticatedApiClient) -> None:
        self.api_client = api_client


class UsersApi(_ApiBase):
    async def get_organizations_users_myorganizations_get(self) -> list[Organization]:
        raise NotImplementedError


class ProjectsApi(_ApiBase):
    async def get_project_organizations_organization_id_projects_project_id_get(self, **kwargs):
        raise NotImplementedError

    async def get_project_comments_organizations_organization_id_projects_project_id_comments_get(
        self, **kwargs
    ):
        raise NotImplementedError


class VersionsApi(_ApiBase):
    async def get_latest_version_organizations_organization_id_projects_project_id_versions_latest_get(  # noqa: E501
        self, **kwargs
    ):
        raise NotImplementedError

    async def get_version_comments_organizations_organization_id_projects_project_id_versions_version_id_comments_get(  # noqa: E501
        self, **kwargs
    ):
        raise NotImplementedError

    async def get_version_comment_threads_organizations_organization_id_projects_project_id_versions_version_id_comment_threads_get(  # noqa: E501
        self, **kwargs
    ):
        raise NotImplementedError


class IssuesApi(_ApiBase):
    async def get_issues_organizations_organization_id_projects_project_id_issues_get(
        self, **kwargs
    ):
        raise NotImplementedError

    async def get_issue_organizations_organization_id_projects_project_id_issues_issue_id_get(
        self, **kwargs
    ):
        raise NotImplementedError


class TasksApi(_ApiBase):
    async def get_info_organizations_organization_id_tasks_task_id_get(self, **kwargs):
        raise NotImplementedError

    async def get_output_organizations_organization_id_tasks_task_id_step_code_output_get(
        self, **kwargs
    ):
        raise NotImplementedError


def _module(name: str) -> types.ModuleType:
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    return mod


def install_sdk_stubs() -> None:
    """Install minimal SDK stub modules for unit tests."""
    sdk = _module("audithub_sdk")
    sdk.Configuration = Configuration

    _module("audithub_sdk.api")
    users_api = _module("audithub_sdk.api.users_api")
    users_api.UsersApi = UsersApi
    projects_api = _module("audithub_sdk.api.projects_api")
    projects_api.ProjectsApi = ProjectsApi
    versions_api = _module("audithub_sdk.api.versions_api")
    versions_api.VersionsApi = VersionsApi
    issues_api = _module("audithub_sdk.api.issues_api")
    issues_api.IssuesApi = IssuesApi
    tasks_api = _module("audithub_sdk.api.tasks_api")
    tasks_api.TasksApi = TasksApi

    _module("audithub_sdk.models")
    for name, cls in (
        ("organization", Organization),
        ("project", Project),
        ("version", Version),
        ("task", Task),
        ("comment", Comment),
        ("thread", Thread),
        ("issue_for_list", IssueForList),
        ("issue_details", IssueDetails),
    ):
        mod = _module(f"audithub_sdk.models.{name}")
        setattr(mod, cls.__name__, cls)

    sdk_ext = _module("audithub_sdk_ext")
    sdk_ext.AuthenticatedApiClient = AuthenticatedApiClient
    sdk_ext.OIDCClientCredentialsContext = OIDCClientCredentialsContext
