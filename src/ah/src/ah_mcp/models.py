"""SDK-backed AuditHub models and MCP-specific response types."""

from audithub_sdk.models.comment import Comment
from audithub_sdk.models.fio_data import FIOData
from audithub_sdk.models.issue_details import IssueDetails
from audithub_sdk.models.issue_for_list import IssueForList
from audithub_sdk.models.organization import Organization
from audithub_sdk.models.project import Project
from audithub_sdk.models.task import Task
from audithub_sdk.models.thread import Thread
from audithub_sdk.models.version import Version
from pydantic import BaseModel, ConfigDict


class OrganizationNameIndexEntry(BaseModel):
    """Name lookup entry for an allowlisted AuditHub organization."""

    model_config = ConfigDict(frozen=True)

    id: int
    name: str
    lookup_key: str


class ProjectNameIndexEntry(BaseModel):
    """Name lookup entry for an allowlisted AuditHub project."""

    model_config = ConfigDict(frozen=True)

    id: int
    name: str
    lookup_key: str


class VersionNameIndexEntry(BaseModel):
    """Name lookup entry for an allowlisted AuditHub version."""

    model_config = ConfigDict(frozen=True)

    id: int
    name: str
    lookup_key: str

__all__ = [
    "Comment",
    "FIOData",
    "IssueDetails",
    "IssueForList",
    "Organization",
    "OrganizationNameIndexEntry",
    "Project",
    "ProjectNameIndexEntry",
    "Task",
    "Thread",
    "Version",
    "VersionNameIndexEntry",
]
