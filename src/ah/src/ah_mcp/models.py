"""Pydantic response models for the AuditHub REST API v1.

Derived from the OpenAPI specification at:
  https://audithub.veridise.com/api/v1/openapi.json
  (snapshot: openapi.audithub.v1.json, 2026-02-27)

These models are used to validate and type all tool responses in server.py.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, model_validator
from pydantic.networks import UrlConstraints

#: URL type restricted to HTTPS only.  Rejects file://, javascript:, and other
#: non-HTTPS schemes that could act as SSRF gadgets when followed by an agent.
_HttpsUrl = Annotated[AnyUrl, UrlConstraints(allowed_schemes=["https"])]

# ---------------------------------------------------------------------------
# Shared building blocks
# ---------------------------------------------------------------------------


class EnvVar(BaseModel):
    name: str
    value: str


class GitInput(BaseModel):
    input_type: Literal["git"] = "git"
    url: str
    includes_submodules: bool | None = False
    revision: str | None = None


class ArchiveInput(BaseModel):
    input_type: Literal["archive"] = "archive"
    url: str | None = None


#: Discriminated union for project / version input sources.
InputInfo = Annotated[GitInput | ArchiveInput, Field(discriminator="input_type")]

BuildSystem = Literal["hardhat", "hardhat-ignition", "foundry"]
ContentKind = Literal["circom", "solidity", "picus", "llzk"]


# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------


class Organization(BaseModel):
    id: int
    name: str
    gh_connected: bool
    support_channel: str | None = None
    user_limit: int | None = None


# ---------------------------------------------------------------------------
# Project
# ---------------------------------------------------------------------------


class NPMProjectDependency(BaseModel):
    tool: Literal["npm", "yarn", "pnpm"]
    lockfile: bool
    node_version: str | None = None


class ProjectDependency(BaseModel):
    npm: NPMProjectDependency | None = None
    foundry: bool | None = False


class Project(BaseModel):
    id: int
    name: str
    project_root: str
    src_path: str
    created_at: datetime
    input_info: InputInfo
    env_vars: list[EnvVar] = []
    dependencies: ProjectDependency | None = None
    build_system: BuildSystem | None = None
    contents: list[ContentKind] | None = None
    include_path: str | None = None
    specs_path: str | None = None
    hints_path: str | None = None
    deployment_script_path: str | None = None


# ---------------------------------------------------------------------------
# Version (with archive catalog tree)
# ---------------------------------------------------------------------------


class File(BaseModel):
    name: str
    type: Literal["f"] = "f"
    size: int


# Forward reference: Directory.contents holds File | Directory entries.
class Directory(BaseModel):
    name: str
    type: Literal["d"] = "d"
    contents: list[File | Directory] = []


Directory.model_rebuild()  # resolve the forward reference


class Version(BaseModel):
    id: int
    name: str
    created_at: datetime
    project_revision_hash: str
    digest: str | None = None
    commit_hash: str | None = None
    input_info: InputInfo
    archive_catalog: Directory | None = None
    # archive_abi items are untyped in the OpenAPI spec (items: {})
    archive_abi: list[object] | None = None


# ---------------------------------------------------------------------------
# Task
# ---------------------------------------------------------------------------

TaskStatus = Literal[
    "Queued", "Running", "Finished", "Failed", "Error",
    "Canceled", "Pending", "Succeeded", "Skipped", "Omitted",
]


class StepDefinition(BaseModel):
    caption: str
    short_name: str
    is_tool: bool = False


class TaskStep(BaseModel):
    code: str = Field(description="Step code; pass this value as step_code to get_task_logs.")
    definition: StepDefinition
    status: TaskStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    exit_code: int | None = None
    error_message: str | None = None
    completed_without_timeout: bool | None = None  # API may omit for in-progress steps
    findings_counters: dict[str, int] | None = None


class Artifact(BaseModel):
    id: str
    name: str
    step_code: str
    mime_type: str
    is_fio: bool
    presigned_url: _HttpsUrl | None = Field(
        None, description="Time-limited pre-signed URL for downloading the artifact."
    )


class Task(BaseModel):
    id: int
    tool_name: str
    tool_version: str
    version_id: int
    status: TaskStatus
    created_at: datetime
    name: str | None = None
    tool_parameters: str | None = None
    tool_extra: str | None = None
    steps: list[TaskStep] | None = None
    info_text: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    artifacts: list[Artifact] | None = None
    findings_counters: dict[str, int] | None = None


# ---------------------------------------------------------------------------
# Comment
# ---------------------------------------------------------------------------


class Comment(BaseModel):
    id: int
    project_id: int
    thread_id: int
    data: str | None = None
    created_at: datetime
    created_by: str
    is_modified: bool
    is_deleted: bool
    version_id: int | None = None
    system_generated: bool | None = None


# ---------------------------------------------------------------------------
# Thread (discriminated-union subject)
# ---------------------------------------------------------------------------


class FileThreadSubject(BaseModel):
    type: Literal["file_range"] = "file_range"
    file_path: str
    from_line: int
    to_line: int


class FindingThreadSubject(BaseModel):
    type: Literal["finding"] = "finding"
    task_id: int
    analysis_result_id: str
    finding_id: str


class IssueThreadSubject(BaseModel):
    type: Literal["issue"] = "issue"
    issue_id: int


class ProjectThreadSubject(BaseModel):
    type: Literal["project"] = "project"


ThreadSubject = Annotated[
    FileThreadSubject | FindingThreadSubject | IssueThreadSubject | ProjectThreadSubject,
    Field(discriminator="type"),
]

ThreadType = Literal["note", "question", "potential_finding", "issue"]


class Thread(BaseModel):
    id: int
    project_id: int
    type: ThreadType
    subject: ThreadSubject
    created_at: datetime
    created_by: str
    resolved: bool = False
    version_id: int | None = None
    title: str | None = None
    resolved_at: datetime | None = None
    resolved_by: str | None = None


# ---------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------


class IssueResolution(BaseModel):
    resolution_pr: str | None = None
    resolution_commit: str | None = None


class SourceReference(BaseModel):
    version_id: int
    relative_path: str
    line_from: int | None = None
    line_to: int | None = None


class FindingReference(BaseModel):
    task_id: int
    analysis_result_id: str
    finding_id: str


class IssueForList(BaseModel):
    id: int
    title: str
    status: str
    likelihood: int = Field(description="Likelihood score 1–5 where 5 is most likely.")
    impact: int = Field(description="Impact score 1–5 where 5 is highest impact.")
    severity: int = Field(description="Severity score 1–5 where 5 is most severe.")
    internally_shared: bool
    externally_shared: bool
    created_at: datetime
    last_updated_at: datetime
    gh_issue_url: str | None = None
    gh_security_advisory_url: str | None = None


class ExtraFunctionArguments(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    comments: str | None = None
    pr: _HttpsUrl | None = Field(None, alias="PR")
    commit: str | None = None


class IssueStateTransitionFunction(BaseModel):
    id: int
    code: str
    caption: str
    has_comment: bool
    has_pr: bool
    optional_comment: bool
    pre_populated_extra: ExtraFunctionArguments | None
    available_to_developers: bool


class IssueBase(BaseModel):
    """Shared fields for Issue and IssueComplete."""

    id: int
    title: str
    status: str
    description: str
    likelihood: int = Field(description="Likelihood score 1–5 where 5 is most likely.")
    impact: int = Field(description="Impact score 1–5 where 5 is highest impact.")
    severity: int = Field(description="Severity score 1–5 where 5 is most severe.")
    revision_id: int
    affected_files: list[SourceReference]
    type: list[int]
    gh_issue_url: str | None = None
    gh_security_advisory_url: str | None = None
    resolutions: list[IssueResolution] = []


class Issue(IssueBase):
    """Public issue view — subset of fields available without full access."""


class IssueComplete(IssueBase):
    """Full issue view including audit metadata, available to authorized users."""

    created_at: datetime
    last_updated_at: datetime
    created_by: str
    last_updated_by: str
    internally_shared: bool
    externally_shared: bool
    promoted_findings: list[FindingReference] = []
    candidate_for_tool: list[int] = []
    raised_by: list[str]
    poc_author: list[str] = []
    document_authors: list[str] = []


class IssueDetails(BaseModel):
    kind: Literal["public", "complete"]
    data: Issue | IssueComplete
    functions: list[IssueStateTransitionFunction] = []

    @model_validator(mode="before")
    @classmethod
    def _parse_data_by_kind(cls, values: Any) -> Any:
        """Select Issue or IssueComplete based on the kind discriminator."""
        if not isinstance(values, dict):
            raise ValueError(
                f"IssueDetails expected a dict input, got {type(values).__name__!r}"
            )
        kind = values.get("kind")
        data = values.get("data")
        if data is None:
            raise ValueError("IssueDetails requires a 'data' field")
        if kind not in ("public", "complete"):
            raise ValueError(
                f"Unknown IssueDetails kind {kind!r}; expected 'public' or 'complete'"
            )
        values["data"] = (IssueComplete if kind == "complete" else Issue).model_validate(data)
        return values
