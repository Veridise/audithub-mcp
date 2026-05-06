"""SDK-backed AuditHub models and MCP-specific response types."""

from typing import Annotated, Literal

from audithub_sdk.models.comment import Comment
from audithub_sdk.models.fio_data import FIOData
from audithub_sdk.models.issue_details import IssueDetails
from audithub_sdk.models.issue_for_list import IssueForList
from audithub_sdk.models.my_organization import MyOrganization
from audithub_sdk.models.project import Project
from audithub_sdk.models.task import Task
from audithub_sdk.models.task_creation import TaskCreation
from audithub_sdk.models.thread import Thread
from audithub_sdk.models.version import Version
from pydantic import BaseModel, ConfigDict, Field

_PositiveId = Annotated[int, Field(strict=True, gt=0)]


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


class VersionFromUrlInput(BaseModel):
    """Input payload for creating an AuditHub project version from a source URL."""

    model_config = ConfigDict(frozen=True)

    name: Annotated[str, Field(min_length=1)]
    input_type: Literal["archive", "git"]
    url: Annotated[str, Field(min_length=1)]
    commit_hash: str | None = None
    is_deployed: bool | None = False
    revision: str | None = None
    includes_submodules: bool | None = None


class VersionCreation(BaseModel):
    """Response returned after an AuditHub version creation request."""

    model_config = ConfigDict(frozen=True)

    id: _PositiveId
    message: str


class OrCaVersionSpecReference(BaseModel):
    """OrCa V spec reference to a file inside the project version archive."""

    model_config = ConfigDict(frozen=True)

    type: Literal["version"] = "version"
    relative_path: str


class OrCaStandardLibrarySpecReference(BaseModel):
    """OrCa V spec reference to AuditHub's standard library."""

    model_config = ConfigDict(frozen=True)

    type: Literal["stdlib"] = "stdlib"
    category: str
    name: str
    library_version: str | None = None


class OrCaOrganizationLibrarySpecReference(BaseModel):
    """OrCa V spec reference to an organization library entry."""

    model_config = ConfigDict(frozen=True)

    type: Literal["orglib"] = "orglib"
    id: _PositiveId


class OrCaAdHocSpecReference(BaseModel):
    """Inline OrCa V spec reference."""

    model_config = ConfigDict(frozen=True)

    type: Literal["adhoc"] = "adhoc"
    filename: str
    contents: str
    encoding: Literal["plain"] = "plain"


OrCaSpecReference = Annotated[
    OrCaVersionSpecReference
    | OrCaStandardLibrarySpecReference
    | OrCaOrganizationLibrarySpecReference
    | OrCaAdHocSpecReference,
    Field(discriminator="type"),
]


class OrCaVersionHintReference(BaseModel):
    """OrCa hint reference to a file inside the project version archive."""

    model_config = ConfigDict(frozen=True)

    type: Literal["version"] = "version"
    relative_path: str


class OrCaStandardLibraryHintReference(BaseModel):
    """OrCa hint reference to AuditHub's standard library."""

    model_config = ConfigDict(frozen=True)

    type: Literal["stdlib"] = "stdlib"
    category: str
    name: str
    library_version: str | None = None


class OrCaOrganizationLibraryHintReference(BaseModel):
    """OrCa hint reference to an organization library entry."""

    model_config = ConfigDict(frozen=True)

    type: Literal["orglib"] = "orglib"
    id: _PositiveId


class OrCaAdHocHintReference(BaseModel):
    """Inline OrCa hint reference."""

    model_config = ConfigDict(frozen=True)

    type: Literal["adhoc"] = "adhoc"
    filename: str
    contents: str
    encoding: Literal["plain"] = "plain"


OrCaHintReference = Annotated[
    OrCaVersionHintReference
    | OrCaStandardLibraryHintReference
    | OrCaOrganizationLibraryHintReference
    | OrCaAdHocHintReference,
    Field(discriminator="type"),
]


class OrCaFuzzingBlacklistEntry(BaseModel):
    """Function-level OrCa fuzzing blacklist entry."""

    model_config = ConfigDict(frozen=True)

    contract: str
    function: str


class OrCaParametersInput(BaseModel):
    """Parameters passed to an OrCa task."""

    model_config = ConfigDict(frozen=True)

    disable_user_proxies: bool | None = None
    fuzz_pure: bool | None = None
    fuzz_targets: list[str] | None = None
    fuzzing_blacklist: list[OrCaFuzzingBlacklistEntry] | None = None
    language: str | None = "solidity"
    timeout: Annotated[int, Field(strict=True, gt=0)] | None = 600
    fork_network: str | None = None
    fork_block_number: Annotated[int, Field(strict=True, ge=0)] | None = None


class OrCaTaskInput(BaseModel):
    """Input payload for launching an OrCa task."""

    model_config = ConfigDict(frozen=True)

    specs_override: Annotated[list[OrCaSpecReference], Field(min_length=1)]
    hints_override: list[OrCaHintReference] | None = None
    deployment_script_path_override: str | None = None
    on_chain: bool | None = False
    deployment_info_file: str | None = None
    auxiliary_deployment_script: str | None = None
    name: str | None = None
    parameters: OrCaParametersInput = Field(default_factory=OrCaParametersInput)

__all__ = [
    "Comment",
    "FIOData",
    "IssueDetails",
    "IssueForList",
    "MyOrganization",
    "OrCaAdHocHintReference",
    "OrCaAdHocSpecReference",
    "OrCaFuzzingBlacklistEntry",
    "OrCaHintReference",
    "OrCaOrganizationLibraryHintReference",
    "OrCaOrganizationLibrarySpecReference",
    "OrCaParametersInput",
    "OrCaSpecReference",
    "OrCaStandardLibraryHintReference",
    "OrCaStandardLibrarySpecReference",
    "OrCaTaskInput",
    "OrCaVersionHintReference",
    "OrCaVersionSpecReference",
    "OrganizationNameIndexEntry",
    "Project",
    "ProjectNameIndexEntry",
    "Task",
    "TaskCreation",
    "Thread",
    "Version",
    "VersionNameIndexEntry",
]
