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
from pydantic import BaseModel, ConfigDict, Field, model_validator

_PositiveId = Annotated[int, Field(strict=True, gt=0)]


class OrganizationNameIndexEntry(BaseModel):
    """Name lookup entry for an allowlisted AuditHub organization."""

    model_config = ConfigDict(frozen=True)

    id: int
    name: str
    sort_key: str


class ProjectNameIndexEntry(BaseModel):
    """Name lookup entry for an allowlisted AuditHub project."""

    model_config = ConfigDict(frozen=True)

    id: int
    name: str
    sort_key: str


class VersionNameIndexEntry(BaseModel):
    """Name lookup entry for an allowlisted AuditHub version."""

    model_config = ConfigDict(frozen=True)

    id: int
    name: str
    sort_key: str


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


class VersionFromFileInput(BaseModel):
    """Input payload for creating an AuditHub project version from a .zip archive."""

    model_config = ConfigDict(frozen=True)

    name: Annotated[str, Field(min_length=1)]
    archive: Annotated[str, Field(min_length=1)]
    commit_hash: str | None = None
    is_deployed: bool | None = False


class VersionCreation(BaseModel):
    """Response returned after an AuditHub version creation request."""

    model_config = ConfigDict(frozen=True)

    id: _PositiveId
    message: str


class TaskArtifact(BaseModel):
    """Sanitized metadata for an artifact produced by an AuditHub task."""

    model_config = ConfigDict(frozen=True)

    id: Annotated[str, Field(min_length=1)]
    name: str
    step_code: str
    mime_type: str
    is_fio: bool


class TaskArtifactContent(BaseModel):
    """Base64-encoded content for an AuditHub task artifact."""

    model_config = ConfigDict(frozen=True)

    artifact_id: Annotated[str, Field(min_length=1)]
    content_length: Annotated[int, Field(ge=0)]
    content_base64: str
    content_encoding: Literal["base64"] = "base64"
    content_type: str | None = None


class FindingsParseResult(BaseModel):
    """Summary returned after parsing a task log into findings JSON."""

    model_config = ConfigDict(frozen=True)

    num_findings: Annotated[int, Field(ge=0)]
    num_findings_by_log_file_path: dict[str, Annotated[int, Field(ge=0)]]


DefiVanguardV2DetectorSelectionInput = tuple[
    Literal["builtin", "stdlib", "orglib", "version"],
    str | int,
]


class DefiVanguardV2TaskInput(BaseModel):
    """Input payload for launching a DeFi Vanguard v2 task."""

    model_config = ConfigDict(frozen=True)

    organization_id: Annotated[
        _PositiveId,
        Field(description="AuditHub organization ID to run the Vanguard task against."),
    ]
    project_id: Annotated[
        _PositiveId,
        Field(description="AuditHub project ID to run the Vanguard task against."),
    ]
    version_id: Annotated[
        _PositiveId,
        Field(description="AuditHub version ID to run the Vanguard task against."),
    ]
    detectors: Annotated[
        list[DefiVanguardV2DetectorSelectionInput],
        Field(
            min_length=1,
            description=(
                "Detector selections for the task as two-item `(type, id)` tuples, "
                "corresponding to detector entries from the `get_defi_vanguard_detectors` tool."
            ),
        ),
    ]
    name: Annotated[
        str | None,
        Field(description="Optional display name for the Vanguard task."),
    ] = None
    input_limit: Annotated[
        list[str] | None,
        Field(description="Optional list of paths in the version to limit analysis to."),
    ] = None
    cross_version_triage: Annotated[
        bool,
        Field(
            description=(
                "When true, suppress findings previously discovered for this project "
                "across versions."
            )
        ),
    ] = False
    solc: Annotated[
        str | None,
        Field(
            description=(
                "Optional Solidity compiler version to use for compilation. "
                "Must be one of the builtin Vanguard solc versions from AuditHub "
                "configuration. `None` maps to `latest`."
            )
        ),
    ] = None
    ignore_build_system: Annotated[
        bool,
        Field(
            description="When true, compile without using the project's build system.",
        ),
    ] = False


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
    deployment_script_path_override: str | None = Field(
        default=None,
        description="Optional deployment script path for source-based OrCa runs.",
    )
    on_chain: bool | None = Field(
        default=False,
        description=(
            "Enable on-chain OrCa fuzzing. Prefer setting deployment_info_file to a "
            "path ending in .deployment.json; the server will normalize that to "
            "on_chain=True."
        ),
    )
    deployment_info_file: str | None = Field(
        default=None,
        description=(
            "Path to a .deployment.json file containing deployed_contract_information "
            "for on-chain fuzzing."
        ),
    )
    auxiliary_deployment_script: str | None = None
    name: str | None = None
    parameters: OrCaParametersInput = Field(default_factory=OrCaParametersInput)

    @model_validator(mode="before")
    @classmethod
    def _normalize_on_chain_mode(cls, data: object) -> object:
        """Normalize and validate the on-chain OrCa task settings."""
        if not isinstance(data, dict):
            return data
        deployment_info_file = data.get("deployment_info_file")
        on_chain = data.get("on_chain")
        if deployment_info_file is not None and not deployment_info_file.endswith(
            ".deployment.json"
        ):
            raise ValueError(
                "deployment_info_file must end with .deployment.json for on-chain fuzzing."
            )
        if deployment_info_file is not None and on_chain is not True:
            normalized = dict(data)
            normalized["on_chain"] = True
            return normalized
        if on_chain is True and deployment_info_file is None:
            raise ValueError(
                "on_chain=True requires deployment_info_file to point to a .deployment.json file."
            )
        return data


__all__ = [
    "Comment",
    "DefiVanguardV2DetectorSelectionInput",
    "DefiVanguardV2TaskInput",
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
    "TaskArtifact",
    "TaskArtifactContent",
    "TaskCreation",
    "FindingsParseResult",
    "Thread",
    "Version",
    "VersionFromFileInput",
    "VersionNameIndexEntry",
]
