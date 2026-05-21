"""Configuration types and environment parsing for the AuditHub MCP server."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import audithub_sdk
import yaml
from audithub_sdk_ext import OIDCClientCredentialsContext
from pydantic import BaseModel, Field, SecretStr, field_validator

_AhId = Annotated[int, Field(strict=True, gt=0)]
_ArtifactId = Annotated[str, Field(min_length=1)]
_MaxBytes = Annotated[int, Field(strict=True, gt=0)]

_DEFAULT_ARTIFACT_MAX_BYTES = 5 * 1024 * 1024

_TASK_RUN_TOOL_NAME = "run_orca_task"
_VERSION_CREATION_TOOL_NAMES = (
    "create_version_from_archive",
    "create_version_from_url",
)


class StartupConfigError(RuntimeError):
    """Raised when the server startup configuration is invalid."""


@dataclass(frozen=True)
class AuditHubSdkContext:
    """Static SDK configuration derived from environment variables at startup."""

    configuration: audithub_sdk.Configuration
    auth_context: OIDCClientCredentialsContext


@dataclass(frozen=True)
class AuditHubServerConfig:
    """Resolved startup configuration for the AuditHub MCP server."""

    context: AuditHubSdkContext
    allowed_org_ids: frozenset[int]
    allowed_project_ids: frozenset[int]
    task_runs_enabled: bool
    version_creation_enabled: bool


class AuditHubInputConfig(BaseModel):
    """Validated input config data loaded from file-backed or env-backed sources."""

    audithub_base_url: str = Field(min_length=1)
    audithub_oidc_configuration_url: str = Field(min_length=1)
    audithub_oidc_client_id: str = Field(min_length=1)
    audithub_oidc_client_secret: SecretStr
    allowed_org_ids: list[_AhId]
    allowed_project_ids: list[_AhId]
    enable_task_runs: bool = False
    enable_version_creation: bool = False

    @field_validator("audithub_oidc_client_secret")
    @classmethod
    def _validate_client_secret(cls, value: SecretStr) -> SecretStr:
        if value.get_secret_value() == "":
            raise ValueError("client secret cannot be an empty string")
        return value


def update_input_config_from_env(config: AuditHubInputConfig) -> None:
    """Mutate *config* from environment variables.

    The caller is responsible for validating the resulting config after calling
    this function.
    """
    if "AUDITHUB_BASE_URL" in os.environ:
        config.audithub_base_url = os.environ["AUDITHUB_BASE_URL"]
    if "AUDITHUB_OIDC_CONFIGURATION_URL" in os.environ:
        config.audithub_oidc_configuration_url = os.environ["AUDITHUB_OIDC_CONFIGURATION_URL"]
    if "AUDITHUB_OIDC_CLIENT_ID" in os.environ:
        config.audithub_oidc_client_id = os.environ["AUDITHUB_OIDC_CLIENT_ID"]
    if "AUDITHUB_OIDC_CLIENT_SECRET" in os.environ:
        config.audithub_oidc_client_secret = SecretStr(os.environ["AUDITHUB_OIDC_CLIENT_SECRET"])
    if "AH_ALLOWED_ORG_IDS" in os.environ:
        config.allowed_org_ids = list(
            _parse_id_list(
                os.environ["AH_ALLOWED_ORG_IDS"], "--allowed-org-ids / AH_ALLOWED_ORG_IDS"
            )
        )
    if "AH_ALLOWED_PROJECT_IDS" in os.environ:
        config.allowed_project_ids = list(
            _parse_id_list(
                os.environ["AH_ALLOWED_PROJECT_IDS"],
                "--allowed-project-ids / AH_ALLOWED_PROJECT_IDS",
            )
        )
    if "AH_ENABLE_TASK_RUNS" in os.environ:
        config.enable_task_runs = _parse_bool_flag(
            os.environ.get("AH_ENABLE_TASK_RUNS"), "AH_ENABLE_TASK_RUNS"
        )
    if "AH_ENABLE_VERSION_CREATION" in os.environ:
        config.enable_version_creation = _parse_bool_flag(
            os.environ.get("AH_ENABLE_VERSION_CREATION"), "AH_ENABLE_VERSION_CREATION"
        )


def _parse_id_list(value: str, flag: str) -> frozenset[int]:
    """Parse a comma-separated string of positive integers into a frozenset."""
    try:
        ids = frozenset(int(tok.strip()) for tok in value.split(",") if tok.strip())
    except ValueError:
        sys.exit(f"Error: {flag} must be a comma-separated list of integers, got: {value!r}")
    non_positive = [item for item in ids if item <= 0]
    if non_positive:
        sys.exit(f"Error: {flag} contains non-positive IDs: {sorted(non_positive)}")
    return ids


def _parse_bool_flag(value: str | None, flag: str) -> bool:
    """Parse an optional boolean environment flag."""
    if value is None or value == "":
        return False
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    sys.exit(f"Error: {flag} must be one of 1/0, true/false, yes/no, or on/off.")


def _build_context(config: AuditHubInputConfig) -> AuditHubSdkContext:
    """Build SDK context from validated input config values."""
    configuration = audithub_sdk.Configuration(host=config.audithub_base_url)
    auth_context = OIDCClientCredentialsContext(
        oidc_configuration_url=config.audithub_oidc_configuration_url,
        client_id=config.audithub_oidc_client_id,
        client_secret=config.audithub_oidc_client_secret.get_secret_value(),
    )
    return AuditHubSdkContext(configuration=configuration, auth_context=auth_context)


def _load_raw_config_from_path(path: Path) -> dict[str, object]:
    """Load raw config data from a JSON or YAML file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise StartupConfigError(f"Failed to read config file {path}: {exc}") from exc

    suffix = path.suffix.casefold()
    if suffix == ".json":
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError as exc:
            raise StartupConfigError(f"Invalid JSON config in {path}: {exc.msg}") from exc
    elif suffix in {".yaml", ".yml"}:
        try:
            loaded = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise StartupConfigError(f"Invalid YAML config in {path}: {exc}") from exc
    else:
        raise StartupConfigError(f"Unsupported config file format for {path}.")
    if not isinstance(loaded, dict):
        raise StartupConfigError(f"Config file {path} must contain a top-level object.")
    return loaded


def load_config_from_path(
    path: Path, *, override_from_env_vars: bool = False
) -> AuditHubServerConfig:
    """Load startup config from a JSON or YAML file."""
    raw_config = _load_raw_config_from_path(path)
    try:
        input_config = AuditHubInputConfig.model_construct(
            audithub_base_url="",
            audithub_oidc_configuration_url="",
            audithub_oidc_client_id="",
            audithub_oidc_client_secret=SecretStr(""),
            allowed_org_ids=None,
            allowed_project_ids=None,
            enable_task_runs=False,
            enable_version_creation=False,
        )
        input_config.__dict__.update(raw_config)
        if override_from_env_vars:
            update_input_config_from_env(input_config)
        input_config = AuditHubInputConfig.model_validate(
            input_config.model_dump(mode="python", warnings=False)
        )
    except Exception as exc:
        raise StartupConfigError(f"Invalid config file {path}: {exc}") from exc
    return AuditHubServerConfig(
        context=_build_context(input_config),
        allowed_org_ids=frozenset(input_config.allowed_org_ids),
        allowed_project_ids=frozenset(input_config.allowed_project_ids),
        task_runs_enabled=input_config.enable_task_runs,
        version_creation_enabled=input_config.enable_version_creation,
    )


def load_config_from_env() -> AuditHubServerConfig:
    """Resolve startup configuration from environment variables."""
    input_config = AuditHubInputConfig.model_construct(
        audithub_base_url="",
        audithub_oidc_configuration_url="",
        audithub_oidc_client_id="",
        audithub_oidc_client_secret=SecretStr(""),
        allowed_org_ids=[],
        allowed_project_ids=[],
        enable_task_runs=False,
        enable_version_creation=False,
    )
    update_input_config_from_env(input_config)
    input_config = AuditHubInputConfig.model_validate(input_config.model_dump())
    return AuditHubServerConfig(
        context=_build_context(input_config),
        allowed_org_ids=frozenset(input_config.allowed_org_ids),
        allowed_project_ids=frozenset(input_config.allowed_project_ids),
        task_runs_enabled=input_config.enable_task_runs,
        version_creation_enabled=input_config.enable_version_creation,
    )


def validate_startup_config(config: AuditHubServerConfig) -> None:
    """Raise unless the resolved startup config contains the required allowlists."""
    if not config.allowed_org_ids:
        raise StartupConfigError(
            "Error: allowed organization IDs are required. "
            "Set --allowed-org-ids or AH_ALLOWED_ORG_IDS."
        )
    if not config.allowed_project_ids:
        raise StartupConfigError(
            "Error: allowed project IDs are required. "
            "Set --allowed-project-ids or AH_ALLOWED_PROJECT_IDS."
        )
