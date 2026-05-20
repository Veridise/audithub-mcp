"""Configuration types and environment parsing for the AuditHub MCP server."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import audithub_sdk
import yaml  # type: ignore[import-untyped]
from audithub_sdk_ext import OIDCClientCredentialsContext
from pydantic import Field

_AhId = Annotated[int, Field(strict=True, gt=0)]
_ArtifactId = Annotated[str, Field(min_length=1)]
_MaxBytes = Annotated[int, Field(strict=True, gt=0)]

_REQUIRED_ENV_VARS: tuple[str, ...] = (
    "AUDITHUB_BASE_URL",
    "AUDITHUB_OIDC_CONFIGURATION_URL",
    "AUDITHUB_OIDC_CLIENT_ID",
    "AUDITHUB_OIDC_CLIENT_SECRET",
)

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


_REQUIRED_FILE_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "audithub_base_url",
        "audithub_oidc_configuration_url",
        "audithub_oidc_client_id",
        "audithub_oidc_client_secret",
        "allowed_org_ids",
        "allowed_project_ids",
    }
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


def _build_context() -> AuditHubSdkContext:
    """Read AuditHub SDK/auth configuration from environment variables."""
    missing = [v for v in _REQUIRED_ENV_VARS if not os.environ.get(v)]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    configuration = audithub_sdk.Configuration(host=os.environ["AUDITHUB_BASE_URL"])
    auth_context = OIDCClientCredentialsContext(
        oidc_configuration_url=os.environ["AUDITHUB_OIDC_CONFIGURATION_URL"],
        client_id=os.environ["AUDITHUB_OIDC_CLIENT_ID"],
        client_secret=os.environ["AUDITHUB_OIDC_CLIENT_SECRET"],
    )
    return AuditHubSdkContext(configuration=configuration, auth_context=auth_context)


def _build_context_from_values(values: dict[str, object]) -> AuditHubSdkContext:
    """Build SDK context from normalized config values."""
    configuration = audithub_sdk.Configuration(host=_require_string(values, "audithub_base_url"))
    auth_context = OIDCClientCredentialsContext(
        oidc_configuration_url=_require_string(values, "audithub_oidc_configuration_url"),
        client_id=_require_string(values, "audithub_oidc_client_id"),
        client_secret=_require_string(values, "audithub_oidc_client_secret"),
    )
    return AuditHubSdkContext(configuration=configuration, auth_context=auth_context)


def _require_string(values: dict[str, object], key: str) -> str:
    """Return a non-empty string config value."""
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise StartupConfigError(f"Config key {key!r} must be a non-empty string.")
    return value


def _require_int_list(values: dict[str, object], key: str) -> frozenset[int]:
    """Return a validated list of positive integer IDs."""
    raw_value = values.get(key)
    if not isinstance(raw_value, list):
        raise StartupConfigError(f"Config key {key!r} must be a list of positive integers.")
    if any(not isinstance(item, int) or item <= 0 for item in raw_value):
        raise StartupConfigError(f"Config key {key!r} must be a list of positive integers.")
    return frozenset(raw_value)


def _optional_bool(values: dict[str, object], key: str) -> bool:
    """Return an optional boolean config value, defaulting to False."""
    value = values.get(key, False)
    if not isinstance(value, bool):
        raise StartupConfigError(f"Config key {key!r} must be a boolean.")
    return value


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


def load_config_from_path(path: Path) -> AuditHubServerConfig:
    """Load startup config from a JSON or YAML file."""
    raw_config = _load_raw_config_from_path(path)
    missing_keys = sorted(_REQUIRED_FILE_CONFIG_KEYS - raw_config.keys())
    if missing_keys:
        raise StartupConfigError(
            f"Missing required config key(s): {', '.join(missing_keys)}."
        )
    return AuditHubServerConfig(
        context=_build_context_from_values(raw_config),
        allowed_org_ids=_require_int_list(raw_config, "allowed_org_ids"),
        allowed_project_ids=_require_int_list(raw_config, "allowed_project_ids"),
        task_runs_enabled=_optional_bool(raw_config, "enable_task_runs"),
        version_creation_enabled=_optional_bool(raw_config, "enable_version_creation"),
    )


def load_server_config() -> AuditHubServerConfig:
    """Resolve startup configuration from environment variables."""
    org_ids_raw = os.environ.get("AH_ALLOWED_ORG_IDS", "")
    project_ids_raw = os.environ.get("AH_ALLOWED_PROJECT_IDS", "")
    task_runs_enabled = _parse_bool_flag(
        os.environ.get("AH_ENABLE_TASK_RUNS"), "AH_ENABLE_TASK_RUNS"
    )
    version_creation_enabled = _parse_bool_flag(
        os.environ.get("AH_ENABLE_VERSION_CREATION"), "AH_ENABLE_VERSION_CREATION"
    )

    return AuditHubServerConfig(
        context=_build_context(),
        allowed_org_ids=(
            frozenset()
            if not org_ids_raw
            else _parse_id_list(org_ids_raw, "--allowed-org-ids / AH_ALLOWED_ORG_IDS")
        ),
        allowed_project_ids=(
            frozenset()
            if not project_ids_raw
            else _parse_id_list(project_ids_raw, "--allowed-project-ids / AH_ALLOWED_PROJECT_IDS")
        ),
        task_runs_enabled=task_runs_enabled,
        version_creation_enabled=version_creation_enabled,
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
