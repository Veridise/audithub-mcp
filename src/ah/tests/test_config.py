"""Tests for file-backed AuditHub startup config loading."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

import ah_mcp.config as config

AuditHubInputConfig = config.AuditHubInputConfig
StartupConfigError = config.StartupConfigError
load_config_from_path = config.load_config_from_path
update_input_config_from_env = config.update_input_config_from_env


_DUMMY_CONFIG_PATH = Path(__file__).with_name("dummy_config.yaml")


def test_config_loads_from_yaml() -> None:
    """Validate that dummy YAML config loads successfully"""
    config = load_config_from_path(_DUMMY_CONFIG_PATH)

    assert config.context.configuration.host == "https://example.com/api/v1"
    assert (
        config.context.auth_context.oidc_configuration_url
        == "https://issuer/.well-known/openid-configuration"
    )
    assert config.allowed_org_ids == frozenset({1, 2})
    assert config.allowed_project_ids == frozenset({10, 20})
    assert config.task_runs_enabled is True
    assert config.version_creation_enabled is False


def test_config_loads_from_json() -> None:
    """Validate that dummy JSON config loads successfully"""
    with _DUMMY_CONFIG_PATH.open("r", encoding="utf-8") as handle:
        dummy_config = yaml.safe_load(handle)

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "dummy_config.json"
        json_path.write_text(json.dumps(dummy_config), encoding="utf-8")
        config = load_config_from_path(json_path)

    assert config.allowed_org_ids == frozenset({1, 2})
    assert config.allowed_project_ids == frozenset({10, 20})


def test_file_configuration_can_be_overridden_from_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test combined config from file and env vars"""
    monkeypatch.setenv("AUDITHUB_BASE_URL", "https://override.example/api/v1")
    monkeypatch.setenv("AUDITHUB_OIDC_CLIENT_ID", "override-client-id")
    monkeypatch.setenv("AH_ALLOWED_ORG_IDS", "7,8")
    monkeypatch.setenv("AH_ENABLE_TASK_RUNS", "false")
    monkeypatch.setenv("AH_ENABLE_VERSION_CREATION", "true")

    # ensure the following keys are loaded from config
    monkeypatch.delenv("AH_ALLOWED_PROJECT_IDS", raising=False)

    config = load_config_from_path(_DUMMY_CONFIG_PATH, override_from_env_vars=True)

    assert config.context.configuration.host == "https://override.example/api/v1"
    assert config.context.auth_context.client_id == "override-client-id"
    assert config.allowed_org_ids == frozenset({7, 8})
    assert config.allowed_project_ids == frozenset({10, 20})
    assert config.task_runs_enabled is False
    assert config.version_creation_enabled is True


def test_configuration_with_missing_keys_fails_to_load() -> None:
    """Reject config that omits a required key."""
    with _DUMMY_CONFIG_PATH.open("r", encoding="utf-8") as handle:
        invalid_config = dict(yaml.safe_load(handle))
    del invalid_config["allowed_project_ids"]

    with tempfile.TemporaryDirectory() as tmpdir:
        invalid_path = Path(tmpdir) / "invalid_config.yaml"
        invalid_path.write_text(yaml.safe_dump(invalid_config), encoding="utf-8")
        with pytest.raises(StartupConfigError, match="allowed_project_ids"):
            load_config_from_path(invalid_path)


def test_update_config_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mutate a config in place from environment variables."""
    input_config = AuditHubInputConfig(
        audithub_base_url="https://before.example/api/v1",
        audithub_oidc_configuration_url="https://before/.well-known/openid-configuration",
        audithub_oidc_client_id="before-client-id",
        audithub_oidc_client_secret="before-client-secret",
        allowed_org_ids=[1],
        allowed_project_ids=[10],
        enable_task_runs=False,
        enable_version_creation=False,
    )
    monkeypatch.setenv("AUDITHUB_BASE_URL", "https://after.example/api/v1")
    monkeypatch.setenv(
        "AUDITHUB_OIDC_CONFIGURATION_URL",
        "https://after/.well-known/openid-configuration",
    )
    monkeypatch.setenv("AUDITHUB_OIDC_CLIENT_ID", "after-client-id")
    monkeypatch.setenv("AUDITHUB_OIDC_CLIENT_SECRET", "after-client-secret")
    monkeypatch.setenv("AH_ALLOWED_ORG_IDS", "2,3")
    monkeypatch.setenv("AH_ALLOWED_PROJECT_IDS", "20,30")
    monkeypatch.setenv("AH_ENABLE_TASK_RUNS", "true")
    monkeypatch.setenv("AH_ENABLE_VERSION_CREATION", "1")

    update_input_config_from_env(input_config)

    assert input_config.audithub_base_url == "https://after.example/api/v1"
    assert (
        input_config.audithub_oidc_configuration_url
        == "https://after/.well-known/openid-configuration"
    )
    assert input_config.audithub_oidc_client_id == "after-client-id"
    assert input_config.audithub_oidc_client_secret.get_secret_value() == "after-client-secret"
    assert set(input_config.allowed_org_ids) == {2, 3}
    assert set(input_config.allowed_project_ids) == {20, 30}
    assert input_config.enable_task_runs is True
    assert input_config.enable_version_creation is True


def test_ah_mcp_rejects_invalid_config() -> None:
    """Check that `ah-mcp` reports missing config settings."""
    env = os.environ.copy()
    env.update(
        {
            "AUDITHUB_BASE_URL": "https://example.com/api/v1",
            "AUDITHUB_OIDC_CONFIGURATION_URL": "",
            "AUDITHUB_OIDC_CLIENT_ID": "test-client-id",
            "AUDITHUB_OIDC_CLIENT_SECRET": "",
            "AH_ALLOWED_ORG_IDS": "1",
            "AH_ALLOWED_PROJECT_IDS": "10",
        }
    )

    result = subprocess.run(
        ["ah-mcp"],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    combined_output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "Missing required configuration values" in combined_output
    assert "AUDITHUB_OIDC_CONFIGURATION_URL" in combined_output
    assert "AUDITHUB_OIDC_CLIENT_SECRET" in combined_output
    assert "Traceback" not in combined_output
