"""Tests for file-backed AuditHub startup config loading."""

from __future__ import annotations

import importlib
import json
import tempfile
from pathlib import Path

import pytest
import yaml

from tests.sdk_stubs import install_sdk_stubs

install_sdk_stubs()

config = importlib.import_module("ah_mcp.config")
StartupConfigError = config.StartupConfigError
load_config_from_path = config.load_config_from_path


_DUMMY_CONFIG_PATH = Path(__file__).with_name("dummy_config.yaml")


def test_dummy_yaml_configuration_loads_successfully() -> None:
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


def test_dummy_configuration_also_loads_from_json() -> None:
    with _DUMMY_CONFIG_PATH.open("r", encoding="utf-8") as handle:
        dummy_config = yaml.safe_load(handle)

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "dummy_config.json"
        json_path.write_text(json.dumps(dummy_config), encoding="utf-8")
        config = load_config_from_path(json_path)

    assert config.allowed_org_ids == frozenset({1, 2})
    assert config.allowed_project_ids == frozenset({10, 20})


def test_configuration_with_missing_keys_fails_to_load() -> None:
    with _DUMMY_CONFIG_PATH.open("r", encoding="utf-8") as handle:
        invalid_config = dict(yaml.safe_load(handle))
    del invalid_config["allowed_project_ids"]

    with tempfile.TemporaryDirectory() as tmpdir:
        invalid_path = Path(tmpdir) / "invalid_config.yaml"
        invalid_path.write_text(yaml.safe_dump(invalid_config), encoding="utf-8")
        with pytest.raises(StartupConfigError, match="allowed_project_ids"):
            load_config_from_path(invalid_path)
