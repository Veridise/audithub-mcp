"""Test helpers for generating SDK-shaped payloads.

The real AuditHub SDK is available in the test environment, but several
endpoints validate their responses with Pydantic models. These factories
provide small, valid SDK payloads so tests can stub network calls without
hand-crafting the full generated schemas each time.
"""

from __future__ import annotations

from audithub_sdk.models.public_configuration import PublicConfiguration
from audithub_sdk.models.vanguard_detector import VanguardDetector


def make_vanguard_detector(
    *,
    code: str,
    caption: str,
    tool: str = "builtin-tool",
) -> VanguardDetector:
    """Build a valid builtin Vanguard detector model."""
    return VanguardDetector(code=code, caption=caption, tool=tool)


def make_public_configuration(
    *,
    solc_versions: list[str] | None = None,
    builtin_detectors: list[VanguardDetector] | None = None,
) -> PublicConfiguration:
    """Build a minimal valid public configuration payload for tests."""
    return PublicConfiguration.model_construct(
        fork_networks=[],
        vanguard_solc_versions=solc_versions or ["latest", "0.8.21"],
        vanguard_defi_detectors=[],
        vanguard_v2_defi_detectors=builtin_detectors
        or [
            make_vanguard_detector(
                code="hiyul/unchecked-return",
                caption="Unchecked Return",
            ),
            make_vanguard_detector(
                code="hiyul/divide-before-multiply",
                caption="Divide Before Multiply",
            ),
        ],
        vanguard_zk_detectors=[],
        vanguard_v2_zk_detectors=[],
        node_versions=[],
        workflow_steps={},
        orca={},
        issue_configuration_options={},
        available_tools=[],
        application_functions=[],
        version_archive_size_limit=200_000_000,
    )
