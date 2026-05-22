"""Vanguard detector catalog helpers and cache management."""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from audithub_sdk.models.custom_detector_from_organization_library import (
    CustomDetectorFromOrganizationLibrary,
)
from audithub_sdk.models.custom_detector_from_standard_library import (
    CustomDetectorFromStandardLibrary,
)
from audithub_sdk.models.custom_detector_from_version import CustomDetectorFromVersion
from audithub_sdk.models.custom_detector_with_id import CustomDetectorWithId
from audithub_sdk.models.defi_vanguard_v2_input import DefiVanguardV2Input
from audithub_sdk.models.defi_vanguard_v2_parameters import DefiVanguardV2Parameters
from audithub_sdk.models.public_configuration import PublicConfiguration
from audithub_sdk.models.root_model_list_union_custom_detector_from_version_custom_detector_from_standard_library_custom_detector_from_organization_library_inner import (  # noqa: E501
    RootModelListUnionCustomDetectorFromVersionCustomDetectorFromStandardLibraryCustomDetectorFromOrganizationLibraryInner as SdkVanguardCustomDetectorReference,  # noqa: E501
)
from audithub_sdk.models.vanguard_detector import VanguardDetector
from pydantic import TypeAdapter, ValidationError

from ah_mcp.models import DefiVanguardV2DetectorSelectionInput, DefiVanguardV2TaskInput

_VANGUARD_DETECTOR_CACHE_LIFETIME_SECONDS = 24 * 60 * 60
_builtin_vanguard_v2_detectors_cache: tuple[float, GlobalVanguardV2Configuration] | None = None

_vanguard_detector_ta = TypeAdapter(list[VanguardDetector])
_custom_detector_ta = TypeAdapter(list[CustomDetectorWithId])


@dataclass(frozen=True)
class VanguardDetectorCatalogEntry:
    """Normalized detector metadata used for lookup and list formatting."""

    display_name: str
    description: str | None = None
    builtin_code: str | None = None
    custom_detector_id: int | str | None = None
    custom_detector_type: str | None = None
    custom_detector_category: str | None = None
    custom_detector_name: str | None = None
    custom_detector_library_version: str | None = None


@dataclass(frozen=True)
class GlobalVanguardV2Configuration:
    """Cached global Vanguard configuration loaded from public configuration."""

    builtin_detectors: tuple[VanguardDetector, ...]
    solc_versions: tuple[str, ...]


def reset_builtin_vanguard_v2_detectors_cache() -> None:
    """Clear the cached builtin detector catalog."""
    global _builtin_vanguard_v2_detectors_cache
    _builtin_vanguard_v2_detectors_cache = None


def set_builtin_vanguard_v2_detectors_cache(
    cache: tuple[float, GlobalVanguardV2Configuration] | None,
) -> None:
    """Set the cached builtin Vanguard configuration, primarily for tests."""
    global _builtin_vanguard_v2_detectors_cache
    _builtin_vanguard_v2_detectors_cache = cache


def _vanguard_display_name(value: str) -> str:
    """Normalize detector display text while preserving the user-facing spelling."""
    return value.strip()


def _vanguard_custom_display_name(value: str) -> str:
    """Humanize detector names loaded from custom detector libraries."""
    stripped = value.strip()
    if not stripped:
        return "Custom detector"
    candidate = stripped.replace("_", " ").replace("-", " ")
    if candidate == stripped:
        return candidate
    return " ".join(part[:1].upper() + part[1:] for part in candidate.split())


def _vanguard_custom_detector_description(contents: str) -> str:
    """Derive a compact human-readable summary for a custom detector."""
    stripped = contents.strip()
    if not stripped:
        return "Custom detector"
    for line in stripped.splitlines():
        line = line.strip()
        if line:
            return line
    return "Custom detector"


def _vanguard_custom_detector_library_description(value: dict[str, object]) -> str | None:
    """Extract a human-readable description from a standard-library detector payload."""
    description = value.get("description")
    if isinstance(description, str):
        stripped = description.strip()
        if stripped:
            return stripped
    return None


def _normalize_lookup_key(value: str) -> str:
    """Normalize a lookup key for case-insensitive comparison."""
    return "".join(ch for ch in value.casefold() if ch.isalnum())


def _format_vanguard_detector_selection(
    detector_type: str,
    detector_id: str | int,
) -> str:
    """Encode a detector selection in the JSON shape accepted by task input."""
    return json.dumps([detector_type, detector_id])


async def get_builtin_vanguard_v2_configuration(
    fetch_configuration: Callable[[], Awaitable[object]],
) -> GlobalVanguardV2Configuration:
    """Fetch and cache the builtin DeFi Vanguard v2 configuration."""
    global _builtin_vanguard_v2_detectors_cache
    now = time.monotonic()
    if _builtin_vanguard_v2_detectors_cache is not None:
        fetched_at, configuration = _builtin_vanguard_v2_detectors_cache
        if now - fetched_at < _VANGUARD_DETECTOR_CACHE_LIFETIME_SECONDS:
            return configuration
    raw_configuration = await fetch_configuration()
    public_configuration = PublicConfiguration.model_validate(raw_configuration)
    configuration = GlobalVanguardV2Configuration(
        builtin_detectors=tuple(
            _vanguard_detector_ta.validate_python(
                public_configuration.vanguard_v2_defi_detectors or []
            )
        ),
        solc_versions=tuple(public_configuration.vanguard_solc_versions or []),
    )
    _builtin_vanguard_v2_detectors_cache = (now, configuration)
    return configuration


async def get_builtin_vanguard_v2_detectors(
    fetch_configuration: Callable[[], Awaitable[object]],
) -> tuple[VanguardDetector, ...]:
    """Fetch and cache the builtin DeFi Vanguard v2 detector list."""
    configuration = await get_builtin_vanguard_v2_configuration(fetch_configuration)
    return configuration.builtin_detectors


async def get_custom_vanguard_detectors(
    organization_id: int,
    fetch_custom_detectors: Callable[[int], Awaitable[object]],
) -> tuple[CustomDetectorWithId, ...]:
    """Fetch the live organization custom detector list without caching."""
    detectors = await fetch_custom_detectors(organization_id)
    return tuple(_custom_detector_ta.validate_python(detectors))


async def get_standard_library_vanguard_detectors(
    fetch_custom_detectors_library: Callable[[], Awaitable[object]],
) -> tuple[VanguardDetectorCatalogEntry, ...]:
    """Fetch the live standard-library custom detector catalog without caching."""
    library = await fetch_custom_detectors_library()
    entries: list[VanguardDetectorCatalogEntry] = []
    seen: set[tuple[str, str, str]] = set()
    for detector in _iter_custom_detector_dicts(library):
        standard_detector = _validate_custom_detector_from_standard_library(detector)
        if standard_detector is None:
            continue
        key = (
            _normalize_lookup_key(standard_detector.category),
            _normalize_lookup_key(standard_detector.name),
            _normalize_lookup_key(standard_detector.library_version or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        entries.append(
            VanguardDetectorCatalogEntry(
                display_name=_vanguard_custom_display_name(standard_detector.name),
                description=(_vanguard_custom_detector_library_description(detector)),
                custom_detector_id=standard_detector.name,
                custom_detector_type="stdlib",
                custom_detector_category=standard_detector.category,
                custom_detector_name=_vanguard_custom_display_name(standard_detector.name),
                custom_detector_library_version=standard_detector.library_version,
            )
        )
    return tuple(entries)


async def load_vanguard_detector_catalog(
    organization_id: int,
    *,
    fetch_configuration: Callable[[], Awaitable[object]],
    fetch_custom_detectors: Callable[[int], Awaitable[object]],
    fetch_custom_detectors_library: Callable[[], Awaitable[object]],
) -> tuple[list[VanguardDetectorCatalogEntry], list[VanguardDetectorCatalogEntry]]:
    """Load builtin and custom detector catalog entries for display and resolution."""
    builtin_configuration = await get_builtin_vanguard_v2_configuration(fetch_configuration)
    organization_custom_detectors = await get_custom_vanguard_detectors(
        organization_id,
        fetch_custom_detectors,
    )
    standard_library_custom_detectors = await get_standard_library_vanguard_detectors(
        fetch_custom_detectors_library,
    )
    builtin_entries = [
        VanguardDetectorCatalogEntry(
            display_name=_vanguard_display_name(detector.caption),
            description=detector.code,
            builtin_code=detector.code,
        )
        for detector in builtin_configuration.builtin_detectors
    ]
    custom_entries = [
        VanguardDetectorCatalogEntry(
            display_name=_vanguard_display_name(detector.filename),
            description=_vanguard_custom_detector_description(detector.contents),
            custom_detector_id=detector.id,
            custom_detector_type="orglib",
            custom_detector_name=_vanguard_display_name(detector.filename),
        )
        for detector in organization_custom_detectors
    ]
    custom_entries.extend(standard_library_custom_detectors)
    return builtin_entries, custom_entries


def format_vanguard_detector_listing_entry(entry: VanguardDetectorCatalogEntry) -> str:
    """Render a detector entry in the user-facing listing format."""
    if entry.builtin_code is not None:
        return (
            f"detector: {_format_vanguard_detector_selection('builtin', entry.builtin_code)}\n"
            f"title: {entry.display_name}\n"
            "------"
        )
    if entry.custom_detector_id is not None:
        custom_type = entry.custom_detector_type or "custom"
        title = entry.custom_detector_name or entry.display_name
        detector = _format_vanguard_detector_selection(custom_type, entry.custom_detector_id)
        if custom_type == "orglib":
            return f"detector: {detector}\ntitle: {title}\n------"
        return f"detector: {detector}\ntitle: {title}\ndescription: {entry.description}\n------"
    raise RuntimeError("Unsupported detector entry.")


def resolve_vanguard_detector_selection(
    selection: DefiVanguardV2DetectorSelectionInput,
    *,
    builtin_entries: Sequence[VanguardDetectorCatalogEntry],
    custom_entries: Sequence[VanguardDetectorCatalogEntry],
) -> tuple[str | None, SdkVanguardCustomDetectorReference | None]:
    """Resolve a typed detector selection to the corresponding SDK payload."""
    selection_type, selection_id = selection

    if selection_type == "builtin":
        if not isinstance(selection_id, str):
            raise RuntimeError("Builtin detector ids must be strings.")
        builtin = next(
            (entry for entry in builtin_entries if entry.builtin_code == selection_id),
            None,
        )
        if builtin is None:
            raise RuntimeError(
                "Unknown builtin detector "
                f"{selection_id!r}. Use get_defi_vanguard_detectors to list valid values."
            )
        return builtin.builtin_code, None

    if selection_type == "orglib":
        if not isinstance(selection_id, int):
            raise RuntimeError("Organization-library detector ids must be integers.")
        custom = next(
            (
                entry
                for entry in custom_entries
                if entry.custom_detector_type == "orglib"
                and entry.custom_detector_id == selection_id
            ),
            None,
        )
        if custom is None:
            raise RuntimeError(
                "Unknown organization-library detector "
                f"{selection_id!r}. Use get_defi_vanguard_detectors to list valid values."
            )
        return None, SdkVanguardCustomDetectorReference(
            actual_instance=CustomDetectorFromOrganizationLibrary(id=selection_id)
        )

    if selection_type == "stdlib":
        if not isinstance(selection_id, str):
            raise RuntimeError("Standard-library detector ids must be strings.")
        custom = next(
            (
                entry
                for entry in custom_entries
                if entry.custom_detector_type == "stdlib"
                and entry.custom_detector_id == selection_id
            ),
            None,
        )
        if custom is None:
            raise RuntimeError(
                "Unknown standard-library detector "
                f"{selection_id!r}. Use get_defi_vanguard_detectors to list valid values."
            )
        return None, SdkVanguardCustomDetectorReference(
            actual_instance=CustomDetectorFromStandardLibrary(
                category=custom.custom_detector_category or "",
                name=selection_id,
                library_version=custom.custom_detector_library_version,
            )
        )

    if selection_type == "version":
        if not isinstance(selection_id, str):
            raise RuntimeError("Version detector ids must be strings.")
        return None, SdkVanguardCustomDetectorReference(
            actual_instance=CustomDetectorFromVersion(relative_path=selection_id)
        )

    raise RuntimeError(f"Unsupported detector selection type {selection_type!r}.")


async def validate_vanguard_solc_version(
    solc: str | None,
    *,
    fetch_configuration: Callable[[], Awaitable[object]],
) -> str:
    """Normalize and validate the requested solc version against builtin config."""
    builtin_configuration = await get_builtin_vanguard_v2_configuration(fetch_configuration)
    normalized_solc = "latest" if solc is None else solc
    if normalized_solc not in builtin_configuration.solc_versions:
        raise RuntimeError(
            f"Unsupported solc version {normalized_solc!r}. "
            "Use a value from the builtin Vanguard configuration."
        )
    return normalized_solc


async def build_vanguard_v2_input(
    organization_id: int,
    task_input: DefiVanguardV2TaskInput,
    *,
    fetch_configuration: Callable[[], Awaitable[object]],
    fetch_custom_detectors: Callable[[int], Awaitable[object]],
    fetch_custom_detectors_library: Callable[[], Awaitable[object]],
) -> DefiVanguardV2Input:
    """Convert local DeFi Vanguard v2 task input to the generated SDK input model."""
    validated_solc = await validate_vanguard_solc_version(
        task_input.solc,
        fetch_configuration=fetch_configuration,
    )
    builtin_entries, custom_entries = await load_vanguard_detector_catalog(
        organization_id,
        fetch_configuration=fetch_configuration,
        fetch_custom_detectors=fetch_custom_detectors,
        fetch_custom_detectors_library=fetch_custom_detectors_library,
    )
    detector_codes: list[str] = []
    custom_detectors: list[SdkVanguardCustomDetectorReference] = []
    for selection in task_input.detectors:
        detector_code, custom_detector = resolve_vanguard_detector_selection(
            selection,
            builtin_entries=builtin_entries,
            custom_entries=custom_entries,
        )
        if detector_code is not None:
            detector_codes.append(detector_code)
        elif custom_detector is not None:
            custom_detectors.append(custom_detector)
    parameters = DefiVanguardV2Parameters(
        detector=detector_codes or None,
        input_limit=task_input.input_limit,
        cross_version_triage=task_input.cross_version_triage,
        lang="solidity",
        solc=validated_solc,
        ignore_build_system=task_input.ignore_build_system,
        custom_detectors=custom_detectors or None,
    )
    return DefiVanguardV2Input(name=task_input.name, parameters=parameters)


def _iter_custom_detector_dicts(data: object) -> list[dict[str, object]]:
    """Yield candidate detector dictionaries from arbitrary library payloads."""
    detectors: list[dict[str, object]] = []
    stack: list[object] = [data]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            detectors.append(current)
            stack.extend(current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
    return detectors


def _validate_custom_detector_from_standard_library(
    value: dict[str, object],
) -> CustomDetectorFromStandardLibrary | None:
    """Validate a standard-library custom detector payload if possible."""
    try:
        return CustomDetectorFromStandardLibrary.model_validate(value)
    except ValidationError:
        return None
