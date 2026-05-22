"""Unit tests for Vanguard detector catalog helpers."""

from __future__ import annotations

from pydantic import TypeAdapter

from tests.sdk_stubs import install_sdk_stubs

install_sdk_stubs()

import ah_mcp.vanguard as vanguard  # noqa: E402
from ah_mcp.models import DefiVanguardV2TaskInput  # noqa: E402


def test_formats_builtin_detector_entry() -> None:
    entry = vanguard.VanguardDetectorCatalogEntry(
        display_name="Unchecked Return",
        description="hiyul/unchecked-return",
        builtin_code="hiyul/unchecked-return",
    )

    assert (
        vanguard.format_vanguard_detector_listing_entry(entry)
        == """\
detector: ["builtin", "hiyul/unchecked-return"]
title: Unchecked Return
------"""
    )


def test_formats_orglib_detector_entry() -> None:
    entry = vanguard.VanguardDetectorCatalogEntry(
        display_name="my-detector.luau",
        description="Detects things",
        custom_detector_id=7,
        custom_detector_type="orglib",
        custom_detector_name="my-detector.luau",
    )

    assert (
        vanguard.format_vanguard_detector_listing_entry(entry)
        == """\
detector: ["orglib", 7]
title: my-detector.luau
------"""
    )


def test_formats_stdlib_detector_entry() -> None:
    entry = vanguard.VanguardDetectorCatalogEntry(
        display_name="Library Custom Detector",
        description="Description of the library detector\nHello world!",
        custom_detector_id="my-lib-detector",
        custom_detector_type="stdlib",
        custom_detector_category="my-category",
        custom_detector_name="Library Custom Detector",
        custom_detector_library_version="latest",
    )

    assert (
        vanguard.format_vanguard_detector_listing_entry(entry)
        == """\
detector: ["stdlib", "my-lib-detector"]
title: Library Custom Detector
description: Description of the library detector
Hello world!
------"""
    )


def test_defi_vanguard_task_input_schema_has_no_defs_or_refs() -> None:
    schema = TypeAdapter(DefiVanguardV2TaskInput).json_schema()

    def assert_no_defs_or_refs(value: object) -> None:
        if isinstance(value, dict):
            assert "$defs" not in value
            assert "$ref" not in value
            for nested_value in value.values():
                assert_no_defs_or_refs(nested_value)
        elif isinstance(value, list):
            for item in value:
                assert_no_defs_or_refs(item)

    assert_no_defs_or_refs(schema)
