"""Tests for the native PAQL subprocess adapter."""

from __future__ import annotations

import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import pytest

from audithub_mcp import paql


class _FakeProcess:
    """Minimal asyncio subprocess used by adapter tests."""

    def __init__(self, *, returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        """Return configured process output."""
        return self._stdout, self._stderr

    def kill(self) -> None:
        """Record process termination."""
        self.killed = True

    async def wait(self) -> int:
        """Return the configured exit status."""
        return self.returncode


class _HangingProcess(_FakeProcess):
    """Fake process that never finishes communicating."""

    async def communicate(self) -> tuple[bytes, bytes]:
        """Wait until the caller cancels the operation."""
        await asyncio.Future()
        raise AssertionError("unreachable")


@pytest.mark.asyncio
async def test_validate_pattern_invokes_paql_without_a_shell() -> None:
    process = _FakeProcess(returncode=0)
    captured_source = ""

    async def _create_process(*command: str, **_kwargs: object) -> _FakeProcess:
        nonlocal captured_source
        source_path = Path(command[3])
        captured_source = source_path.read_text(encoding="utf-8")
        assert source_path.stat().st_mode & 0o777 == 0o600
        assert command[:3] == (
            str(paql._BUNDLED_PAQL_EXECUTABLE),
            "validate",
            "pattern",
        )
        assert command[4:] == ("--no-typecheck",)
        return process

    with (
        patch.dict("os.environ", {}, clear=True),
        patch("asyncio.create_subprocess_exec", side_effect=_create_process),
    ):
        result = await paql.validate_source(
            "FIND Contract c",
            source_format="pattern",
            typecheck=False,
        )

    assert result.success
    assert result.errors == []
    assert captured_source == "FIND Contract c"


def test_operator_executable_overrides_bundled_paql() -> None:
    with patch.dict(
        "os.environ",
        {"PAQL_EXECUTABLE": "/opt/paql/bin/paql"},
        clear=True,
    ):
        executable = paql._resolve_paql_executable()

    assert executable == "/opt/paql/bin/paql"


def test_operator_dialect_overrides_bundled_solidity_spec() -> None:
    with patch.dict(
        "os.environ",
        {"PAQL_DIALECT_SPEC": "/opt/vanguard/solidity.luau"},
        clear=True,
    ):
        dialect_spec = paql._resolve_paql_dialect_spec()

    assert dialect_spec == Path("/opt/vanguard/solidity.luau")


@pytest.mark.asyncio
async def test_validate_source_returns_sanitized_paql_errors() -> None:
    async def _create_process(*command: str, **_kwargs: object) -> _FakeProcess:
        source_path = command[3]
        return _FakeProcess(
            returncode=1,
            stderr=f"{source_path}:1:6: error: unexpected token\n".encode(),
        )

    with patch("asyncio.create_subprocess_exec", side_effect=_create_process):
        result = await paql.validate_source(
            "broken",
            source_format="pattern",
            typecheck=False,
        )

    assert not result.success
    assert result.errors == ["<query>:1:6: error: unexpected token"]


@pytest.mark.asyncio
async def test_validate_source_separates_warnings_from_errors() -> None:
    async def _create_process(*command: str, **_kwargs: object) -> _FakeProcess:
        source_path = command[3]
        return _FakeProcess(
            returncode=1,
            stderr=(
                f"{source_path}:1:1: warning: unused variable\n"
                f"{source_path}:2:1: error: unknown property\n"
            ).encode(),
        )

    with patch("asyncio.create_subprocess_exec", side_effect=_create_process):
        result = await paql.validate_source(
            "broken",
            source_format="pattern",
            typecheck=False,
        )

    assert not result.success
    assert result.errors == ["<query>:2:1: error: unknown property"]
    assert result.warnings == ["<query>:1:1: warning: unused variable"]


@pytest.mark.asyncio
async def test_typechecking_requires_operator_configured_dialect() -> None:
    create_process = AsyncMock()
    with (
        patch.dict("os.environ", {"PAQL_EXECUTABLE": "/opt/paql"}, clear=True),
        patch.object(
            paql,
            "_BUNDLED_PAQL_DIALECT_SPEC",
            Path("/missing/solidityDialectSpec.luau"),
        ),
        patch("asyncio.create_subprocess_exec", create_process),
    ):
        result = await paql.validate_source(
            "FIND Contract c",
            source_format="pattern",
            typecheck=True,
        )

    assert not result.success
    assert "PAQL_DIALECT_SPEC" in result.errors[0]
    create_process.assert_not_awaited()


@pytest.mark.asyncio
async def test_typechecking_uses_bundled_solidity_dialect() -> None:
    async def _create_process(*command: str, **_kwargs: object) -> _FakeProcess:
        assert command[4:] == (
            "--dialect-spec",
            str(paql._BUNDLED_PAQL_DIALECT_SPEC),
        )
        return _FakeProcess(returncode=0)

    with (
        patch.dict("os.environ", {}, clear=True),
        patch("asyncio.create_subprocess_exec", side_effect=_create_process),
    ):
        result = await paql.validate_source(
            "FIND Contract c",
            source_format="pattern",
            typecheck=True,
        )

    assert result.success


@pytest.mark.asyncio
async def test_typechecking_passes_and_sanitizes_configured_dialect() -> None:
    with TemporaryDirectory() as temp_dir:
        dialect_path = Path(temp_dir) / "solidity.luau"
        dialect_path.write_text("return {}", encoding="utf-8")

        async def _create_process(*command: str, **_kwargs: object) -> _FakeProcess:
            assert command[4:] == ("--dialect-spec", str(dialect_path))
            return _FakeProcess(
                returncode=1,
                stderr=f"{dialect_path}: error: invalid dialect\n".encode(),
            )

        with (
            patch.dict(
                "os.environ",
                {"PAQL_DIALECT_SPEC": str(dialect_path)},
                clear=True,
            ),
            patch("asyncio.create_subprocess_exec", side_effect=_create_process),
        ):
            result = await paql.validate_source(
                "FIND Contract c",
                source_format="pattern",
                typecheck=True,
            )

    assert not result.success
    assert result.errors == ["<dialect-spec>: error: invalid dialect"]


@pytest.mark.asyncio
async def test_missing_paql_executable_is_a_validation_error() -> None:
    with patch(
        "asyncio.create_subprocess_exec",
        AsyncMock(side_effect=FileNotFoundError),
    ):
        result = await paql.validate_source(
            "FIND Contract c",
            source_format="pattern",
            typecheck=False,
        )

    assert not result.success
    assert "PAQL executable was not found" in result.errors[0]


@pytest.mark.asyncio
async def test_validation_timeout_kills_paql_process() -> None:
    process = _HangingProcess(returncode=-9)
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=process)):
        result = await paql.validate_source(
            "FIND Contract c",
            source_format="pattern",
            typecheck=False,
            timeout_seconds=0.01,
        )

    assert not result.success
    assert process.killed
    assert result.errors == ["PAQL validation timed out after 0.01 seconds."]
