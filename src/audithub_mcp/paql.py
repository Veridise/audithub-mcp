"""Safe subprocess adapter for the WebAssembly PAQL validator."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from nodejs_wheel import executable as nodejs_executable

from audithub_mcp.models import PaqlValidationResult

PaqlSourceFormat = Literal["pattern", "query-def"]

_DEFAULT_TIMEOUT_SECONDS = 10.0
_PAQL_NODE_EXECUTABLE_ENV_VAR = "PAQL_NODE_EXECUTABLE"
_PAQL_WASM_MODULE_ENV_VAR = "PAQL_WASM_MODULE"
_PAQL_DIALECT_SPEC_ENV_VAR = "PAQL_DIALECT_SPEC"
_BUNDLED_PAQL_WASM_MODULE = Path(__file__).parent / "_bin" / "paql-wasm.js"
_BUNDLED_PAQL_DIALECT_SPEC = Path(__file__).parent / "_data" / "solidityDialectSpec.luau"


def _resolve_node_executable() -> str:
    """Resolve the operator override or uv-installed Node executable."""
    override = os.environ.get(_PAQL_NODE_EXECUTABLE_ENV_VAR)
    if override:
        return override
    package_dir = Path(nodejs_executable.__file__).parent
    if os.name == "nt":
        return str(package_dir / "node.exe")
    return str(package_dir / "bin" / "node")


def _resolve_paql_wasm_module() -> Path:
    """Resolve the operator override or bundled Emscripten module."""
    override = os.environ.get(_PAQL_WASM_MODULE_ENV_VAR)
    if override:
        return Path(override)
    return _BUNDLED_PAQL_WASM_MODULE


def _resolve_paql_dialect_spec() -> Path | None:
    """Resolve the operator override or bundled Solidity dialect spec."""
    override = os.environ.get(_PAQL_DIALECT_SPEC_ENV_VAR)
    if override:
        return Path(override)
    if _BUNDLED_PAQL_DIALECT_SPEC.is_file():
        return _BUNDLED_PAQL_DIALECT_SPEC
    return None


def _diagnostic_lines(
    contents: bytes,
    *,
    source_path: Path,
    dialect_spec_path: Path | None,
) -> list[str]:
    """Decode PAQL diagnostics and hide server-local filenames."""
    decoded = contents.decode("utf-8", errors="replace")
    sanitized = decoded.replace(str(source_path), "<query>")
    if dialect_spec_path is not None:
        sanitized = sanitized.replace(str(dialect_spec_path), "<dialect-spec>")
    return [line for line in sanitized.splitlines() if line.strip()]


def _split_diagnostics(diagnostics: list[str]) -> tuple[list[str], list[str]]:
    """Separate PAQL warning diagnostics from errors."""
    errors: list[str] = []
    warnings: list[str] = []
    for diagnostic in diagnostics:
        if ": warning:" in diagnostic:
            warnings.append(diagnostic)
        else:
            errors.append(diagnostic)
    return errors, warnings


async def _communicate(
    process: asyncio.subprocess.Process,
    *,
    timeout_seconds: float,
) -> tuple[bytes, bytes] | None:
    """Wait for a PAQL process, terminating it on timeout or cancellation."""
    try:
        return await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except TimeoutError:
        process.kill()
        await process.wait()
        return None
    except asyncio.CancelledError:
        process.kill()
        await process.wait()
        raise


async def validate_source(
    source: str,
    *,
    source_format: PaqlSourceFormat,
    typecheck: bool,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> PaqlValidationResult:
    """Validate PAQL source with the bundled Emscripten WebAssembly module.

    Args:
        source: PAQL pattern text or Luau query-definition text.
        source_format: Input format accepted by the PAQL CLI.
        typecheck: Whether to typecheck using ``PAQL_DIALECT_SPEC``.
        timeout_seconds: Maximum runtime for the validator process.

    Returns:
        A structured validation result containing errors and warnings.
    """
    node_executable = _resolve_node_executable()
    wasm_module = _resolve_paql_wasm_module()
    if not wasm_module.is_file():
        return PaqlValidationResult(
            success=False,
            errors=["The configured PAQL_WASM_MODULE file does not exist."],
        )
    if not wasm_module.with_suffix(".wasm").is_file():
        return PaqlValidationResult(
            success=False,
            errors=["The WebAssembly binary paired with PAQL_WASM_MODULE does not exist."],
        )

    dialect_spec_path: Path | None = None
    if typecheck:
        dialect_spec_path = _resolve_paql_dialect_spec()
        if dialect_spec_path is None:
            return PaqlValidationResult(
                success=False,
                errors=[
                    "PAQL typechecking requires the bundled Solidity dialect spec or "
                    "an operator-configured PAQL_DIALECT_SPEC."
                ],
            )
        if not dialect_spec_path.is_file():
            return PaqlValidationResult(
                success=False,
                errors=["The configured PAQL_DIALECT_SPEC file does not exist."],
            )

    suffix = ".paql" if source_format == "pattern" else ".luau"
    with TemporaryDirectory(prefix="audithub-mcp-paql-") as temp_dir:
        source_path = Path(temp_dir) / f"query{suffix}"
        source_path.write_text(source, encoding="utf-8")
        source_path.chmod(0o600)

        command = [
            node_executable,
            str(wasm_module),
            "validate",
            source_format,
            str(source_path),
        ]
        if typecheck:
            assert dialect_spec_path is not None
            command.extend(["--dialect-spec", str(dialect_spec_path)])
        else:
            command.append("--no-typecheck")

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return PaqlValidationResult(
                success=False,
                errors=[
                    "The PAQL WebAssembly runtime was not found. Reinstall the server "
                    "dependencies or set PAQL_NODE_EXECUTABLE."
                ],
            )
        except OSError:
            return PaqlValidationResult(
                success=False,
                errors=["The configured PAQL WebAssembly runtime could not be started."],
            )

        output = await _communicate(process, timeout_seconds=timeout_seconds)
        if output is None:
            return PaqlValidationResult(
                success=False,
                errors=[f"PAQL validation timed out after {timeout_seconds:g} seconds."],
            )
        _stdout, stderr = output
        diagnostics = _diagnostic_lines(
            stderr,
            source_path=source_path,
            dialect_spec_path=dialect_spec_path,
        )
        errors, warnings = _split_diagnostics(diagnostics)
        if process.returncode != 0:
            return PaqlValidationResult(
                success=False,
                errors=errors or ["PAQL validation failed without error diagnostics."],
                warnings=warnings,
            )
        return PaqlValidationResult(success=True, warnings=warnings)
