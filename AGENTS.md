# AI Agent Instructions

Instructions for AI agents working in this repository.

Repository-wide project details: `./docs/architecture.md`
Coding conventions: `./docs/llm-conventions.md`

## Project Structure

- Treat each MCP server under `src/<server>/` as independent; avoid changes that
  can break unrelated servers.
- Tests belong in `src/<server>/tests`

## Development Instructions

- Check that the virtual environment is active (in `VIRTUAL_ENV` environment
  variable) before running any commands.
  Otherwise, stop and refuse to do anything.
- Do not attempt to manage dependencies (install packages, etc.) unless explicitly asked to.
- Run `ruff check`, `mypy`, and `pytest` after functional changes.
- Format code with `ruff format`
- Update relevant files in `docs/` after making major changes.
