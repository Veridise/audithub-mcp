.DEFAULT_GOAL := help

.PHONY: help sync install dev-install test test-cov lint format type-check check clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

sync: ## Sync dependencies with uv
	uv sync

install: ## Install the package (runtime dependencies only)
	uv pip install -e .

dev-install: ## Install the package with dev dependencies
	uv pip install -e ".[dev]"

test: ## Run tests
	pytest

test-cov: ## Run tests with coverage report
	pytest --cov --cov-report=term-missing

lint: ## Lint source and tests with ruff
	ruff check src tests

format: ## Format source and tests with ruff
	ruff format src tests

type-check: ## Run static type checking with mypy
	mypy

check: lint type-check ## Run lint and type-check

clean: ## Remove build artifacts and caches
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -rf .ruff_cache .mypy_cache .pytest_cache .coverage htmlcov
