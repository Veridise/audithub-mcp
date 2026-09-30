# syntax=docker/dockerfile:1

FROM ghcr.io/astral-sh/uv:0.12.7 AS uv

FROM python:3.12-slim-bookworm

COPY --from=uv /uv /uvx /bin/

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Install locked third-party dependencies before copying the source so this
# layer remains cached when only application code changes.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

COPY src ./src
RUN uv sync --locked --no-dev --no-editable

RUN useradd --create-home --uid 10001 audithub \
    && mkdir /data \
    && chown audithub:audithub /data

USER audithub
WORKDIR /data

ENTRYPOINT ["audithub-mcp"]
