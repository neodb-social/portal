# syntax=docker/dockerfile:1

# Two stages: resolve the locked environment with uv, then run it on a clean
# slim image so the build toolchain never ships to production.
FROM python:3.14-slim AS build

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /src
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

# Locked dependencies first, so editing source does not invalidate the layer.
# Extras are opt-in, so the `dev` extra never reaches the image.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev

COPY pyproject.toml uv.lock README.md ./
COPY neodb_portal ./neodb_portal

# --no-editable installs the project as a built wheel, so /opt/venv is
# self-contained and /src need not exist in the runtime stage.
#
# --reinstall-package is not optional: the version stays 0.1.0 across source
# edits, so uv will happily serve a stale neodb-portal wheel out of the mounted
# cache above and the image ships code that is not in the build context. Forcing
# the rebuild is the difference between shipping HEAD and shipping whatever was
# cached first.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-editable --no-dev --reinstall-package neodb-portal


FROM python:3.14-slim AS runtime

# Runs unprivileged: this service takes hostnames from strangers and makes
# outbound requests with them, so it should own as little as possible.
RUN useradd --system --create-home --uid 10001 portal

COPY --from=build /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORTAL_HOST=0.0.0.0 \
    PORTAL_PORT=8080

USER portal
WORKDIR /home/portal
EXPOSE 8080

# No volumes and nothing to persist: sessions live in memory and are meant to
# die with the process.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,os; \
urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('PORTAL_PORT','8080')}/healthz\").read()"

CMD ["neodb-portal"]
