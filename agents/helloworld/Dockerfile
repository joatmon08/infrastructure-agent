FROM ghcr.io/astral-sh/uv:0.10-python3.14-alpine AS builder

# Copy the project into the image
COPY . /app

# Disable development dependencies
ENV UV_NO_DEV=1

# Configure the Python directory so it is consistent
ENV UV_PYTHON_INSTALL_DIR=/python

# Only use the managed Python version
ENV UV_PYTHON_PREFERENCE=only-managed

WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

FROM alpine

# Setup a non-root user
RUN addgroup -S -g 1001 nonroot \
 && adduser -S -G nonroot -u 1001 -h nonroot nonroot

# Copy the Python version
COPY --from=builder --chown=python:python /python /python

# Copy the application from the builder
COPY --from=builder --chown=nonroot:nonroot /app /app

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Use the non-root user to run our application
USER nonroot

# Use `/app` as the working directory
WORKDIR /app

# Expose default port (change if needed)
EXPOSE 9999

# Run the agent
CMD python __main__.py