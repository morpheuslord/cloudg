# ── Stage 1: Build ──
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps for building wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip install --no-cache-dir poetry poetry-core

# Copy dependencies first (cache layer)
COPY pyproject.toml ./
RUN poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --no-root --only main 2>/dev/null || true

# Copy full source and install cloudmapper
COPY . .
RUN poetry build -f wheel && \
    pip install --no-deps dist/*.whl

# ── Isolated Security Scanners ──
# Installing these in separate venvs prevents extremely slow dependency backtracking
# and avoids breaking cloudmapper's boto3/aioboto3 versions.
RUN pip install --no-cache-dir parliament
RUN python -m venv /opt/prowler && /opt/prowler/bin/pip install --no-cache-dir prowler
RUN python -m venv /opt/checkov && /opt/checkov/bin/pip install --no-cache-dir checkov

# ── Stage 2: Runtime ──
FROM python:3.12-slim

LABEL maintainer="CloudMapper Team"
LABEL description="Cloud Infrastructure Mapping & Security Intelligence Agent"

WORKDIR /app

# Graphviz for diagram rendering + curl for trivy
RUN apt-get update && apt-get install -y --no-install-recommends \
    graphviz curl && \
    rm -rf /var/lib/apt/lists/*

# Install Trivy CLI binary
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Copy CloudMapper from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy Isolated Scanners from builder
COPY --from=builder /opt /opt
RUN ln -s /opt/prowler/bin/prowler /usr/local/bin/prowler && \
    ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov

# Copy templates, rules, etc.
COPY templates/ ./templates/
COPY rules/ ./rules/

# Reports output directory
RUN mkdir -p /app/reports

ENTRYPOINT ["cloudmapper"]
CMD ["--help"]
