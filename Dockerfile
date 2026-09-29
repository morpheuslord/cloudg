# ═══════════════════════════════════════════════════════════════════
# CloudG — Multi-stage Dockerfile optimized for rapid prototyping
# ═══════════════════════════════════════════════════════════════════
# Layer strategy (fastest → slowest to change):
#   1. scanners  — Prowler, Checkov, Trivy (rarely changes, cached)
#   2. deps      — Python dependencies from pyproject.toml (changes with deps)
#   3. app       — Source code + templates (changes every edit, <5s rebuild)
# ═══════════════════════════════════════════════════════════════════

# ── Stage 1: Security Scanners (heavy, rarely changes) ──
FROM python:3.12-slim AS scanners

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev curl && \
    rm -rf /var/lib/apt/lists/*

# Parliament (IAM linting) — installed globally
RUN pip install --no-cache-dir parliament

# Prowler in isolated venv
RUN python -m venv /opt/prowler && \
    /opt/prowler/bin/pip install --no-cache-dir prowler

# Checkov in isolated venv
RUN python -m venv /opt/checkov && \
    /opt/checkov/bin/pip install --no-cache-dir checkov

# Trivy CLI binary — detect architecture and install correct binary
RUN ARCH=$(dpkg --print-architecture) && \
    echo "Installing Trivy for architecture: ${ARCH}" && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    trivy --version


# ── Stage 2: Python Dependencies (changes only when pyproject.toml changes) ──
FROM python:3.12-slim AS deps

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# uv — fast dependency resolution and installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy ONLY the dependency file — this layer is cached until deps change
COPY pyproject.toml ./
RUN uv pip install --system --no-cache -r pyproject.toml \
    --extra aws --extra azure --extra gcp


# ── Stage 3: Application (changes every code edit — instant rebuild) ──
FROM python:3.12-slim

LABEL maintainer="CloudG Team"
LABEL description="Cloud Infrastructure Mapping & Security Intelligence Agent"

WORKDIR /app

# System utils — including libffi for C-extensions used by checkov/prowler
RUN apt-get update && apt-get install -y --no-install-recommends \
    graphviz libffi8 && \
    rm -rf /var/lib/apt/lists/*

# Copy Python packages from deps stage (cached unless pyproject.toml changes)
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

# Copy scanners from scanner stage (cached unless scanner stage changes)
# Copy the full venvs so their internal site-packages and Python are intact
COPY --from=scanners /opt/prowler /opt/prowler
COPY --from=scanners /opt/checkov /opt/checkov
COPY --from=scanners /usr/local/bin/trivy /usr/local/bin/trivy

# Create CLI symlinks so 'checkov' and 'prowler' are on PATH
RUN ln -sf /opt/prowler/bin/prowler /usr/local/bin/prowler && \
    ln -sf /opt/checkov/bin/checkov /usr/local/bin/checkov

# Verify all scanner tools are accessible
RUN echo "=== Verifying scanner installations ===" && \
    prowler --version  || echo "WARNING: prowler not working" && \
    checkov --version  || echo "WARNING: checkov not working" && \
    trivy --version    || echo "WARNING: trivy not working" && \
    echo "=== Scanner verification complete ==="

# Parliament (IAM linting) — small pure-Python package, install directly
RUN pip install --no-cache-dir parliament

# ── Everything below here rebuilds on every code change (fast) ──

# Copy source code last — only this layer busts cache on code edits
# (templates, rules and policies ship inside the cloudg package)
COPY --from=deps /usr/local/bin/uv /usr/local/bin/uv
COPY cloudg/ ./cloudg/
COPY pyproject.toml README.md ./
# The package readme rendered on PyPI; hatchling refuses to build without it
COPY docs/DOCUMENTATION.md ./docs/DOCUMENTATION.md

# Install cloudg package (no-deps since deps are already installed from stage 2)
RUN uv pip install --system --no-cache --no-deps .

# Reports output directory
RUN mkdir -p /app/reports

ENTRYPOINT ["cloudg"]
CMD ["--help"]
