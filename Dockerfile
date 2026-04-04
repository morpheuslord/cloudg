# ─────────────────────────────────────────────────────────────────
# CloudMapper Docker Image
# python:3.11-slim + all Python deps + Node.js for CloudSploit
# ─────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS base

LABEL maintainer="CloudMapper Team"
LABEL description="Cloud Infrastructure Mapping & Security Intelligence Agent"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    graphviz \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20 LTS (for CloudSploit)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Working directory
WORKDIR /app

# Install Python dependencies first (cache layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]" 2>/dev/null || \
    pip install --no-cache-dir pydantic click rich aioboto3 boto3 networkx jinja2 svgwrite aiofiles parliament \
    pytest pytest-asyncio moto

# Install CloudSploit (optional)
RUN npm install -g @aqua-security/cloudsploit 2>/dev/null || true

# Copy application code
COPY . .

# Install the package
RUN pip install --no-cache-dir -e .

# Default entrypoint
ENTRYPOINT ["cloudmapper"]
CMD ["--help"]
