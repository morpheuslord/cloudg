#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# CloudG Auto-Install Script (Linux / macOS)
# Installs ALL Python deps, system packages, and security scanner tools.
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $1"; }

echo -e "${BOLD}☁️  CloudG Full Auto-Installer${NC}"
echo "─────────────────────────────────────────────────"

# ── Detect OS & package manager ──
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        if command -v brew &> /dev/null; then
            PKG_MGR="brew"
        else
            info "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            PKG_MGR="brew"
        fi
    elif command -v apt-get &> /dev/null; then
        OS="debian"
        PKG_MGR="apt"
    elif command -v dnf &> /dev/null; then
        OS="fedora"
        PKG_MGR="dnf"
    elif command -v yum &> /dev/null; then
        OS="rhel"
        PKG_MGR="yum"
    elif command -v pacman &> /dev/null; then
        OS="arch"
        PKG_MGR="pacman"
    elif command -v zypper &> /dev/null; then
        OS="suse"
        PKG_MGR="zypper"
    else
        OS="unknown"
        PKG_MGR="none"
    fi
    ok "Detected OS: $OS (package manager: $PKG_MGR)"
}

# ── Install a system package via the detected package manager ──
install_sys_pkg() {
    local pkg_apt="$1"
    local pkg_brew="${2:-$1}"
    local pkg_dnf="${3:-$1}"
    local pkg_pacman="${4:-$1}"

    case "$PKG_MGR" in
        apt)     sudo apt-get install -y "$pkg_apt" ;;
        brew)    brew install "$pkg_brew" ;;
        dnf)     sudo dnf install -y "$pkg_dnf" ;;
        yum)     sudo yum install -y "$pkg_dnf" ;;
        pacman)  sudo pacman -S --noconfirm "$pkg_pacman" ;;
        zypper)  sudo zypper install -y "$pkg_apt" ;;
        *)       warn "Cannot auto-install '$pkg_apt' — unknown package manager" ; return 1 ;;
    esac
}

detect_os

# ── 1. System Prerequisites ──
echo ""
info "Installing system prerequisites..."

# Update package index (apt only, others don't need it)
if [[ "$PKG_MGR" == "apt" ]]; then
    sudo apt-get update -qq
fi

# curl, git, unzip (needed for various installers)
for tool in curl git unzip; do
    if ! command -v "$tool" &> /dev/null; then
        info "Installing $tool..."
        install_sys_pkg "$tool" "$tool" "$tool" "$tool" && ok "$tool installed" || warn "Could not install $tool"
    else
        ok "$tool found"
    fi
done

# ── 2. Python 3.11+ ──
echo ""
info "Checking Python version..."
PYTHON_CMD=""
for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" &> /dev/null; then
        PY_VERSION=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
            PYTHON_CMD="$candidate"
            ok "Python $PY_VERSION found ($candidate)"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    info "Python 3.11+ not found, attempting install..."
    case "$PKG_MGR" in
        apt)
            sudo apt-get install -y software-properties-common
            sudo add-apt-repository -y ppa:deadsnakes/ppa 2>/dev/null || true
            sudo apt-get update -qq
            sudo apt-get install -y python3.11 python3.11-venv python3.11-dev
            PYTHON_CMD="python3.11"
            ;;
        brew)
            brew install python@3.11
            PYTHON_CMD="python3.11"
            ;;
        dnf|yum)
            sudo "$PKG_MGR" install -y python3.11 python3.11-devel 2>/dev/null || \
            sudo "$PKG_MGR" install -y python311 python311-devel 2>/dev/null || {
                fail "Could not install Python 3.11. Please install manually."
                exit 1
            }
            PYTHON_CMD="python3.11"
            ;;
        pacman)
            sudo pacman -S --noconfirm python
            PYTHON_CMD="python3"
            ;;
        *)
            fail "Python 3.11+ is required. Please install manually: https://python.org"
            exit 1
            ;;
    esac

    if command -v "$PYTHON_CMD" &> /dev/null; then
        ok "Python installed: $($PYTHON_CMD --version)"
    else
        fail "Python installation failed"
        exit 1
    fi
fi

# Ensure venv module is available
if ! "$PYTHON_CMD" -m venv --help &> /dev/null 2>&1; then
    info "Installing python3-venv..."
    install_sys_pkg "python3-venv" "" "python3-devel" "python" 2>/dev/null || \
    install_sys_pkg "python3.11-venv" "" "" "" 2>/dev/null || \
    warn "Could not install venv module. You may need: sudo apt install python3.11-venv"
fi

# ── 3. Graphviz (for SVG topology renderings) ──
echo ""
info "Installing Graphviz..."
if command -v dot &> /dev/null; then
    ok "Graphviz already installed"
else
    install_sys_pkg graphviz graphviz graphviz graphviz && ok "Graphviz installed" || warn "Could not auto-install Graphviz"
fi

# ── 4. Node.js (for CloudSploit — optional) ──
echo ""
info "Checking Node.js..."
if command -v node &> /dev/null; then
    ok "Node.js $(node --version) found"
else
    info "Installing Node.js 20 LTS..."
    case "$PKG_MGR" in
        apt)
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 2>/dev/null
            sudo apt-get install -y nodejs
            ;;
        brew)
            brew install node@20
            ;;
        dnf|yum)
            curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash - 2>/dev/null
            sudo "$PKG_MGR" install -y nodejs
            ;;
        pacman)
            sudo pacman -S --noconfirm nodejs npm
            ;;
        *)
            warn "Could not auto-install Node.js. Install from: https://nodejs.org/"
            ;;
    esac
    command -v node &> /dev/null && ok "Node.js $(node --version) installed" || warn "Node.js installation failed"
fi

# ── 5. uv (package manager) ──
echo ""
if ! command -v uv &> /dev/null; then
    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi
command -v uv &> /dev/null && ok "uv $(uv --version | cut -d' ' -f2) found" || { fail "uv installation failed"; exit 1; }

# ── 6. Create virtual environment ──
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    info "Creating virtual environment..."
    uv venv "$VENV_DIR" --python "$PYTHON_CMD"
    ok "Virtual environment created at $VENV_DIR"
else
    ok "Virtual environment already exists"
fi

# Activate
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
ok "Virtual environment activated"

# ── 7. Install CloudG + all deps ──
echo ""
info "Installing CloudG with full dependencies..."
uv pip install -e ".[all,dev]" --quiet && ok "CloudG core + dev installed" || {
    warn "editable install failed, installing deps directly..."
    uv pip install pydantic click rich aioboto3 boto3 networkx jinja2 svgwrite aiofiles parliament \
        pytest pytest-asyncio moto --quiet
    ok "Core dependencies installed"
}

# Attempt full extras (may have optional heavy deps)
uv pip install -e ".[full]" --quiet 2>/dev/null && ok "Full extras installed" || warn "Some optional extras not available"

# ── 8. Install Security Scanner Tools ──
echo ""
echo -e "${BOLD}Installing Security Scanner Tools${NC}"
echo "─────────────────────────────────────────────────"

# Prowler
info "Installing Prowler..."
if command -v prowler &> /dev/null; then
    ok "Prowler already installed: $(prowler --version 2>/dev/null || echo 'version unknown')"
else
    uv pip install prowler --quiet 2>/dev/null && ok "Prowler installed via pip" || warn "Prowler install failed (try: uv pip install prowler)"
fi

# Checkov
info "Installing Checkov..."
if command -v checkov &> /dev/null; then
    ok "Checkov already installed"
else
    uv pip install checkov --quiet 2>/dev/null && ok "Checkov installed via pip" || warn "Checkov install failed (try: uv pip install checkov)"
fi

# ScoutSuite
info "Installing ScoutSuite..."
if command -v scout &> /dev/null; then
    ok "ScoutSuite already installed"
else
    uv pip install scoutsuite --quiet 2>/dev/null && ok "ScoutSuite installed via pip" || warn "ScoutSuite install failed (try: uv pip install scoutsuite)"
fi

# Parliament (IAM linter)
info "Installing Parliament..."
uv pip install parliament --quiet 2>/dev/null && ok "Parliament installed" || warn "Parliament install failed"

# Policy Sentry
info "Installing Policy Sentry..."
uv pip install policy-sentry --quiet 2>/dev/null && ok "Policy Sentry installed" || warn "Policy Sentry install failed"

# Trivy (binary — not a pip package)
echo ""
info "Installing Trivy..."
if command -v trivy &> /dev/null; then
    ok "Trivy already installed: $(trivy --version 2>/dev/null | head -1)"
else
    case "$OS" in
        macos)
            brew install trivy 2>/dev/null && ok "Trivy installed via Homebrew" || {
                info "Trying Trivy install script..."
                curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null \
                    && ok "Trivy installed" || warn "Trivy install failed. Get it from: https://trivy.dev/"
            }
            ;;
        debian|fedora|rhel|arch|suse)
            # Try official install script first
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin 2>/dev/null \
                && ok "Trivy installed" || {
                # Fallback: try distro-specific repos
                case "$PKG_MGR" in
                    apt)
                        sudo apt-get install -y wget apt-transport-https gnupg lsb-release 2>/dev/null
                        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null 2>&1
                        echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list 2>/dev/null
                        sudo apt-get update -qq 2>/dev/null && sudo apt-get install -y trivy 2>/dev/null \
                            && ok "Trivy installed via apt" || warn "Trivy install failed"
                        ;;
                    dnf|yum)
                        sudo rpm --import https://aquasecurity.github.io/trivy-repo/rpm/public.key 2>/dev/null || true
                        cat << 'REPO' | sudo tee /etc/yum.repos.d/trivy.repo > /dev/null
[trivy]
name=Trivy
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
REPO
                        sudo "$PKG_MGR" install -y trivy 2>/dev/null \
                            && ok "Trivy installed via $PKG_MGR" || warn "Trivy install failed"
                        ;;
                    *)
                        warn "Could not auto-install Trivy. Get it from: https://trivy.dev/"
                        ;;
                esac
            }
            ;;
        *)
            warn "Cannot auto-install Trivy on this OS. Get it from: https://trivy.dev/"
            ;;
    esac
fi

# CloudSploit (npm — optional)
echo ""
info "Installing CloudSploit..."
if command -v cloudsploit &> /dev/null; then
    ok "CloudSploit already installed"
elif command -v npm &> /dev/null; then
    sudo npm install -g @aqua-security/cloudsploit --silent 2>/dev/null \
        && ok "CloudSploit installed via npm" || warn "CloudSploit install failed (optional)"
else
    warn "npm not available, skipping CloudSploit (optional)"
fi

# Cloud Custodian (pip)
info "Installing Cloud Custodian..."
uv pip install c7n --quiet 2>/dev/null && ok "Cloud Custodian (c7n) installed" || warn "Cloud Custodian install failed (optional)"

# ── 9. Install cloud CLIs (if missing) ──
echo ""
echo -e "${BOLD}Checking Cloud Provider CLIs${NC}"
echo "─────────────────────────────────────────────────"

# AWS CLI v2
if command -v aws &> /dev/null; then
    ok "AWS CLI found: $(aws --version 2>/dev/null | head -1)"
else
    info "Installing AWS CLI v2..."
    case "$OS" in
        macos)
            brew install awscli 2>/dev/null && ok "AWS CLI installed" || warn "AWS CLI install failed"
            ;;
        debian|fedora|rhel|arch|suse)
            curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip" 2>/dev/null
            unzip -qo /tmp/awscliv2.zip -d /tmp/ 2>/dev/null
            sudo /tmp/aws/install --update 2>/dev/null && ok "AWS CLI v2 installed" || warn "AWS CLI install failed. Get it from: https://aws.amazon.com/cli/"
            rm -rf /tmp/awscliv2.zip /tmp/aws
            ;;
        *)
            warn "Cannot auto-install AWS CLI. Get it from: https://aws.amazon.com/cli/"
            ;;
    esac
fi

# Azure CLI
if command -v az &> /dev/null; then
    ok "Azure CLI found: $(az version --output tsv 2>/dev/null | head -1)"
else
    info "Installing Azure CLI..."
    case "$OS" in
        macos)
            brew install azure-cli 2>/dev/null && ok "Azure CLI installed" || warn "Azure CLI install failed"
            ;;
        debian)
            curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash 2>/dev/null && ok "Azure CLI installed" || warn "Azure CLI install failed"
            ;;
        fedora|rhel)
            sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc 2>/dev/null || true
            sudo "$PKG_MGR" install -y azure-cli 2>/dev/null && ok "Azure CLI installed" || {
                uv pip install azure-cli --quiet 2>/dev/null && ok "Azure CLI installed via pip" || warn "Azure CLI install failed"
            }
            ;;
        *)
            uv pip install azure-cli --quiet 2>/dev/null && ok "Azure CLI installed via pip" || warn "Azure CLI install failed"
            ;;
    esac
fi

# gcloud CLI
if command -v gcloud &> /dev/null; then
    ok "gcloud CLI found: $(gcloud version 2>/dev/null | head -1)"
else
    info "Installing gcloud CLI..."
    case "$OS" in
        macos)
            brew install --cask google-cloud-sdk 2>/dev/null && ok "gcloud installed" || warn "gcloud install failed"
            ;;
        debian)
            curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg 2>/dev/null
            echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list 2>/dev/null
            sudo apt-get update -qq 2>/dev/null && sudo apt-get install -y google-cloud-cli 2>/dev/null \
                && ok "gcloud installed" || warn "gcloud install failed. Get it from: https://cloud.google.com/sdk"
            ;;
        *)
            warn "Cannot auto-install gcloud. Get it from: https://cloud.google.com/sdk/docs/install"
            ;;
    esac
fi

# ── 10. Verify CloudG Installation ──
echo ""
echo -e "${BOLD}Verifying Installation${NC}"
echo "─────────────────────────────────────────────────"

if cloudg --version &> /dev/null; then
    VERSION=$(cloudg --version 2>/dev/null)
    ok "cloudg $VERSION"
else
    warn "CloudG CLI not on PATH — trying direct invocation"
    "$PYTHON_CMD" -m cloudg.cli --version 2>/dev/null && ok "CloudG accessible via python -m" || warn "CloudG CLI not yet functional"
fi

# ── 11. Summary ──
echo ""
echo -e "${BOLD}────────── Installation Summary ──────────${NC}"

declare -A TOOLS=(
    ["CloudG"]="cloudg"
    ["Prowler"]="prowler"
    ["Checkov"]="checkov"
    ["ScoutSuite"]="scout"
    ["Trivy"]="trivy"
    ["AWS CLI"]="aws"
    ["Azure CLI"]="az"
    ["gcloud CLI"]="gcloud"
    ["Graphviz"]="dot"
    ["Node.js"]="node"
)

for name in "${!TOOLS[@]}"; do
    cmd="${TOOLS[$name]}"
    if command -v "$cmd" &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $name"
    else
        echo -e "  ${YELLOW}✗${NC} $name (not found)"
    fi
done

echo ""
echo -e "${GREEN}${BOLD}✓ Installation complete!${NC}"
echo ""
echo "Usage:"
echo "  source $VENV_DIR/bin/activate"
echo "  cloudg --help"
echo "  cloudg collect --provider aws --region us-east-1"
echo "  cloudg run --provider aws -o ./reports"
echo ""
echo "To run Cloud Custodian policies:"
echo "  custodian run --output-dir ./custodian-output cloudg/policies/custodian.yml"
