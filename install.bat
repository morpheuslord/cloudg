@echo off
REM ─────────────────────────────────────────────────────────────────
REM CloudMapper Auto-Install Script (Windows)
REM Installs ALL Python deps, system packages, and security scanner tools.
REM Run from the cloudmapper project root directory.
REM ─────────────────────────────────────────────────────────────────
setlocal enabledelayedexpansion

echo ☁️  CloudMapper Full Auto-Installer (Windows)
echo ─────────────────────────────────────────────────

REM ── 1. Python version check ──
echo [INFO]  Checking Python version...
python --version >nul 2>&1
if errorlevel 1 (
    echo [INFO]  Python not found. Attempting install via winget...
    winget install Python.Python.3.11 --accept-package-agreements --accept-source-agreements >nul 2>&1
    if errorlevel 1 (
        echo [FAIL]  Could not auto-install Python.
        echo         Download from: https://www.python.org/downloads/
        exit /b 1
    )
    echo [OK]    Python installed via winget. Please restart your terminal and re-run this script.
    exit /b 0
)

for /f "tokens=2 delims= " %%i in ('python --version 2^>^&1') do set PY_VERSION=%%i
for /f "tokens=1,2 delims=." %%a in ("%PY_VERSION%") do (
    set PY_MAJOR=%%a
    set PY_MINOR=%%b
)
if %PY_MAJOR% LSS 3 (
    echo [FAIL]  Python 3.11+ is required ^(found %PY_VERSION%^)
    exit /b 1
)
if %PY_MINOR% LSS 11 (
    echo [FAIL]  Python 3.11+ is required ^(found %PY_VERSION%^)
    exit /b 1
)
echo [OK]    Python %PY_VERSION% found

REM ── 2. Check for Chocolatey or winget (for system tools) ──
set HAS_CHOCO=0
set HAS_WINGET=0
where choco >nul 2>&1 && set HAS_CHOCO=1
where winget >nul 2>&1 && set HAS_WINGET=1

REM ── 3. Install Graphviz ──
echo.
echo [INFO]  Checking Graphviz...
where dot >nul 2>&1
if errorlevel 1 (
    echo [INFO]  Installing Graphviz...
    if %HAS_CHOCO%==1 (
        choco install graphviz -y >nul 2>&1 && echo [OK]    Graphviz installed || echo [WARN]  Graphviz install failed
    ) else if %HAS_WINGET%==1 (
        winget install Graphviz.Graphviz --accept-package-agreements --accept-source-agreements >nul 2>&1 && echo [OK]    Graphviz installed || echo [WARN]  Graphviz install failed
    ) else (
        echo [WARN]  Cannot auto-install Graphviz. Get it from: https://graphviz.org/download/
    )
) else (
    echo [OK]    Graphviz found
)

REM ── 4. Create virtual environment ──
echo.
set VENV_DIR=.venv
if not exist "%VENV_DIR%" (
    echo [INFO]  Creating virtual environment...
    python -m venv %VENV_DIR%
    echo [OK]    Virtual environment created at %VENV_DIR%
) else (
    echo [OK]    Virtual environment already exists
)

REM Activate
call %VENV_DIR%\Scripts\activate.bat
echo [OK]    Virtual environment activated

REM ── 5. Upgrade pip ──
echo [INFO]  Upgrading pip, setuptools, wheel...
pip install --upgrade pip setuptools wheel --quiet
echo [OK]    Build tools upgraded

REM ── 6. Install CloudMapper ──
echo.
echo [INFO]  Installing CloudMapper with all dependencies...
pip install -e ".[dev]" --quiet 2>nul
if errorlevel 1 (
    echo [WARN]  Editable install failed, installing deps directly...
    pip install pydantic click rich aioboto3 boto3 networkx jinja2 svgwrite aiofiles parliament pytest pytest-asyncio moto --quiet
)
echo [OK]    CloudMapper installed

pip install -e ".[full]" --quiet 2>nul
if not errorlevel 1 echo [OK]    Full extras installed

REM ── 7. Install Security Scanner Tools ──
echo.
echo Installing Security Scanner Tools
echo ─────────────────────────────────────────────────

echo [INFO]  Installing Prowler...
where prowler >nul 2>&1
if errorlevel 1 (
    pip install prowler --quiet 2>nul && echo [OK]    Prowler installed || echo [WARN]  Prowler install failed
) else (
    echo [OK]    Prowler already installed
)

echo [INFO]  Installing Checkov...
where checkov >nul 2>&1
if errorlevel 1 (
    pip install checkov --quiet 2>nul && echo [OK]    Checkov installed || echo [WARN]  Checkov install failed
) else (
    echo [OK]    Checkov already installed
)

echo [INFO]  Installing ScoutSuite...
where scout >nul 2>&1
if errorlevel 1 (
    pip install scoutsuite --quiet 2>nul && echo [OK]    ScoutSuite installed || echo [WARN]  ScoutSuite install failed
) else (
    echo [OK]    ScoutSuite already installed
)

echo [INFO]  Installing Parliament ^& Policy Sentry...
pip install parliament --quiet 2>nul && echo [OK]    Parliament installed || echo [WARN]  Parliament install failed
pip install policy-sentry --quiet 2>nul && echo [OK]    Policy Sentry installed || echo [WARN]  Policy Sentry install failed

echo [INFO]  Installing Cloud Custodian...
pip install c7n --quiet 2>nul && echo [OK]    Cloud Custodian installed || echo [WARN]  Cloud Custodian install failed

REM Trivy (binary)
echo.
echo [INFO]  Checking Trivy...
where trivy >nul 2>&1
if errorlevel 1 (
    if %HAS_CHOCO%==1 (
        echo [INFO]  Installing Trivy via Chocolatey...
        choco install trivy -y >nul 2>&1 && echo [OK]    Trivy installed || echo [WARN]  Trivy install failed
    ) else if %HAS_WINGET%==1 (
        echo [INFO]  Installing Trivy via winget...
        winget install AquaSecurity.Trivy --accept-package-agreements --accept-source-agreements >nul 2>&1 && echo [OK]    Trivy installed || echo [WARN]  Trivy install failed
    ) else (
        echo [WARN]  Cannot auto-install Trivy. Get it from: https://trivy.dev/
    )
) else (
    echo [OK]    Trivy already installed
)

REM ── 8. Cloud Provider CLIs ──
echo.
echo Checking Cloud Provider CLIs
echo ─────────────────────────────────────────────────

where aws >nul 2>&1
if errorlevel 1 (
    echo [INFO]  Installing AWS CLI...
    if %HAS_WINGET%==1 (
        winget install Amazon.AWSCLI --accept-package-agreements --accept-source-agreements >nul 2>&1 && echo [OK]    AWS CLI installed || echo [WARN]  AWS CLI install failed
    ) else if %HAS_CHOCO%==1 (
        choco install awscli -y >nul 2>&1 && echo [OK]    AWS CLI installed || echo [WARN]  AWS CLI install failed
    ) else (
        echo [WARN]  Cannot auto-install AWS CLI. Get it from: https://aws.amazon.com/cli/
    )
) else (
    echo [OK]    AWS CLI found
)

where az >nul 2>&1
if errorlevel 1 (
    echo [INFO]  Installing Azure CLI...
    if %HAS_WINGET%==1 (
        winget install Microsoft.AzureCLI --accept-package-agreements --accept-source-agreements >nul 2>&1 && echo [OK]    Azure CLI installed || echo [WARN]  Azure CLI install failed
    ) else if %HAS_CHOCO%==1 (
        choco install azure-cli -y >nul 2>&1 && echo [OK]    Azure CLI installed || echo [WARN]  Azure CLI install failed
    ) else (
        echo [WARN]  Cannot auto-install Azure CLI. Get it from: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli
    )
) else (
    echo [OK]    Azure CLI found
)

where gcloud >nul 2>&1
if errorlevel 1 (
    echo [INFO]  Installing gcloud CLI...
    if %HAS_CHOCO%==1 (
        choco install gcloudsdk -y >nul 2>&1 && echo [OK]    gcloud installed || echo [WARN]  gcloud install failed
    ) else (
        echo [WARN]  Cannot auto-install gcloud. Get it from: https://cloud.google.com/sdk/docs/install
    )
) else (
    echo [OK]    gcloud CLI found
)

REM ── 9. Verify ──
echo.
echo Verifying Installation
echo ─────────────────────────────────────────────────

cloudmapper --version >nul 2>&1
if errorlevel 1 (
    echo [WARN]  CloudMapper CLI not yet on PATH
) else (
    for /f "tokens=*" %%v in ('cloudmapper --version 2^>^&1') do echo [OK]    cloudmapper %%v
)

echo.
echo ✓ Installation complete!
echo.
echo Usage:
echo   %VENV_DIR%\Scripts\activate.bat
echo   cloudmapper --help
echo   cloudmapper collect --provider aws --region us-east-1
echo   cloudmapper run --provider aws -o .\reports

endlocal
