---
title: Installation
lede: "cloudg is a Python package with optional extras per cloud provider. The security scanners it drives are separate programs that you install next to it, or get prebuilt in the Docker image."
meta:
  - [Python, "3.11 or newer"]
  - [Package, "`cloudg` on PyPI"]
  - [Image, "`ghcr.io/morpheuslord/cloudg`"]
source: pyproject.toml
---

There are two things to install, and it helps to keep them apart. The first is cloudg itself: the CLI, the graph engine, the normaliser, the report renderers and, through extras, the cloud SDKs. The second is the set of scanners (Prowler, ScoutSuite, Checkov, Trivy) that `cloudg run` and `cloudg scan` call as subprocesses. cloudg works with any subset of them, including none.

## Requirements

cloudg needs Python 3.11 or newer (`requires-python = ">=3.11"`). The Docker image is built on `python:3.12-slim`. Nothing else is required for the core package: no database, no daemon, no Node.js.

Credentials are not needed to install, and not needed at all for `cloudg ingest`, `cloudg report`, `cloudg deps` or the MCP server reading saved files. Only the commands that talk to a cloud (`run`, `collect`, `scan`, `map`) need them.

## Install cloudg

```bash tab="pip"
python3 -m venv .venv
source .venv/bin/activate
pip install "cloudg[all]"
```

```bash tab="uv"
# as a standalone CLI in its own environment
uv tool install "cloudg[all]"
# or into the current project's virtualenv
uv pip install "cloudg[all]"
```

```bash tab="Docker"
docker pull ghcr.io/morpheuslord/cloudg:latest
docker run --rm ghcr.io/morpheuslord/cloudg:latest --version
```

Quote the package spec. In zsh, unquoted square brackets are a glob pattern and `pip install cloudg[all]` fails with "no matches found".

The Docker image already contains cloudg, the AWS, Azure and GCP SDKs, Prowler, Checkov, Trivy and Parliament. It is the shortest way to the full pipeline; [Docker](/guides/docker/) covers running it with credentials and volumes.

### From a source checkout

Contributors, and anyone who wants the newest code on `main`, install in editable mode:

```bash
git clone https://github.com/morpheuslord/cloudg.git
cd cloudg
uv venv
source .venv/bin/activate
uv pip install -e ".[all,dev]"
```

Plain pip works the same way: `pip install -e ".[all,dev]"`.

## Extras

The cloud SDKs are optional, so a machine that only aggregates scanner output does not pull in boto3 or the Azure management libraries.

| Extra | Adds | Install it when |
|---|---|---|
| none | pydantic, click, rich, PyYAML, NetworkX, rdflib, python-louvain, Parliament, Jinja2, svgwrite, aiofiles | You only ingest existing scanner output, re-render reports, or explore saved maps |
| `aws` | `boto3>=1.28`, `aioboto3>=12.0` | You collect from or map AWS |
| `azure` | `azure-identity`, the compute, network, storage, resource, SQL and Key Vault management SDKs, `azure-mgmt-resourcegraph` | You collect from or map Azure |
| `gcp` | `google-cloud-asset>=3.0`, `google-auth>=2.22` | You collect from or map GCP |
| `mcp` | the official MCP SDK, `mcp>=1.30,<3` | You want the SDK flavor of the MCP server or to mount cloudg into an SDK server. The native MCP server needs no extra |
| `all` | `aws`, `azure`, `gcp` and `mcp` together | You are not sure yet |
| `dev` | `aws`, `mcp`, pytest, pytest-asyncio, `moto[all]`, ruff | You work on cloudg itself |
| `full` | diagrams, weasyprint, policy-sentry | Rarely; see the note below |

Extras combine: `pip install "cloudg[aws,gcp]"` gets exactly two providers.

:::note What the core package can do on its own
Without any extra you still get the graph builder, the ontology, the RAG exporter, the findings normaliser with every compliance ruleset, all four scanner parsers, the HTML, JSON and SVG renderers, and the MCP layer with its native server. That is enough for `cloudg ingest` on an air-gapped analysis host.
:::

About `full`: in 0.6.0 the IAM linter only checks whether `policy_sentry` can be imported, and nothing in the package imports `diagrams` or `weasyprint`. Installing `full` does no harm, but it changes no output today.

If the extra for a provider is missing, collection from that provider cannot import its SDK and fails; the error is logged and the other providers carry on. Install the extra and run again.

## Scanner binaries {#scanner-binaries}

cloudg looks each scanner up on `PATH` at the moment it runs it. A missing one is logged ("Prowler is not installed... Skipping Prowler scan.") and the pipeline carries on with the others. So you can start with nothing and add scanners as you need them.

| Scanner | Executable | Install | Used by |
|---|---|---|---|
| Prowler | `prowler` | `pip install prowler` | `run`, `scan`: once per provider |
| ScoutSuite | `scout` | `pip install scoutsuite` | `run`, `scan`: once per provider |
| Checkov | `checkov` | `pip install checkov` | `run`, `scan`: once per IaC directory |
| Trivy | `trivy` | binary, see below | `run`, `scan`: images, or a filesystem fallback |
| IAM linter | none | ships with cloudg (Parliament is a core dependency) | `run`, `scan`: always, when there are IAM assets |

Prowler, ScoutSuite and Checkov are Python applications with large, pinned dependency trees. Putting them in the same virtualenv as cloudg works until two of them disagree about a version. The Docker image avoids that by giving Prowler and Checkov a venv each and symlinking their executables into `/usr/local/bin`. On a workstation, `pipx` or `uv tool` gives you the same isolation:

```bash
uv tool install prowler
uv tool install checkov
uv tool install scoutsuite
```

Both tools put the executables in `~/.local/bin`, which must be on `PATH` for cloudg to find them.

Trivy is a Go binary. Use your package manager or Aqua Security's install script:

```bash tab="macOS"
brew install trivy
```

```bash tab="Linux"
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
```

```bash tab="Windows"
winget install AquaSecurity.Trivy
```

The scanners authenticate on their own. cloudg passes Prowler the AWS profile (`-p`) and, when you gave direct keys, the key pair through the environment; ScoutSuite gets the AWS profile. For Azure and GCP they read the same environment and credential files the SDKs do. If a scanner works when you run it by hand, it works under cloudg.

## Installer scripts

`install.sh` (Linux and macOS) and `install.bat` (Windows) set up a complete workstation in one go. Run them from the root of a source checkout, because they install cloudg in editable mode from the current directory:

```bash tab="Linux / macOS"
git clone https://github.com/morpheuslord/cloudg.git
cd cloudg
./install.sh
```

```bash tab="Windows"
git clone https://github.com/morpheuslord/cloudg.git
cd cloudg
install.bat
```

`install.sh` detects the package manager (apt, dnf, yum, pacman, zypper or Homebrew) and then, in order:

1. installs curl, git and unzip if they are missing, and finds or installs Python 3.11 or newer;
2. installs Graphviz and Node.js 20;
3. installs uv, creates `.venv` and runs `uv pip install -e ".[all,dev]"`, then tries `.[full]`;
4. installs Prowler, Checkov, ScoutSuite, Parliament and policy-sentry into that venv, Trivy through its install script or the distro repository, CloudSploit through npm, and Cloud Custodian (`c7n`);
5. installs the AWS CLI v2, the Azure CLI and the gcloud CLI where they are missing;
6. runs `cloudg --version` and prints which tools it found.

`install.bat` does the same on Windows with winget or Chocolatey. It stops if Python is older than 3.11, and if it has to install Python through winget it asks you to open a new terminal and run it again.

Both scripts use `sudo` (on Linux) or system package managers, and they install more than cloudg strictly needs. CloudSploit and Cloud Custodian are not called by cloudg; Custodian is there so you can run the policy packs in `cloudg/policies/` yourself. Graphviz is not needed either, since the SVG topology is drawn with svgwrite. If you prefer a lean setup, use pip or uv and add only the scanners you want.

Each step logs `[OK]` or `[WARN]` and keeps going, so read the summary at the end. Afterwards, activate the environment:

```bash
source .venv/bin/activate
```

## Verify the install

Check the version and that the command group loads:

```console
$ cloudg --version
cloudg, version 0.6.0
$ cloudg --help
Usage: cloudg [OPTIONS] COMMAND [ARGS]...
...
Commands:
  collect  Collect cloud assets from the specified provider.
  deps     Explore interdependencies in a saved inventory map.
  ingest   Aggregate existing scanner outputs; no scanners are executed.
  map      Map the complete infrastructure inventory, with no scanners...
  mcp      Model Context Protocol server: expose cloudg to AI assistants.
  report   Generate reports from existing scan data.
  run      Run the full pipeline: collect → scan → normalise → render.
  scan     Run security scanners and generate findings.
```

Then see which scanners cloudg will find:

```bash
command -v prowler scout checkov trivy
```

Anything missing from that list is skipped at run time.

Last, an end-to-end smoke test that needs no credentials. Save a minimal Trivy result:

```json title="trivy-sample.json"
{
  "ArtifactName": "myrepo/app:latest",
  "ArtifactType": "container_image",
  "Results": [
    {
      "Target": "myrepo/app:latest (alpine 3.19)",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-0001",
          "PkgName": "openssl",
          "InstalledVersion": "3.1.0",
          "FixedVersion": "3.1.1",
          "Severity": "CRITICAL",
          "Description": "Example vulnerability for a smoke test"
        }
      ]
    }
  ]
}
```

and feed it to `cloudg ingest`:

```bash
cloudg ingest --trivy trivy-sample.json -o ./smoke-test
```

You should see "Ingested 1 findings from 1 tool(s), 1 after deduplication" and three files in `./smoke-test`: `findings.json`, `raw-findings.json` and `report.html`. If that works, the parser, normaliser, compliance rulesets and renderers are all installed correctly.

## Upgrading

```bash tab="pip"
pip install --upgrade "cloudg[all]"
```

```bash tab="uv"
uv tool upgrade cloudg
```

```bash tab="Docker"
docker pull ghcr.io/morpheuslord/cloudg:latest
```

For a source checkout, `git pull` and then reinstall: `uv pip install -e ".[all,dev]"`. Reinstalling matters when the entry points change. The `cloudg-mcp` console script arrived in 0.6.0, so an editable install made before that does not have it until you reinstall.

Image tags follow the release version (`ghcr.io/morpheuslord/cloudg:0.6.0`), and `latest` moves with each release. Pin the version tag in CI so an upgrade happens when you choose.

Configuration files carry over. A `config.yaml` that still uses the old single `provider:` key is migrated to `providers: [...]` when it loads. Read the [changelog](/changelog/) before upgrading across a minor version; it lists every changed default and output field.

## Troubleshooting

`cloudg: command not found` usually means the virtualenv is not active, or `~/.local/bin` is not on `PATH` after `uv tool install`. `python -m cloudg.cli --help` runs the same CLI from whichever interpreter you call it with.

If pip says no matching distribution was found, or mentions "a different Python", the interpreter is older than 3.11. Create the venv with a newer one, for example `uv venv --python 3.12`.

A scanner that works in your shell but is "not installed" under cloudg is on a different `PATH`. That happens with scanners installed in a second virtualenv that is not active. Use `uv tool` or `pipx`, or symlink the executable somewhere on `PATH`.

Next: run your first scan in the [quickstart](/guides/quickstart/).
