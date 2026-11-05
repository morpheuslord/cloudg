#!/usr/bin/env bash
# Install cloudg, with the SDK extras for the requested providers, and the
# scanners the run needs, each as an isolated uv tool. Called by action.yml.
set -euo pipefail

say() { printf '%s\n' "$*"; }
die() { say "::error title=cloudg::$*"; exit 1; }

providers="$(tr ',' ' ' <<<"${CGA_PROVIDER,,}")"
extras=()
for p in $providers; do
  case "$p" in
    aws | azure | gcp) [[ " ${extras[*]-} " == *" $p "* ]] || extras+=("$p") ;;
    all) extras=(aws azure gcp) ;;
    *) die "unknown provider '$p' (expected aws, azure, gcp or all)" ;;
  esac
done
[[ ${#extras[@]} -gt 0 ]] || die "the provider input is empty"
extra_list="$(IFS=,; echo "${extras[*]}")"

if [[ -n "${CGA_VERSION}" ]]; then
  [[ "${CGA_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*$ ]] ||
    die "version '${CGA_VERSION}' is not a release number such as 0.7.1"
  spec="cloudg[${extra_list}]==${CGA_VERSION}"
else
  # The action's own checkout: the cloudg release the workflow pinned with @ref
  spec="${CGA_ACTION_PATH}[${extra_list}]"
fi

bin_dir="$(uv tool dir --bin)"
echo "${bin_dir}" >>"${GITHUB_PATH}"
export PATH="${bin_dir}:${PATH}"

say "::group::Install ${spec}"
uv tool install --python "${CGA_PYTHON}" "${spec}"
say "::endgroup::"
cloudg --version

need() {
  local command_name="$1" package="$2"
  if command -v "${command_name}" >/dev/null 2>&1; then
    say "${package}: already on PATH ($(command -v "${command_name}"))"
    return
  fi
  say "::group::Install ${package}"
  uv tool install --python "${CGA_PYTHON}" "${package}"
  say "::endgroup::"
}

[[ "${CGA_INSTALL_SCANNERS,,}" == "true" ]] || exit 0
[[ -z "${CGA_FINDINGS}" ]] || exit 0 # gating a given findings.json runs no scanner
for s in $(tr ',' ' ' <<<"${CGA_SCANNERS,,}"); do
  case "$s" in
    prowler) need prowler prowler ;;
    checkov) need checkov checkov ;;
    scoutsuite) need scout scoutsuite ;;
    trivy)
      command -v trivy >/dev/null 2>&1 ||
        say "::warning title=cloudg::trivy is not on PATH; add aquasecurity/setup-trivy before this action"
      ;;
    iam) ;; # the IAM linter (parliament) ships with cloudg
    *) say "::warning title=cloudg::unknown scanner '$s' is left to cloudg" ;;
  esac
done
