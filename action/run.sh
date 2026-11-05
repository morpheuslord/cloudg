#!/usr/bin/env bash
# Run the cloudg pipeline (unless the workflow passed its own findings.json),
# then the severity gate. Never fails the step itself: the exit statuses go
# to step outputs so the reports can be uploaded first, and verdict.sh
# decides the job's result. Called by action.yml.
set -uo pipefail

output="${CGA_OUTPUT}"
mkdir -p "${output}"

run_status=0
if [[ -n "${CGA_FINDINGS}" ]]; then
  findings="${CGA_FINDINGS}"
  echo "Gating ${findings}; cloudg run is skipped"
else
  findings="${output}/findings.json"
  args=()
  [[ -n "${CGA_CONFIG}" ]] && args+=(-c "${CGA_CONFIG}")
  args+=(run -o "${output}")
  for p in $(tr ',' ' ' <<<"${CGA_PROVIDER,,}"); do args+=(-p "$p"); done
  [[ -n "${CGA_REGIONS}" ]] && args+=(--regions "${CGA_REGIONS}")
  [[ -n "${CGA_SCANNERS}" ]] && args+=(--scanners "${CGA_SCANNERS}")
  [[ -n "${CGA_SUBSCRIPTION_ID}" ]] && args+=(--subscription-id "${CGA_SUBSCRIPTION_ID}")
  [[ -n "${CGA_PROJECT_ID}" ]] && args+=(--project-id "${CGA_PROJECT_ID}")
  [[ -n "${CGA_IAC_DIR}" ]] && args+=(--iac-dir "${CGA_IAC_DIR}")
  [[ -n "${CGA_IMAGES}" ]] && args+=(--images "${CGA_IMAGES}")
  if [[ -n "${CGA_EXTRA_ARGS}" ]]; then
    read -r -a extra <<<"${CGA_EXTRA_ARGS}"
    args+=("${extra[@]}")
  fi
  echo "::group::cloudg ${args[*]}"
  cloudg "${args[@]}"
  run_status=$?
  echo "::endgroup::"
fi

gate_args=(gate -i "${findings}" --fail-on "${CGA_FAIL_ON}" --max "${CGA_MAX_FINDINGS}"
  --min-assets "${CGA_MIN_ASSETS}" --json)
sarif_file=""
if [[ "${CGA_SARIF,,}" == "true" ]]; then
  sarif_file="${output}/cloudg.sarif"
  gate_args+=(--sarif "${sarif_file}")
fi
[[ -n "${GITHUB_STEP_SUMMARY:-}" ]] && gate_args+=(--summary "${GITHUB_STEP_SUMMARY}")

cloudg "${gate_args[@]}" >"${output}/gate.json"
gate_status=$?

{
  echo "run-exit-code=${run_status}"
  echo "gate-exit-code=${gate_status}"
  echo "report-dir=${output}"
  [[ -f "${sarif_file}" ]] && echo "sarif-file=${sarif_file}"
  python3 - "${output}/gate.json" <<'EOF'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
except (OSError, ValueError):
    data = {}
print(f"passed={str(bool(data.get('passed'))).lower()}")
print(f"blocking={data.get('blocking', '')}")
print(f"total-findings={data.get('total_findings', '')}")
print(f"reason={' '.join(str(data.get('reason', '')).split())}")
EOF
} >>"${GITHUB_OUTPUT}"
exit 0
