#!/usr/bin/env bash
# Turn the run and gate exit statuses into the job's result, after the
# reports and SARIF were uploaded. Called by action.yml.
set -euo pipefail

run_status="${CGA_RUN_EXIT:-0}"
gate_status="${CGA_GATE_EXIT:-1}"

if [[ "${run_status}" != "0" ]]; then
  case "${run_status}" in
    3) why="collection failed for every target; check the cloud credentials" ;;
    2) why="usage or configuration error" ;;
    *) why="the run failed" ;;
  esac
  echo "::error title=cloudg run::cloudg run exited ${run_status}: ${why}"
  exit "${run_status}"
fi

case "${gate_status}" in
  0) echo "cloudg gate passed" ;;
  4)
    echo "::error title=cloudg gate::${CGA_REASON:-the gate failed}"
    exit 4
    ;;
  *)
    echo "::error title=cloudg gate::cloudg gate exited ${gate_status}: findings.json is missing or unreadable"
    exit "${gate_status}"
    ;;
esac
