#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${1:-latest}"

if [[ "$RUN_ID" == "latest" ]]; then
  LATEST_RUN="$(ls -dt "${ROOT_DIR}/runs"/*/ 2>/dev/null | head -n 1 || true)"
  if [[ -z "$LATEST_RUN" ]]; then
    echo "No bootstrap runs found under ${ROOT_DIR}/runs."
    exit 3
  fi
  RUN_DIR="${LATEST_RUN%/}"
else
  if [[ -d "$RUN_ID" ]]; then
    RUN_DIR="$RUN_ID"
  else
    RUN_DIR="${ROOT_DIR}/runs/${RUN_ID}"
  fi
fi

if [[ ! -d "$RUN_DIR" ]]; then
  echo "Run directory not found: $RUN_DIR"
  exit 4
fi

MANIFEST="${RUN_DIR}/run-manifest.json"
BOOTSTRAP_LOG="${RUN_DIR}/bootstrap-log.jsonl"
DEBUG_LOG="${RUN_DIR}/bootstrap-debug.log"
IDENTITY_LOG="${RUN_DIR}/identity-seed-az-log.jsonl"
WORKLOAD_LOG="${RUN_DIR}/workload-seed-az-log.jsonl"
VERIFY_LOG="${RUN_DIR}/population-verification-log.jsonl"
VERIFY_MANIFEST="${RUN_DIR}/population-verification-manifest.json"
SHELL_LOG="${RUN_DIR}/bootstrap-shell.log"

if [[ -f "$MANIFEST" ]]; then
  echo "RUN MANIFEST:"
  cat "$MANIFEST"
  echo
fi

if [[ -f "$MANIFEST" ]]; then
  echo "RUN SUMMARY:"
  python3 - "$MANIFEST" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
items = [
    ("runName", "Run"),
    ("tenantName", "Tenant"),
    ("finalStatus", "Final status"),
    ("identityStatus", "Identity", "components"),
    ("workloadStatus", "Workload", "components"),
    ("verificationStatus", "Verification", "components"),
    ("auditStatus", "Audit", "components"),
    ("completedAt", "Completed"),
]
for item in items:
    if len(item) == 2:
        key, label = item
        section = None
    else:
        key, label, section = item

    if section:
        value = (payload.get(section) or {}).get(key)
    else:
        value = payload.get(key)
    print(f"{label}: {value}")
PY
  echo
fi

if [[ -f "$VERIFY_MANIFEST" ]]; then
  echo "POPULATION VERIFICATION SUMMARY:"
  python3 - "$VERIFY_MANIFEST" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
checks = payload.get("checks", [])
counts = {"pass": 0, "warn": 0, "fail": 0}
for check in checks:
    status = check.get("status")
    if status in counts:
        counts[status] += 1
print(f"Status: {payload.get('status')}")
print(f"Checks: pass={counts['pass']} warn={counts['warn']} fail={counts['fail']}")
failed = [check for check in checks if check.get("status") == "fail"]
warned = [check for check in checks if check.get("status") == "warn"]
for label, rows in (("Failed", failed), ("Warnings", warned[:10])):
    if rows:
        print(f"{label}:")
        for row in rows:
            print(f"  - {row.get('name')}: expected={row.get('expected')} observed={row.get('observed')}")
PY
  echo
fi

if [[ -f "$BOOTSTRAP_LOG" ]]; then
  echo "BOOTSTRAP LOG (last 30):"
  tail -n 30 "$BOOTSTRAP_LOG"
  echo
else
  echo "No bootstrap-log.jsonl in this run (Azure CLI flow writes shell/debug logs directly)."
  echo
fi

if [[ -f "$IDENTITY_LOG" ]]; then
  echo "IDENTITY SEED LOG:"
  tail -n 30 "$IDENTITY_LOG"
  echo
fi

if [[ -f "$WORKLOAD_LOG" ]]; then
  echo "WORKLOAD SEED LOG:"
  tail -n 30 "$WORKLOAD_LOG"
  echo
fi

if [[ -f "$VERIFY_LOG" ]]; then
  echo "POPULATION VERIFICATION LOG:"
  tail -n 30 "$VERIFY_LOG"
  echo
fi

if [[ -f "$SHELL_LOG" ]]; then
  echo "SHELL COMMAND LOG (last 40):"
  tail -n 40 "$SHELL_LOG"
  echo
fi

if [[ -f "$DEBUG_LOG" ]]; then
  echo "DEBUG TRANSCRIPT (last 40):"
  tail -n 40 "$DEBUG_LOG"
fi
