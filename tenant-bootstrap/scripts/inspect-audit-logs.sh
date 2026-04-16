#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage: inspect-audit-logs.sh [run-dir|latest]

  run-dir   Path to an audit evidence directory. Default: latest directory under tenant-bootstrap/audit-output.
USAGE
}

TARGET="${1:-latest}"

if [[ "${TARGET:-latest}" == "--help" || "${TARGET:-latest}" == "-h" ]]; then
  usage
  exit 0
fi

resolve_dir_from_name() {
  local candidate="$1"
  if [[ -d "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi

  local in_output="${ROOT_DIR}/audit-output/${candidate}"
  if [[ -d "$in_output" ]]; then
    printf '%s\n' "$in_output"
    return 0
  fi

  local in_runs="${ROOT_DIR}/runs/${candidate}"
  if [[ -d "$in_runs" ]]; then
    printf '%s\n' "$in_runs"
    return 0
  fi

  return 1
}

if [[ "$TARGET" == "latest" ]]; then
  TARGET_DIR="$(ls -dt "${ROOT_DIR}/audit-output"/*/ 2>/dev/null | head -n 1 || true)"
  if [[ -z "${TARGET_DIR:-}" ]]; then
    echo "No audit output directories found under ${ROOT_DIR}/audit-output"
    exit 2
  fi
  TARGET_DIR="${TARGET_DIR%/}"
else
  if ! TARGET_DIR="$(resolve_dir_from_name "$TARGET")"; then
    if [[ -f "$TARGET" ]]; then
      TARGET_DIR="$(cd "$(dirname "$TARGET")" && pwd)"
    else
      echo "Run directory not found: $TARGET"
      echo "Try: ${ROOT_DIR}/audit-output/<run-name>"
      exit 3
    fi
  fi
fi

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "Run directory not found: $TARGET_DIR"
  exit 4
fi

echo "AUDIT EVIDENCE DIR: $TARGET_DIR"
echo

MANIFEST="${TARGET_DIR}/run-manifest.json"
if [[ ! -f "$MANIFEST" ]]; then
  MANIFEST="${TARGET_DIR}/audit-manifest.json"
fi

AUDIT_LOG="${TARGET_DIR}/audit-command-log.jsonl"
if [[ ! -f "$AUDIT_LOG" ]]; then
  AUDIT_LOG="${TARGET_DIR}/audit-log.jsonl"
fi

DEBUG_LOG="${TARGET_DIR}/audit-debug.log"
SUMMARY_JSON="${TARGET_DIR}/summary.json"
DIAGNOSTICS="${TARGET_DIR}/diagnostics.json"
RUN_SUMMARY="${TARGET_DIR}/summary.md"

if [[ -f "$MANIFEST" ]]; then
  echo "MANIFEST:"
  python3 - "$MANIFEST" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
def first(*keys):
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return "n/a"

tenant = first("tenant_name", "tenantName")
run_id = first("run_id", "runId", "runName")
created = first("created_utc", "createdAt", "startedAt")
status = first("overall_status", "finalStatus", "status")
duration = first("duration_seconds", "duration")
collectors = first("selected_collectors", "collectors")
if isinstance(collectors, dict):
    collector_list = sorted(collectors.keys())
else:
    collector_list = collectors if isinstance(collectors, list) else []
artifacts = first("artifacts")
if not isinstance(artifacts, list):
    artifacts = []

print(f"Tenant: {tenant}")
print(f"Run ID: {run_id}")
print(f"Created: {created}")
print(f"Status: {status}")
print(f"Duration (s): {duration}")
print(f"Collectors: {', '.join(collector_list) if collector_list else 'n/a'}")
print(f"Auditor profile: {payload.get('auditor_profile', 'n/a')}")
print(f"Artifacts captured: {len(artifacts)}")

components = payload.get("components")
if isinstance(components, dict):
    print(f"Identity status: {components.get('identityStatus', 'n/a')}")
    print(f"Workload status: {components.get('workloadStatus', 'n/a')}")
    print(f"Verification status: {components.get('verificationStatus', 'n/a')}")
    print(f"Audit status: {components.get('auditStatus', 'n/a')}")
PY
else
  echo "Manifest not found (both run-manifest.json and audit-manifest.json missing)."
fi

echo

if [[ -f "$SUMMARY_JSON" ]]; then
  echo "COLLECTION SUMMARY:"
  python3 - "$SUMMARY_JSON" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
collectors = payload.get("collectors")
if not isinstance(collectors, list):
    print("No collector rows found.")
    sys.exit(0)
total_items = 0
status_count = {}
for row in collectors:
    name = row.get("name", "unknown")
    status = row.get("status", "unknown")
    items = int(row.get("item_count", 0) or 0)
    message = row.get("message", "")
    total_items += items
    status_count[status] = status_count.get(status, 0) + 1
    print(f"- {name}: status={status} items={items} {message}")

print(f"TOTAL collectors: {len(collectors)}")
print(f"TOTAL items: {total_items}")
for status, count in sorted(status_count.items()):
    print(f"Status {status}: {count}")
PY
  echo
fi

if [[ -f "$DIAGNOSTICS" ]]; then
  echo "DIAGNOSTICS:"
  python3 - "$DIAGNOSTICS" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
if not isinstance(payload, list):
    print("No diagnostic rows found.")
    sys.exit(0)

counts = {}
for row in payload:
    status = str(row.get("status", "unknown"))
    counts[status] = counts.get(status, 0) + 1

print("  " + ", ".join([f"{key}={value}" for key, value in sorted(counts.items())]) if counts else "  no status rows")
sample = payload[:10]
if sample:
    print("  sample:")
    for row in sample:
        collector = row.get("collector") or "unknown"
        status = row.get("status", "unknown")
        error = row.get("error")
        print(f"  - {collector}: {status} :: {error}")
PY
  echo
fi

if [[ -f "$RUN_SUMMARY" ]]; then
  echo "SUMMARY.md (first lines):"
  sed -n '1,25p' "$RUN_SUMMARY"
  echo
fi

if [[ -d "$TARGET_DIR/raw" ]]; then
  echo "RAW ARTIFACTS:"
  find "$TARGET_DIR/raw" -maxdepth 1 -type f -name '*.json' -printf "%f\n" | sort
  echo
fi

if [[ -f "$AUDIT_LOG" ]]; then
  echo "AUDIT LOG (last 30 lines):"
  tail -n 30 "$AUDIT_LOG"
  echo
fi

if [[ -f "$TARGET_DIR/audit-log.jsonl" && "$TARGET_DIR/audit-log.jsonl" != "$AUDIT_LOG" ]]; then
  echo "AUDIT-LOG (last 20 lines):"
  tail -n 20 "$TARGET_DIR/audit-log.jsonl"
  echo
fi

if [[ -f "$DEBUG_LOG" ]]; then
  echo "DEBUG LOG (last 20 lines):"
  tail -n 20 "$DEBUG_LOG"
fi
