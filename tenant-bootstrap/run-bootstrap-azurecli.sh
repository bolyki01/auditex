#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}"
DEFAULT_CONFIG="${ROOT_DIR}/config.example.json"

print_usage() {
  cat <<'USAGE'
Usage: run-bootstrap-azurecli.sh [options]

  --config PATH        Path to config JSON (default: config.example.json)
  --tenant-name NAME   Override tenant display name from config
  --run-name NAME      Base run name prefix (defaults to az-bootstrap-<timestamp>)
  --steps STEP_LIST    workload steps: licenses,windows365,teams,intune,security,devices,exchange,sample (default: licenses,windows365,teams,intune,security,devices,exchange,sample)
  --days DAYS          sample data days window (default: full config count)
  --interactive-workload  Use delegated interactive Graph auth for workload seeding
  --client-id ID          Public client app ID for delegated interactive Graph auth
  --audit-collectors LIST     audit collectors (default: identity,security,intune,teams,exchange)
  --audit-top TOP             audit collector top item count (default: 500)
  --include-audit-exchange    enable command-based exchange collector
  --skip-identity      Skip identity/group seeding
  --skip-workload      Skip Graph workload seeding
  --skip-verify        Skip post-seed population verification
  --skip-audit         Skip audit evidence collection
  --token-env PATH     Path to token env file (default: .secrets/lab-populator-token.env if present).
  --browser-command CMD Browser command for az login (default: firefox)
  --skip-login         Skip automatic az login and require existing session
  --verbose-shell-log  Backward compatible alias; command logging is always captured.
  --dry-run            Dry-run only, no tenant writes
  --help               Show this help

If not already signed in, this script will run `az login` in the specified browser.
USAGE
}

CONFIG="$DEFAULT_CONFIG"
TENANT_NAME=""
RUN_NAME="az-bootstrap-$(date +%Y%m%d_%H%M%S)"
STEPS="licenses,windows365,teams,intune,security,devices,exchange,sample"
DAYS=""
SKIP_IDENTITY=0
SKIP_WORKLOAD=0
SKIP_VERIFY=0
SKIP_AUDIT=0
DRY_RUN=0
AUDIT_COLLECTORS="identity,security,intune,teams,exchange"
AUDIT_TOP=500
AUDIT_INCLUDE_EXCHANGE=0
BROWSER_CMD="firefox"
INTERACTIVE_WORKLOAD=0
WORKLOAD_CLIENT_ID=""
SKIP_LOGIN=0
TOKEN_ENV_PATH="${ROOT_DIR}/.secrets/lab-populator-token.env"
AUTH_SOURCE="unset"
RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
IDENTITY_STATUS="skipped"
WORKLOAD_STATUS="skipped"
VERIFY_STATUS="skipped"
AUDIT_STATUS="skipped"
FINAL_STATUS="completed"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG="$2"
      shift 2
      ;;
    --tenant-name)
      TENANT_NAME="$2"
      shift 2
      ;;
    --run-name)
      RUN_NAME="$2"
      shift 2
      ;;
    --steps)
      STEPS="$2"
      shift 2
      ;;
    --days)
      DAYS="$2"
      shift 2
      ;;
    --interactive-workload)
      INTERACTIVE_WORKLOAD=1
      shift
      ;;
    --client-id)
      WORKLOAD_CLIENT_ID="$2"
      shift 2
      ;;
    --audit-collectors)
      AUDIT_COLLECTORS="$2"
      shift 2
      ;;
    --audit-top)
      AUDIT_TOP="$2"
      shift 2
      ;;
    --include-audit-exchange)
      AUDIT_INCLUDE_EXCHANGE=1
      shift
      ;;
    --skip-identity)
      SKIP_IDENTITY=1
      shift
      ;;
    --skip-workload)
      SKIP_WORKLOAD=1
      shift
      ;;
    --skip-verify)
      SKIP_VERIFY=1
      shift
      ;;
    --skip-audit)
      SKIP_AUDIT=1
      shift
      ;;
    --token-env)
      TOKEN_ENV_PATH="$2"
      shift 2
      ;;
    --verbose-shell-log)
      # retained for compatibility with earlier documentation; shell logging is always on.
      shift
      ;;
    --browser-command)
      BROWSER_CMD="$2"
      shift 2
      ;;
    --skip-login)
      SKIP_LOGIN=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help)
      print_usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      print_usage
      exit 1
      ;;
  esac
done

if [[ ! -f "$CONFIG" ]]; then
  echo "Config file not found: $CONFIG"
  exit 2
fi

if [[ "$TENANT_NAME" == "" ]]; then
  TENANT_NAME="$(python3 - "$CONFIG" <<'PY'
import json,sys
cfg=json.load(open(sys.argv[1]))
print(cfg.get("tenant", {}).get("tenantName", ""))
PY
)"
fi

if [[ -f "${SCRIPT_DIR}/scripts/token-env.sh" ]]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/scripts/token-env.sh"
fi

resolve_azure_access_token() {
  if [[ -n "${AZURE_ACCESS_TOKEN:-}" ]]; then
    AUTH_SOURCE="AZURE_ACCESS_TOKEN"
    return 0
  fi

  if [[ -z "${TOKEN_ENV_PATH:-}" ]]; then
    AUTH_SOURCE="AZURE_CLI_REQUIRED"
    return 1
  fi
  if [[ ! -f "$TOKEN_ENV_PATH" ]]; then
    AUTH_SOURCE="TOKEN_ENV_MISSING"
    return 1
  fi
  if ! load_token_env "$TOKEN_ENV_PATH"; then
    AUTH_SOURCE="EXPIRED_OR_INVALID_TOKEN_ENV"
    return 1
  fi
  AUTH_SOURCE="AZURE_ACCESS_TOKEN"
  return 0
}

TENANT_ID="$(python3 - "$CONFIG" <<'PY'
import json,sys
cfg=json.load(open(sys.argv[1]))
print(cfg.get("tenant", {}).get("tenantId", ""))
PY
)"

TENANT_DOMAIN="$(python3 - "$CONFIG" <<'PY'
import json,sys
cfg=json.load(open(sys.argv[1]))
print(cfg.get("tenant", {}).get("tenantDomain", ""))
PY
)"

ensure_azure_cli_session() {
  local tenant_hint="$1"

  if ! command -v az >/dev/null 2>&1; then
    echo "Azure CLI not found. Install the Azure CLI package first."
    exit 3
  fi

  if az account show --output none >/dev/null 2>&1; then
    echo "Azure CLI session already active."
    return 0
  fi

  if [[ "$SKIP_LOGIN" -eq 1 ]]; then
    echo "No active Azure CLI session and --skip-login was set."
    echo "Run 'az login' manually and re-run this command."
    exit 4
  fi

  local login_cmd=(az login --output none)
  if [[ -n "$tenant_hint" ]]; then
    login_cmd+=(--tenant "$tenant_hint")
  fi

  echo "No active Azure CLI session found. Launching browser authentication..."
  echo "Using browser command: $BROWSER_CMD"
  BROWSER="$BROWSER_CMD" "${login_cmd[@]}"

  if ! az account show --output none >/dev/null 2>&1; then
    echo "Azure CLI sign-in did not complete. Run 'az login' manually and retry."
    exit 5
  fi
}

BOOTSTRAP_LOG_DIR="${ROOT_DIR}/runs/${RUN_NAME}"
BOOTSTRAP_SHELL_LOG="${BOOTSTRAP_LOG_DIR}/bootstrap-shell.log"
BOOTSTRAP_DEBUG_LOG="${BOOTSTRAP_LOG_DIR}/bootstrap-debug.log"
BOOTSTRAP_MANIFEST="${BOOTSTRAP_LOG_DIR}/run-manifest.json"
mkdir -p "${BOOTSTRAP_LOG_DIR}"
touch "$BOOTSTRAP_SHELL_LOG" "$BOOTSTRAP_DEBUG_LOG"

python3 - "$BOOTSTRAP_MANIFEST" "$RUN_NAME" "$TENANT_NAME" "$TENANT_ID" "$TENANT_DOMAIN" \
  "$RUN_STARTED_AT" "$DRY_RUN" "$STEPS" "$SKIP_IDENTITY" "$SKIP_WORKLOAD" "$SKIP_VERIFY" "$SKIP_AUDIT" "$AUTH_SOURCE" "$TOKEN_ENV_PATH" <<'PY'
import json
import sys
from pathlib import Path

path, run_name, tenant_name, tenant_id, tenant_domain, started_at, dry_run, steps, skip_identity, skip_workload, skip_verify, skip_audit, auth_source, token_env = sys.argv[1:15]
payload = {
    "runName": run_name,
    "tenantName": tenant_name,
    "tenantId": tenant_id,
    "tenantDomain": tenant_domain,
    "startedAt": started_at,
    "dryRun": dry_run == "1",
    "steps": {
        "skipIdentity": skip_identity == "1",
        "skipWorkload": skip_workload == "1",
        "skipVerify": skip_verify == "1",
        "skipAudit": skip_audit == "1",
        "workloadSteps": steps,
    },
    "components": {
        "identityStatus": "skipped",
        "workloadStatus": "skipped",
        "verificationStatus": "skipped",
        "auditStatus": "skipped",
    },
    "auth": {
        "source": auth_source,
        "tokenEnvPath": token_env,
    },
    "commands": {
        "shellLog": "bootstrap-shell.log",
        "debugLog": "bootstrap-debug.log",
    },
}
Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
PY

log_shell_event() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "${BOOTSTRAP_SHELL_LOG}"
}

shell_command_repr() {
  local token cmd=()
  for token in "$@"; do
    cmd+=("$(printf '%q' "$token")")
  done
  printf '%s' "${cmd[*]}"
}

log_shell_debug() {
  local msg="$1"
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$msg" >> "${BOOTSTRAP_DEBUG_LOG}"
}

run_shell_cmd() {
  local cmd
  local rc
  cmd="$(shell_command_repr "$@")"
  log_shell_event "RUN ${cmd}"
  log_shell_debug "START ${cmd}"

  set +e
  { "$@"; } 2>&1 | tee -a "$BOOTSTRAP_DEBUG_LOG"
  rc=${PIPESTATUS[0]}
  set -e
  log_shell_event "EXIT ${rc} ${cmd}"
  if [[ $rc -ne 0 ]]; then
    FINAL_STATUS="failed"
    log_shell_debug "Command failed: rc=${rc} cmd=${cmd}"
    return "${rc}"
  fi
  log_shell_debug "Command completed: rc=${rc} cmd=${cmd}"
}

emit_manifest() {
  local status="$1"
  local completed_at
  completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 - "$BOOTSTRAP_MANIFEST" "$RUN_NAME" "$TENANT_NAME" "$TENANT_ID" "$TENANT_DOMAIN" \
    "$RUN_STARTED_AT" "$completed_at" "$status" "$IDENTITY_STATUS" "$WORKLOAD_STATUS" "$VERIFY_STATUS" "$AUDIT_STATUS" "$AUTH_SOURCE" "$TOKEN_ENV_PATH" <<'PY'
import json
import sys
from pathlib import Path

path, run_name, tenant_name, tenant_id, tenant_domain, started_at, completed_at, status, identity_status, workload_status, verification_status, audit_status, auth_source, token_env = sys.argv[1:15]
payload = json.loads(Path(path).read_text(encoding="utf-8"))
payload.update(
    {
        "runName": run_name,
        "tenantName": tenant_name,
        "tenantId": tenant_id,
        "tenantDomain": tenant_domain,
        "startedAt": started_at,
        "completedAt": completed_at,
        "finalStatus": status,
        "components": {
            "identityStatus": identity_status,
            "workloadStatus": workload_status,
            "verificationStatus": verification_status,
            "auditStatus": audit_status,
        },
        "auth": {
            "source": auth_source,
            "tokenEnvPath": token_env,
        },
    }
)
Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
PY
}

cleanup() {
  local exit_code="${1:-$?}"
  if [[ "$exit_code" -ne 0 ]]; then
    FINAL_STATUS="failed"
  fi
  emit_manifest "$FINAL_STATUS"
  exit "$exit_code"
}

trap 'cleanup $?' EXIT

if [[ "$DRY_RUN" -eq 0 ]]; then
  if ! resolve_azure_access_token; then
    ensure_azure_cli_session "${TENANT_ID:-$TENANT_DOMAIN}"
    AUTH_SOURCE="AZURE_CLI"
  fi
  if [[ -z "${AZURE_ACCESS_TOKEN:-}" ]] && ! az account show --output json --query "{tenantId:tenantId, user:user.name}" >/dev/null 2>&1; then
    echo "Unable to verify Azure CLI context."
    exit 5
  fi
  log_shell_debug "Auth source: ${AUTH_SOURCE}"
  if [[ -n "${AZURE_ACCESS_TOKEN:-}" ]]; then
    log_shell_debug "Using delegated Graph token from AZURE_ACCESS_TOKEN."
  else
    log_shell_debug "Azure CLI context verified."
  fi
  if [[ -n "${TOKEN_ENV_PATH:-}" && -f "$TOKEN_ENV_PATH" ]]; then
    log_shell_debug "Token env file: $TOKEN_ENV_PATH"
  fi
fi

echo "Bootstrap start: name=$RUN_NAME tenant=$TENANT_NAME"
echo "Config: $CONFIG"

if [[ "$SKIP_IDENTITY" -eq 0 ]]; then
  IDENTITY_ARGS=(--config "$CONFIG" --run-name "${RUN_NAME}-identity")
  if [[ "$DRY_RUN" -eq 1 ]]; then
    IDENTITY_ARGS+=(--dry-run)
  fi
  IDENTITY_STATUS="running"
  if run_shell_cmd python3 "${ROOT_DIR}/scripts/identity_seed_az.py" "${IDENTITY_ARGS[@]}"; then
    IDENTITY_STATUS="completed"
  else
    IDENTITY_STATUS="failed"
    exit 1
  fi
fi

if [[ "$SKIP_WORKLOAD" -eq 0 ]]; then
  WORKLOAD_ARGS=(--config "$CONFIG" --run-name "${RUN_NAME}-workload" --steps "$STEPS")
  if [[ "$DRY_RUN" -eq 1 ]]; then
    WORKLOAD_ARGS+=(--dry-run)
  fi
  if [[ -n "$DAYS" ]]; then
    WORKLOAD_ARGS+=(--days "$DAYS")
  fi
  if [[ "$INTERACTIVE_WORKLOAD" -eq 1 ]]; then
    WORKLOAD_ARGS+=(--interactive --browser-command "$BROWSER_CMD")
  fi
  if [[ -n "$WORKLOAD_CLIENT_ID" ]]; then
    WORKLOAD_ARGS+=(--client-id "$WORKLOAD_CLIENT_ID")
  fi
  WORKLOAD_STATUS="running"
  if run_shell_cmd python3 "${ROOT_DIR}/scripts/seed-workload-az.py" "${WORKLOAD_ARGS[@]}"; then
    WORKLOAD_STATUS="completed"
  else
    WORKLOAD_STATUS="failed"
    exit 1
  fi
fi

if [[ "$SKIP_VERIFY" -eq 0 ]]; then
  VERIFY_ARGS=(
    --config "$CONFIG"
    --run-name "$RUN_NAME"
    --run-dir "$BOOTSTRAP_LOG_DIR"
    --bootstrap-root "$ROOT_DIR"
  )
  if [[ "$DRY_RUN" -eq 1 ]]; then
    VERIFY_ARGS+=(--dry-run)
  fi
  VERIFY_STATUS="running"
  if run_shell_cmd python3 "${ROOT_DIR}/scripts/verify-population-az.py" "${VERIFY_ARGS[@]}"; then
    VERIFY_STATUS="completed"
  else
    VERIFY_STATUS="failed"
    exit 1
  fi
fi

if [[ "$SKIP_AUDIT" -eq 0 ]]; then
  AUDIT_OUT="${ROOT_DIR}/audit-output/${RUN_NAME}-evidence"
  mkdir -p "$AUDIT_OUT"
  AUDIT_ARGS=(
    --tenant-name "$TENANT_NAME"
    --tenant-id "$TENANT_ID"
    --collectors "$AUDIT_COLLECTORS"
    --top "$AUDIT_TOP"
    --out "$AUDIT_OUT"
    --run-name "${RUN_NAME}-evidence"
  )
  if [[ "$AUDIT_INCLUDE_EXCHANGE" -eq 1 || "$AUDIT_COLLECTORS" == *"exchange"* ]]; then
    AUDIT_ARGS+=(--include-exchange)
  fi
  if [[ "${AUTH_SOURCE}" == "AZURE_ACCESS_TOKEN" && -n "${TOKEN_ENV_PATH:-}" && -f "$TOKEN_ENV_PATH" ]]; then
    AUDIT_ARGS+=(--token-env "$TOKEN_ENV_PATH")
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    AUDIT_ARGS+=(--dry-run)
  fi
  AUDIT_STATUS="running"
  if run_shell_cmd "${ROOT_DIR}/scripts/run-audit-collector.sh" "${AUDIT_ARGS[@]}"; then
    AUDIT_STATUS="completed"
  else
    AUDIT_STATUS="failed"
    exit 1
  fi
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Dry-run complete; no tenant writes occurred."
else
  echo "Bootstrap complete."
fi
