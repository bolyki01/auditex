#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

print_usage() {
  cat <<'USAGE'
Usage: run-enterprise-audit.sh [options]

  --config PATH                 Tenant bootstrap config (default: config.example.json)
  --tenant-name NAME            Tenant display name override
  --tenant-id ID                Tenant ID override for audit and bootstrap token scope
  --run-name NAME               Shared run name for bootstrap and audit output
  --steps STEP_LIST             Workload seed steps (default: licenses,windows365,teams,intune,security,devices,exchange,sample)
  --interactive-workload        Use delegated interactive Graph auth for workload seeding
  --client-id ID                Public client app ID for delegated interactive Graph auth
  --collectors COLLECTOR_LIST    Audit collectors (default: identity,security,intune,teams,exchange)
  --top N                       Top items per collector (default: 500)
  --out PATH                    Audit output directory (default: tenant-bootstrap/audit-output/<run-name>-evidence)
  --days N                      Days of sample data to generate
  --include-exchange            Include exchange-style collectors where supported
  --skip-bootstrap              Skip bootstrap and run audit only
  --skip-verify                 Skip bootstrap population verification
  --skip-audit                  Skip audit collection
  --dry-run                     Safe dry-run for both bootstrap and audit steps
  --auditor-profile PROFILE      Audit profile: auto|enterprise|global-reader (default: auto)
  --browser-command CMD         Browser for interactive Azure CLI login (default: firefox)
  --skip-login                  Skip interactive login and require existing az session
  --token-env PATH              Optional token env file (default: .secrets/lab-populator-token.env if present)
  --inspect                     Print combined bootstrap/audit summaries after run
  --help
USAGE
}

CONFIG="${SCRIPT_DIR}/config.example.json"
TENANT_NAME=""
TENANT_ID=""
RUN_NAME="enterprise-audit-$(date +%Y%m%d_%H%M%S)"
STEPS="licenses,windows365,teams,intune,security,devices,exchange,sample"
COLLECTORS="identity,security,intune,teams,exchange"
TOP=500
OUT=""
DAYS=""
INCLUDE_EXCHANGE=0
SKIP_BOOTSTRAP=0
SKIP_VERIFY=0
SKIP_AUDIT=0
DRY_RUN=0
AUDITOR_PROFILE="auto"
BROWSER_CMD="firefox"
INTERACTIVE_WORKLOAD=0
WORKLOAD_CLIENT_ID=""
SKIP_LOGIN=0
INSPECT=0
TOKEN_ENV_PATH="${SCRIPT_DIR}/.secrets/lab-populator-token.env"

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
    --tenant-id)
      TENANT_ID="$2"
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
    --interactive-workload)
      INTERACTIVE_WORKLOAD=1
      shift
      ;;
    --client-id)
      WORKLOAD_CLIENT_ID="$2"
      shift 2
      ;;
    --token-env)
      TOKEN_ENV_PATH="$2"
      shift 2
      ;;
    --collectors)
      COLLECTORS="$2"
      shift 2
      ;;
    --top)
      TOP="$2"
      shift 2
      ;;
    --out)
      OUT="$2"
      shift 2
      ;;
    --days)
      DAYS="$2"
      shift 2
      ;;
    --include-exchange)
      INCLUDE_EXCHANGE=1
      shift
      ;;
    --skip-bootstrap)
      SKIP_BOOTSTRAP=1
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
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --auditor-profile)
      AUDITOR_PROFILE="$2"
      shift 2
      ;;
    --browser-command)
      BROWSER_CMD="$2"
      shift 2
      ;;
    --skip-login)
      SKIP_LOGIN=1
      shift
      ;;
    --inspect)
      INSPECT=1
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
  echo "Config not found: $CONFIG"
  exit 2
fi

if [[ -f "${SCRIPT_DIR}/scripts/token-env.sh" ]]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/scripts/token-env.sh"
fi
if [[ -n "${TOKEN_ENV_PATH:-}" && -f "$TOKEN_ENV_PATH" ]]; then
  if ! load_token_env "$TOKEN_ENV_PATH"; then
    echo "Warning: token env not usable from ${TOKEN_ENV_PATH}; running without it."
  else
    echo "Loaded token source from ${TOKEN_ENV_PATH}"
  fi
fi

if [[ -z "$TENANT_NAME" ]]; then
  TENANT_NAME="$(python3 - "$CONFIG" <<'PY'
import json
import sys

cfg = json.load(open(sys.argv[1]))
print(cfg.get("tenant", {}).get("tenantName", ""))
PY
)"
fi

if [[ -z "$TENANT_ID" ]]; then
  TENANT_ID="$(python3 - "$CONFIG" <<'PY'
import json
import sys

cfg = json.load(open(sys.argv[1]))
print(cfg.get("tenant", {}).get("tenantId", ""))
PY
)"
fi

BOOTSTRAP_ARGS=(
  --config "$CONFIG"
  --tenant-name "$TENANT_NAME"
  --run-name "$RUN_NAME"
  --steps "$STEPS"
  --audit-collectors "$COLLECTORS"
  --audit-top "$TOP"
  --browser-command "$BROWSER_CMD"
  --skip-audit
)
if [[ -n "$DAYS" ]]; then
  BOOTSTRAP_ARGS+=(--days "$DAYS")
fi
if [[ "$INCLUDE_EXCHANGE" -eq 1 ]]; then
  BOOTSTRAP_ARGS+=(--include-audit-exchange)
fi
if [[ "$DRY_RUN" -eq 1 ]]; then
  BOOTSTRAP_ARGS+=(--dry-run)
fi
if [[ "$SKIP_LOGIN" -eq 1 ]]; then
  BOOTSTRAP_ARGS+=(--skip-login)
fi
if [[ -n "${TOKEN_ENV_PATH:-}" ]]; then
  BOOTSTRAP_ARGS+=(--token-env "$TOKEN_ENV_PATH")
fi
if [[ "$SKIP_VERIFY" -eq 1 ]]; then
  BOOTSTRAP_ARGS+=(--skip-verify)
fi
if [[ "$INTERACTIVE_WORKLOAD" -eq 1 ]]; then
  BOOTSTRAP_ARGS+=(--interactive-workload)
fi
if [[ -n "$WORKLOAD_CLIENT_ID" ]]; then
  BOOTSTRAP_ARGS+=(--client-id "$WORKLOAD_CLIENT_ID")
fi

if [[ "$SKIP_BOOTSTRAP" -eq 0 ]]; then
  echo "Running bootstrap: ./run-bootstrap-azurecli.sh ${BOOTSTRAP_ARGS[*]}"
  ./run-bootstrap-azurecli.sh "${BOOTSTRAP_ARGS[@]}"
else
  echo "Skipping bootstrap by request."
fi

if [[ "$SKIP_AUDIT" -eq 0 ]]; then
  AUDIT_OUT="$OUT"
  if [[ -z "$AUDIT_OUT" ]]; then
    AUDIT_OUT="${SCRIPT_DIR}/audit-output/${RUN_NAME}-evidence"
  fi

  AUDIT_ARGS=(
    --tenant-name "$TENANT_NAME"
    --tenant-id "$TENANT_ID"
    --collectors "$COLLECTORS"
    --top "$TOP"
    --out "$AUDIT_OUT"
    --run-name "${RUN_NAME}-evidence"
  )
  if [[ "$INCLUDE_EXCHANGE" -eq 1 || "$COLLECTORS" == *"exchange"* ]]; then
    AUDIT_ARGS+=(--include-exchange)
  fi
  AUDIT_ARGS+=(--auditor-profile "$AUDITOR_PROFILE")
  if [[ "$DRY_RUN" -eq 1 ]]; then
    AUDIT_ARGS+=(--dry-run)
  fi
  if [[ -n "${TOKEN_ENV_PATH:-}" && -f "$TOKEN_ENV_PATH" ]]; then
    AUDIT_ARGS+=(--token-env "$TOKEN_ENV_PATH")
  fi

  echo "Running audit collector: ./scripts/run-audit-collector.sh ${AUDIT_ARGS[*]}"
  ./scripts/run-audit-collector.sh "${AUDIT_ARGS[@]}"
fi

if [[ "$INSPECT" -eq 1 ]]; then
  echo
  ./scripts/inspect-bootstrap-log.sh "$RUN_NAME"
  if [[ "$SKIP_AUDIT" -eq 0 ]]; then
    if [[ -z "$OUT" ]]; then
      AUDIT_TARGET="${SCRIPT_DIR}/audit-output/${RUN_NAME}-evidence"
    else
      AUDIT_TARGET="$OUT"
    fi
    ./scripts/inspect-audit-logs.sh "$AUDIT_TARGET"
  fi
fi

if [[ "$SKIP_BOOTSTRAP" -eq 0 || "$SKIP_AUDIT" -eq 0 ]]; then
  echo "Run complete."
  echo "bootstrap run dir: ${SCRIPT_DIR}/runs/${RUN_NAME}"
  if [[ "$SKIP_AUDIT" -eq 0 ]]; then
    echo "audit run dir: ${OUT:-${SCRIPT_DIR}/audit-output/${RUN_NAME}-evidence}"
  fi
fi
