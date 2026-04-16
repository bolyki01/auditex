#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TENANT_BOOTSTRAP_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${TENANT_BOOTSTRAP_ROOT}/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage: run-audit-collector.sh [options]

  --tenant-name NAME       Tenant display name (default: tenant)
  --tenant-id ID           Tenant ID (default: organizations)
  --collectors LIST        Comma-separated collectors (default: identity,security,intune,teams,exchange)
  --include-exchange       Enable command-based exchange collector (full collector set)
  --top N                  Max items per endpoint (default: 500)
  --out PATH               Output directory (default: tenant-bootstrap/audit-output)
  --run-name NAME          Optional run name
  --interactive            Acquire delegated token with interactive browser login
  --client-id ID           Client ID for interactive auth
  --browser-command CMD    Browser command for interactive auth (default: firefox)
  --token-env PATH         Token env file (for AZURE_ACCESS_TOKEN)
  --scopes CSV             Comma-separated delegated scopes
  --auditor-profile PROFILE  Audit profile: auto|enterprise|global-reader (default: auto)
  --dry-run                Print the command without running it
  --help
USAGE
}

TENANT_NAME="tenant"
TENANT_ID="organizations"
COLLECTORS="identity,security,intune,teams,exchange"
TOP="500"
OUT_DIR=""
RUN_NAME=""
INCLUDE_EXCHANGE=0
CLIENT_ID=""
INTERACTIVE=0
BROWSER_CMD="firefox"
SCOPES=""
AUDITOR_PROFILE="auto"
TOKEN_ENV_PATH=""
TOKEN_ENV_EXPLICIT=0
# default token env path for portability
if [[ -f "${TENANT_BOOTSTRAP_ROOT}/.secrets/lab-populator-token.env" ]]; then
  TOKEN_ENV_PATH="${TENANT_BOOTSTRAP_ROOT}/.secrets/lab-populator-token.env"
fi
DRY_RUN=0
FULL_AUDIT_ROOT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tenant-name)
      TENANT_NAME="$2"
      shift 2
      ;;
    --tenant-id)
      TENANT_ID="$2"
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
      OUT_DIR="$2"
      shift 2
      ;;
    --run-name)
      RUN_NAME="$2"
      shift 2
      ;;
    --client-id)
      CLIENT_ID="$2"
      shift 2
      ;;
    --token-env)
      TOKEN_ENV_PATH="$2"
      TOKEN_ENV_EXPLICIT=1
      shift 2
      ;;
    --interactive)
      INTERACTIVE=1
      shift
      ;;
    --browser-command)
      BROWSER_CMD="$2"
      shift 2
      ;;
    --scopes)
      SCOPES="$2"
      shift 2
      ;;
    --auditor-profile)
      AUDITOR_PROFILE="$2"
      shift 2
      ;;
    --include-exchange)
      INCLUDE_EXCHANGE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

OUT_DIR="${OUT_DIR:-${TENANT_BOOTSTRAP_ROOT}/audit-output}"
if [[ ! -d "$OUT_DIR" ]]; then
  mkdir -p "$OUT_DIR"
fi

if [[ -f "${TENANT_BOOTSTRAP_ROOT}/scripts/token-env.sh" ]]; then
  # shellcheck source=/dev/null
  source "${TENANT_BOOTSTRAP_ROOT}/scripts/token-env.sh"
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python not found. Set PYTHON_BIN to a valid python3 executable."
  exit 2
fi

HAS_TOKEN_FILE=0
if [[ -n "${TOKEN_ENV_PATH:-}" ]]; then
  if [[ -f "$TOKEN_ENV_PATH" ]] && load_token_env "$TOKEN_ENV_PATH"; then
    HAS_TOKEN_FILE=1
  elif [[ "$TOKEN_ENV_EXPLICIT" -eq 1 ]]; then
    echo "Warning: token env path not usable: ${TOKEN_ENV_PATH}. Falling back to Azure CLI token mode."
  fi
fi

HAS_FULL_AUDIT=0
if [[ -f "${TENANT_BOOTSTRAP_ROOT}/azure_tenant_audit/cli.py" && -f "${TENANT_BOOTSTRAP_ROOT}/configs/collector-definitions.json" && -f "${TENANT_BOOTSTRAP_ROOT}/configs/collector-permissions.json" ]]; then
  HAS_FULL_AUDIT=1
  FULL_AUDIT_ROOT="${TENANT_BOOTSTRAP_ROOT}"
elif [[ -f "${REPO_ROOT}/src/azure_tenant_audit/cli.py" && -f "${REPO_ROOT}/configs/collector-definitions.json" && -f "${REPO_ROOT}/configs/collector-permissions.json" ]]; then
  HAS_FULL_AUDIT=1
  FULL_AUDIT_ROOT="${REPO_ROOT}/src"
fi

ARGS=(
  "--tenant-name" "$TENANT_NAME"
  "--tenant-id" "${TENANT_ID:-organizations}"
  "--collectors" "$COLLECTORS"
  "--top" "$TOP"
  "--out" "$OUT_DIR"
)

if [[ -n "$RUN_NAME" ]]; then
  ARGS+=(--run-name "$RUN_NAME")
fi
if [[ -n "$CLIENT_ID" ]]; then
  ARGS+=(--client-id "$CLIENT_ID")
fi
if [[ "$INTERACTIVE" -eq 1 ]]; then
  ARGS+=(--interactive)
else
  if [[ "$HAS_TOKEN_FILE" -eq 1 ]]; then
    ARGS+=(--env "$TOKEN_ENV_PATH")
  else
    ARGS+=(--use-azure-cli-token)
  fi
fi
if [[ -n "$SCOPES" ]]; then
  ARGS+=(--scopes "$SCOPES")
fi
if [[ -n "$AUDITOR_PROFILE" ]]; then
  ARGS+=(--auditor-profile "$AUDITOR_PROFILE")
fi
if [[ -n "$BROWSER_CMD" ]]; then
  ARGS+=(--browser-command "$BROWSER_CMD")
fi

if [[ "$HAS_FULL_AUDIT" -eq 1 ]]; then
  ARGS+=(--config "${FULL_AUDIT_ROOT}/configs/collector-definitions.json")
  ARGS+=(--permission-hints "${FULL_AUDIT_ROOT}/configs/collector-permissions.json")
  if [[ "$INCLUDE_EXCHANGE" -eq 1 || "$COLLECTORS" == *"exchange"* ]]; then
    ARGS+=(--include-exchange)
  fi

  PYTHONPATH_VALUE="${FULL_AUDIT_ROOT}"
  if [[ -n "${PYTHONPATH:-}" ]]; then
    PYTHONPATH_VALUE="${PYTHONPATH_VALUE}:${PYTHONPATH}"
  fi
else
  if [[ "$INCLUDE_EXCHANGE" -eq 1 ]]; then
    echo "warning: include-exchange requested; local fallback audit module does not support exchange collectors."
  fi
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Audit dry run command:"
  printf "  %q " "$PYTHON_BIN" -m azure_tenant_audit "${ARGS[@]}"
  echo
  if [[ "$HAS_FULL_AUDIT" -eq 1 ]]; then
    echo "  PYTHONPATH=$PYTHONPATH_VALUE"
  fi
  exit 0
fi

if [[ "$HAS_FULL_AUDIT" -eq 1 ]]; then
  echo "Running full audit package at: ${FULL_AUDIT_ROOT}/azure_tenant_audit."
  (
    export PYTHONPATH="${PYTHONPATH_VALUE}"
    cd "$FULL_AUDIT_ROOT"
    "$PYTHON_BIN" -m azure_tenant_audit "${ARGS[@]}"
  )
else
  echo "Running fallback audit collector in tenant-bootstrap."
  "$PYTHON_BIN" -m azure_tenant_audit "${ARGS[@]}"
fi
