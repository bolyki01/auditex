#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TENANT_BOOTSTRAP_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage: run-auditor.sh [options]

  --tenant-name NAME         Tenant display name (default: tenant)
  --tenant-id ID             Tenant ID / tenant to scope CLI token (default: organizations)
  --collectors LIST          Comma-separated collectors (default: identity,security,intune,teams,exchange)
  --include-exchange         Enable command-style exchange collector (requires Exchange module path in workload tools)
  --top N                    Max items per endpoint (default: 500)
  --out PATH                 Output base directory (default: tenant-bootstrap/audit-output)
  --run-name NAME            Optional audit run name
  --interactive              Use delegated interactive browser login (requires client-id)
  --client-id ID             Public client ID for interactive login
  --browser-command CMD      Browser command (default: firefox)
  --token-env PATH           Token env file for AZURE_ACCESS_TOKEN
  --scopes CSV               Delegated scopes for interactive auth
  --auditor-profile PROFILE  Audit profile: auto|enterprise|global-reader (default: auto)
  --inspect                  Print compact audit summary after run
  --dry-run                  Print command only and do not execute
  --help
USAGE
}

TENANT_NAME="tenant"
TENANT_ID="organizations"
COLLECTORS="identity,security,intune,teams,exchange"
TOP="500"
OUT_DIR="${TENANT_BOOTSTRAP_ROOT}/audit-output"
RUN_NAME=""
INCLUDE_EXCHANGE=0
CLIENT_ID=""
INTERACTIVE=0
BROWSER_CMD="firefox"
SCOPES=""
AUDITOR_PROFILE="auto"
TOKEN_ENV_PATH="${TENANT_BOOTSTRAP_ROOT}/.secrets/lab-populator-token.env"
TOKEN_ENV_EXPLICIT=0
INSPECT=0
DRY_RUN=0

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
    --include-exchange)
      INCLUDE_EXCHANGE=1
      shift
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
    --interactive)
      INTERACTIVE=1
      shift
      ;;
    --browser-command)
      BROWSER_CMD="$2"
      shift 2
      ;;
    --token-env)
      TOKEN_ENV_PATH="$2"
      TOKEN_ENV_EXPLICIT=1
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
    --inspect)
      INSPECT=1
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

if [[ -z "$TENANT_NAME" ]]; then
  echo "--tenant-name cannot be empty"
  exit 1
fi

if [[ -f "${TENANT_BOOTSTRAP_ROOT}/scripts/token-env.sh" ]]; then
  # shellcheck source=/dev/null
  source "${TENANT_BOOTSTRAP_ROOT}/scripts/token-env.sh"
fi

HAS_TOKEN_ENV=0
if [[ -n "${TOKEN_ENV_PATH:-}" ]]; then
  if [[ -f "$TOKEN_ENV_PATH" ]] && load_token_env "$TOKEN_ENV_PATH"; then
    HAS_TOKEN_ENV=1
  elif [[ "$TOKEN_ENV_EXPLICIT" -eq 1 ]]; then
    echo "Warning: token env path not usable: ${TOKEN_ENV_PATH}. Falling back to Azure CLI token mode."
  fi
fi

RUN_NAME_ARG=( )
if [[ -n "$RUN_NAME" ]]; then
  RUN_NAME_ARG+=(--run-name "$RUN_NAME")
fi

AUDIT_ARGS=(
  --tenant-name "$TENANT_NAME"
  --tenant-id "$TENANT_ID"
  --collectors "$COLLECTORS"
  --top "$TOP"
  --out "$OUT_DIR"
  --browser-command "$BROWSER_CMD"
)

if [[ "$INCLUDE_EXCHANGE" -eq 1 || "$COLLECTORS" == *"exchange"* ]]; then
  AUDIT_ARGS+=(--include-exchange)
fi

if [[ "$INTERACTIVE" -eq 1 ]]; then
  if [[ -z "$CLIENT_ID" ]]; then
    echo "Interactive mode requested without --client-id"
    exit 1
  fi
  AUDIT_ARGS+=(--interactive --client-id "$CLIENT_ID")
else
  if [[ "$HAS_TOKEN_ENV" -eq 1 ]]; then
    AUDIT_ARGS+=(--env "$TOKEN_ENV_PATH")
  else
    AUDIT_ARGS+=(--use-azure-cli-token)
  fi
fi

if [[ -n "$SCOPES" ]]; then
  AUDIT_ARGS+=(--scopes "$SCOPES")
fi
if [[ -n "$AUDITOR_PROFILE" ]]; then
  AUDIT_ARGS+=(--auditor-profile "$AUDITOR_PROFILE")
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  AUDIT_ARGS+=(--dry-run)
fi

if [[ "$INTERACTIVE" -eq 0 && "$HAS_TOKEN_ENV" -eq 0 && "$DRY_RUN" -eq 0 ]]; then
  if ! command -v az >/dev/null 2>&1; then
    echo "Azure CLI not found. Install azure-cli or use --interactive with --client-id."
    exit 2
  fi
  if ! az account show --output none >/dev/null 2>&1; then
    echo "No active Azure CLI session found. Launching browser login..."
    BROWSER="$BROWSER_CMD" az login --tenant "$TENANT_ID" --output none
    if ! az account show --output none >/dev/null 2>&1; then
      echo "Azure CLI sign-in did not complete. Retry az login manually and re-run."
      exit 3
    fi
  fi
fi

if [[ "${#RUN_NAME_ARG[@]}" -eq 0 && "${#RUN_NAME}" -eq 0 ]]; then
  AUDIT_ARGS+=(--run-name "auditor-${TOP}-$(date +%Y%m%d_%H%M%S)")
else
  AUDIT_ARGS+=("${RUN_NAME_ARG[@]}")
fi

FULL_CMD=(
  "${SCRIPT_DIR}/run-audit-collector.sh"
  "${AUDIT_ARGS[@]}"
)

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "DRY RUN:"
  printf '  %q ' "${FULL_CMD[@]}"
  echo
  exit 0
fi

if ! command -v bash >/dev/null 2>&1; then
  echo "bash is required to run this wrapper."
  exit 4
fi

set -o pipefail
"${FULL_CMD[@]}"

if [[ "$INSPECT" -eq 1 ]]; then
  RESOLVED_OUT="${OUT_DIR%/}/${TENANT_NAME}-${RUN_NAME:-auditor}"
  if [[ -d "$OUT_DIR" && -n "$(ls -dt "${OUT_DIR}"/* 2>/dev/null | head -n 1 || true)" ]]; then
    # best-effort resolve run dir for latest matching tenant/run-name
    RESOLVED_OUT="$(ls -dt "${OUT_DIR}"/*/ 2>/dev/null | head -n 1 || true)"
  fi
  if [[ -n "${RESOLVED_OUT}" ]]; then
    echo "Inspecting ${RESOLVED_OUT}"
    "${SCRIPT_DIR}/inspect-audit-logs.sh" "${RESOLVED_OUT}"
  else
    echo "No audit evidence directory found for inspection."
  fi
fi
