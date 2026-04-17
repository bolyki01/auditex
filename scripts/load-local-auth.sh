#!/usr/bin/env bash

set -euo pipefail

LOCAL_AUTH_ENV="${AUDITEX_LOCAL_AUTH_ENV:-}"
if [[ -z "${LOCAL_AUTH_ENV}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  LOCAL_AUTH_ENV="${SCRIPT_DIR}/../.secrets/m365-auth.env"
fi

if [[ -f "${LOCAL_AUTH_ENV}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${LOCAL_AUTH_ENV}"
  set +a
fi
