#!/usr/bin/env bash
set -euo pipefail

cat <<'MSG'
This script documents the cutover flow. Run it from a sanitized Auditex tree only.

Recommended remote cutover:
  git remote add origin <NEW_PRIVATE_REMOTE_URL>
  git push -u origin main

If reusing the old remote and accepting force-push risk:
  git remote set-url origin <OLD_REMOTE_URL>
  git push --force --prune origin main
  git push --delete origin <OLD_RISKY_TAG_1> <OLD_RISKY_TAG_2>

Do not merge this tree into the old repository. That preserves old tainted history.
MSG
