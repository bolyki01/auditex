---
name: delegated-auth
description: Use when starting a customer Microsoft 365 audit without an app registration and you need the delegated-first Global Reader workflow.
---

# Delegated Auth

## Default rule

Start with delegated `Global Reader` or equivalent before asking for app consent.

## Preferred path

```bash
az login --tenant <tenant>
auditex guided-run --flow gr-audit --include-exchange
auditex run --tenant-name <label> --tenant-id <tenant> --use-azure-cli-token --auditor-profile global-reader --out outputs/live
```

## What to record

- who signed in
- what role context was visible
- what collectors were blocked
- what additional delegated role would help

If delegated visibility is enough, do not escalate.
