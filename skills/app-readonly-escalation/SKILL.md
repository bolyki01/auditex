---
name: app-readonly-escalation
description: Use when a delegated Microsoft 365 audit is blocked and you need to justify a customer-local read-only app registration as a second pass.
---

# App-Readonly Escalation

## Rule

Use app consent only as a documented second pass.

## Requirements

- customer-local app registration
- read-only permissions only
- exact justification tied to blocked collectors
- no shared multi-tenant customer evidence

## Output

State:

- what delegated mode collected
- what remained blocked
- what exact app permissions would unlock more depth
- why those permissions are read-only and scoped to this tenant
