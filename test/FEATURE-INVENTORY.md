# Auditex Feature Inventory

## Product Intent

Auditex is a portable, AI-operated Microsoft 365 tenant audit toolkit with a delegated-first model, optional customer-local app escalation, local evidence retention, resumable collection, and MCP-driven orchestration.

## Canonical Runtime

Primary runtime:

- `src/azure_tenant_audit/`
- `src/auditex/`

These are the product surfaces that matter. `tenant-bootstrap/` is lab/bootstrap support, not the canonical runtime.

## Planes

### Inventory plane

Purpose:

- tenant posture
- policies
- users
- groups
- apps
- devices
- workload configuration
- normalized findings and report pack

Expected auth:

- delegated Azure CLI token reuse
- delegated supplied token
- delegated interactive login
- optional customer-local read-only app

### Export plane

Purpose:

- high-volume evidence copy-out
- checkpointed raw export artifacts
- Purview and eDiscovery export-oriented surfaces

Current shape:

- present in CLI and profiles
- collector support exists
- still relies heavily on adapter-backed command surfaces

### Response plane

Purpose:

- explicitly separated guarded actions
- dry-run-first command planning
- explicit operator intent
- separate artifact bundle

Current actions:

- `message_trace`
- `user_audit_history`
- `purview_audit_export`

## Collectors

Registered collectors:

- `identity`
- `security`
- `conditional_access`
- `defender`
- `auth_methods`
- `intune`
- `sharepoint`
- `teams`
- `exchange`
- `purview`
- `ediscovery`

Key collector intent:

- `identity`: Entra organization, domains, users, groups, apps, service principals, roles, assignments
- `security`: sign-ins and directory audits
- `conditional_access`: policies, named locations, auth strengths, auth contexts
- `defender`: alerts, incidents, secure scores, secure score controls
- `auth_methods`: auth methods policy and MFA registration posture
- `intune`: managed devices, compliance policies, configuration profiles
- `sharepoint`: tenant settings and site inventory
- `teams`: team groups and channels
- `exchange`: posture and command-backed Exchange evidence
- `purview`: readiness, retention, DLP, export-oriented audit job surfaces
- `ediscovery`: Graph case inventory plus command-backed search/export/review-set surfaces

## Profiles

Built-in profiles:

- `auto`
- `global-reader`
- `security-reader`
- `exchange-reader`
- `intune-reader`
- `app-readonly-full`

Important profile behavior:

- profiles shape defaults and diagnostics
- profiles do not create permissions that do not exist
- `exchange-reader` is currently the response-capable profile
- `app-readonly-full` is the deepest intended read-only profile

## Output Model

Per-run artifact model:

- `run-manifest.json`
- `summary.json`
- `summary.md`
- `audit-log.jsonl`
- `audit-command-log.jsonl`
- `audit-debug.log`
- `raw/`
- `chunks/`
- `index/coverage.jsonl`
- `blockers/`
- `normalized/`
- `ai_safe/`
- `findings/`
- `reports/`
- `checkpoints/checkpoint-state.json`

Important behavior:

- raw evidence stays local
- command invocations are logged
- blockers are structured rather than free-text only
- normalization produces AI-safe surfaces by default

## MCP Surface

Current orchestration tools include:

- profile listing
- collector listing
- adapter listing
- delegated audit execution
- run summary
- run diff
- live capability probe
- blocker listing
- response action listing
- response action execution
- local auth status/list/use

## Current Position

The repo is beyond MVP collector scaffolding. It now has a plausible platform shape.

It is not finished. The main remaining concerns are depth, scale proof, and richer response/export adapters.
