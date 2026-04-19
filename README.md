# Auditex

Auditex is a portable, AI-first Microsoft 365 audit toolkit for Codex-operated tenant assessments.

The operating model is:

- customer signs in with delegated `Global Reader` or another read role
- Auditex collects evidence locally
- operator control is CLI/MCP-first; there is no GUI
- collector failures are isolated and written as blocker evidence
- raw tenant data stays local
- AI reads normalized and `ai_safe` artifacts by default
- optional customer-local read-only app consent can unlock deeper second-pass collection
- guarded response actions live in a separate `auditex response` namespace and are dry-run by default

## Product shape

- `src/azure_tenant_audit/`
  Canonical Python audit engine and collectors
- `src/auditex/`
  Product wrapper, stable CLI alias, and MCP server entrypoint
- `skills/`
  Local Codex-facing skill pack for repeatable operator behavior
- `profiles/`
  Profile documents for delegated and app-readonly audit modes
- `schemas/`
  Stable machine-readable output contracts
- `docs/specs/`
  Product and architecture specs
- `tenant-bootstrap/`
  Lab and bootstrap tooling for homelab population and tenant simulation

## First-class platforms

- macOS ARM
- Linux x64/ARM

Supported but secondary:

- Windows

The core runtime stays Python-only. `pwsh` and `m365` are optional adapters, not part of the critical path.

## Prereqs

- Python 3.11+
- Azure CLI (`az`) for delegated sign-in
- `m365` only for Exchange-backed collectors

Local setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
auditex setup
```

If you need the MCP server:

```bash
auditex setup --mcp
```

If you need Exchange-backed or PowerShell-backed paths:

```bash
auditex setup --exchange
auditex setup --pwsh
```

The local login flow uses `make login TENANT=<tenant>` or `./scripts/tenant-audit-login <tenant>`. For tenant-level reader accounts, that path now uses `az login --allow-no-subscriptions`.

Readiness check:

```bash
auditex doctor
```

JSON doctor output:

```bash
auditex doctor --json
```

Guided first run:

```bash
auditex guided-run
```

The guided flow is the main operator path.

It can:

- run a normal `Global Reader` audit
- do a one-time `Global Admin` app setup for Exchange-backed collection
- run an app audit with saved app credentials

Normal path is `Global Reader`. `Global Admin` is only for the one-time app setup.

First-time GA setup:

```bash
auditex guided-run --flow ga-setup-app
```

Normal GR audit after that:

```bash
auditex guided-run --flow gr-audit --include-exchange
# or repo-local:
./scripts/tenant-audit-flow --flow gr-audit --include-exchange
```

Saved app audit:

```bash
auditex guided-run --flow app-audit
```

The flow bootstraps tools, walks login, stores local app details in `.secrets/m365-auth.env`, runs preflight, then writes the full evidence bundle for later AI use.
Supported guided flags:

- `--flow`
- `--auth-mode`
- `--client-id`
- `--client-secret`
- `--tenant-id`
- `--tenant-name`
- `--auditor-profile`
- `--out`
- `--run-name`
- `--top`
- `--page-size`
- `--browser-command`
- `--collectors`
- `--include-exchange`
- `--throttle-mode`
- `--include-blocked`
- `--with-mcp`
- `--non-interactive`
- `--local-mode`
- `--skip-login-check`
- `--skip-tool-check`
- `--report-format`
- `--probe-first` / `--no-probe-first`

App-guided flow:

```bash
auditex guided-run \
  --auth-mode app \
  --tenant-id <tenant-id-or-domain> \
  --tenant-name <label> \
  --client-id <app-id> \
  --client-secret <secret> \
  --auditor-profile app-readonly-full \
  --non-interactive
```

For the full first-run path, see `docs/audit-runbook.md`.

Source provenance:

Auditex ships with a proprietary top-level license, a third-party notice file, and a provenance sheet under `docs/provenance/`. Legacy source-review tooling is not part of the product tree.

## Install

Use the `Prereqs` commands above. Keep `.venv/` local; it is already ignored.

## Main flows

Offline validation:

```bash
auditex --offline --tenant-name demo --out outputs/offline
```

Raw CLI surface:

```bash
auditex compare --run-dir run-a --run-dir run-b
auditex report render <run-dir> --format md
auditex export list
auditex export run <exporter-name> <run-dir>
auditex notify send <run-dir> --sink teams
```

Supported flags:

- `auditex compare`: `--allow-cross-tenant`
- `auditex report render`: `--include-section`, `--exclude-section`, `--output`
- `auditex export run`: `--include-section`, `--exclude-section`, `--output`
- `auditex notify send`: `--execute`
- `auditex notify send --sink`: `teams`, `slack`, `smtp`

Delegated one-off audit with Azure CLI token reuse:

```bash
az login --tenant contoso.onmicrosoft.com
auditex \
  --tenant-name CONTOSO \
  --tenant-id contoso.onmicrosoft.com \
  --use-azure-cli-token \
  --auditor-profile global-reader \
  --out outputs/live
```

Access-token mode:

```bash
auditex \
  --tenant-name CONTOSO \
  --tenant-id contoso.onmicrosoft.com \
  --access-token '<graph-token>' \
  --auditor-profile global-reader \
  --out outputs/live
```

Saved auth contexts from `auditex auth import-token` can be reused for `auditex probe live --auth-context <name>` and `auditex response run --auth-context <name>`.

Optional Exchange coverage:

```bash
auditex \
  --tenant-name CONTOSO \
  --tenant-id contoso.onmicrosoft.com \
  --use-azure-cli-token \
  --auditor-profile global-reader \
  --include-exchange \
  --out outputs/live
```

Safer live runs can use:

```bash
auditex run --probe-first --throttle-mode safe
```

## Profiles

Built-in profiles:

- `auto`
- `global-reader`
- `security-reader`
- `exchange-reader`
- `intune-reader`
- `app-readonly-full`

These profiles do not force permissions into existence. They shape:

- expected role context
- default collector intent
- escalation guidance in diagnostics
- report wording about blocked coverage

Quick support matrix:

| Path | CLI profile | Sign-in | Exchange-assisted | Response |
| --- | --- | --- | --- | --- |
| Global Reader | `global-reader` | Delegated | Optional with `--include-exchange` | No |
| Security Reader | `security-reader` | Delegated | No | No |
| App read-only full | `app-readonly-full` | App-only or delegated token | Yes, with `m365` and `powershell_graph` adapters | No |
| Exchange-assisted | `exchange-reader` | Delegated | Yes, built in | Yes |

Use `auditex probe live --mode delegated|app` for probe runs and `auditex response run --auditor-profile <profile>` for guarded response planning. `exchange-reader` is the only built-in response-capable profile.

## Output contract

Current engine outputs:

- `run-manifest.json`
- `summary.json`
- `summary.md`
- `audit-log.jsonl`
- `audit-debug.log`
- `raw/`
- `index/coverage.jsonl`
- `blockers/blockers.json` and `diagnostics.json` when blockers exist
- `normalized/`
- `ai_safe/`
- `findings/`
- `reports/`
- `chunks/`
- `checkpoints/checkpoint-state.json`

Product target directories are fully implemented and documented in `schemas/` and `docs/specs/`.

Enterprise-scale architecture and backlog are documented in:

- `docs/superpowers/specs/2026-04-17-enterprise-audit-architecture-design.md`
- `docs/superpowers/plans/2026-04-17-enterprise-audit-backlog-plan.md`

## MCP

Local MCP entrypoint:

```bash
auditex-mcp
```

Current MCP tools:

- `auditex_list_profiles`
- `auditex_run_offline_validation`
- `auditex_run_delegated_audit`
- `auditex_summarize_run`
- `auditex_diff_runs`
- `auditex_compare_runs`
- `auditex_probe_live`
- `auditex_probe_summarize`
- `auditex_list_blockers`
- `auditex_report_preview`
- `auditex_export_list`
- `auditex_notify_preview`
- `auditex_rules_inventory`
- `auditex_list_response_actions`
- `auditex_run_response_action`
- `auditex_auth_status`
- `auditex_auth_list`
- `auditex_auth_use`

## Response

Guarded response actions are isolated from the default audit plane:

```bash
auditex response list-actions
auditex response run --tenant-name ACME --action message_trace --target user@contoso.com --intent "triage mail flow" --tenant-id organizations
```

By default the response command writes a dry-run bundle. Execution requires `--execute`, explicit intent, a response-capable profile, and lab-tenant gating.

## Privacy and auditability

- secrets and tokens are scrubbed from command logging
- collector crashes do not abort the run
- permission issues become structured diagnostics
- raw tenant evidence is stored locally
- normalized and `ai_safe` artifacts are the default reasoning surfaces

## GitHub

Target repository: `bolyki01/auditex`
