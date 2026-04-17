# Auditex

Auditex is a portable, AI-first Microsoft 365 audit toolkit for Codex-operated tenant assessments.

The operating model is:

- customer signs in with delegated `Global Reader` or another read role
- Auditex collects evidence locally
- collector failures are isolated and written as blocker evidence
- raw tenant data stays local
- AI reads `ai_safe` artifacts by default
- optional customer-local read-only app consent can unlock deeper second-pass collection

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

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional MCP support:

```bash
pip install -e '.[mcp]'
```

## Main flows

Offline validation:

```bash
auditex --offline --tenant-name demo --out outputs/offline
```

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

## Output contract

Current engine outputs:

- `run-manifest.json`
- `summary.json`
- `summary.md`
- `audit-log.jsonl`
- `audit-debug.log`
- `raw/`
- `index/coverage.jsonl`
- `diagnostics.json` when blockers exist

Product target directories are documented and scaffolded in `schemas/` and `docs/specs/`.

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

## Privacy and auditability

- secrets and tokens are scrubbed from command logging
- collector crashes do not abort the run
- permission issues become structured diagnostics
- raw tenant evidence is stored locally
- AI-safe review is the default reasoning surface

## GitHub

Target repository: `bolyki01/auditex`
