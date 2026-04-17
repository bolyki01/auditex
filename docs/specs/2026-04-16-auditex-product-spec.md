# Auditex Product Specification

## Goal

Package this repo as a portable AI-first Microsoft 365 audit tool operated by Codex, with deterministic evidence, failure-tolerant collection, and optional customer-local app escalation.

## Canonical runtime

`src/azure_tenant_audit/` is the canonical runtime package.

`tenant-bootstrap/` remains adjacent lab/bootstrap tooling and evidence from homelab work. It is not the primary product entrypoint.

## Public entrypoints

- `auditex`
- `azure-tenant-audit`
- `auditex-mcp`

## Auth modes

Primary:

- delegated token via Azure CLI reuse
- delegated supplied access token
- delegated interactive login

Secondary:

- customer-local read-only app registration

## Output model

Stable artifacts required per run:

- `run-manifest.json`
- `summary.json`
- `summary.md`
- `audit-log.jsonl`
- `audit-debug.log`
- `raw/`
- `index/coverage.jsonl`
- `diagnostics.json` when needed
- `blockers/blockers.json` and optional `diagnostics.json`
- `normalized/`
- `ai_safe/`
- `findings/`
- `reports/`
- `chunks/`
- `checkpoints/checkpoint-state.json`

`blockers/` and optional `checkpoints/` are created for resumable and partial runs.

## Failure model

Each collector must end in one of:

- `ok`
- `partial`
- `failed`
- `not_applicable`

Blocked or partial coverage must record:

- attempted endpoint or command
- auth mode
- profile
- error class
- error text
- recommended delegated role
- optional app-readonly escalation permission set

## Privacy model

- raw evidence stays local
- AI should reason over AI-safe artifacts by default
- token values and secrets must be redacted from logs
- document-content access must be explicit and logged

## MCP surface

The local MCP server exposes orchestration, not tenant-specific hidden state:

- list profiles
- run offline validation
- run delegated audit
- summarize completed run
- diff two completed runs
- probe live toolchain readiness
- list blockers for a completed run
- auth status/list/use helpers
- list guarded response actions
- run guarded response actions in a separate bundle

## Skills surface

Local skills exist to teach Codex:

- how to choose auth modes
- how to operate delegated-first audits
- how to escalate to customer-local read-only apps
- how to interpret evidence and blockers

## Known repository debt

- duplicated runtime code exists under `tenant-bootstrap/azure_tenant_audit`
- evidence model and MCP surface have been expanded since this file was authored; current implementation is represented by the concrete schema + MCP contracts in this repo

Current enterprise gap list remains:

- deeper Defender, Purview, and eDiscovery action depth
- large-tenant validation against a real customer matrix
- more response adapters beyond the current guarded scaffold

This spec accepts those facts and moves the public surface toward a coherent product without rewriting the homelab history.

The enterprise-scale target architecture and implementation backlog are extended in:

- `docs/superpowers/specs/2026-04-17-enterprise-audit-architecture-design.md`
- `docs/superpowers/plans/2026-04-17-enterprise-audit-backlog-plan.md`
