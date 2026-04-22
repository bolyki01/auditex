# Auditex Improvement Plan

## Mission

Keep Auditex as a trustworthy local-first Microsoft 365 audit product. Make the contract stable. Make the operator flow sharp. Make scale and release safer without weakening evidence discipline.

## Current State

- The repo already has a good product split:
  `src/azure_tenant_audit/` is the engine.
  `src/auditex/` is the product wrapper, auth, reporting, exporters, notify, guided flow, and MCP.
- Collector behavior is mostly config-driven through `configs/collector-definitions.json`, permission maps, presets, report sections, and finding templates.
- Output shape is already rich:
  raw payloads, chunks, blockers, normalized, `ai_safe`, findings, reports, checkpoints, `index/evidence.sqlite`, `ai_context.json`, and `validation.json`.
- Auth paths are flexible:
  Azure CLI token, saved auth contexts, app auth, optional Exchange and PowerShell helpers.
- The repo has serious test coverage:
  CLI, output, streaming, probe, response, scale, collectors, adapters, auth, bootstrap.
- CI exists and is useful, but it is still generic:
  pytest, help smoke, and contract smoke.
- The main architectural pressure is orchestration sprawl.
  `azure_tenant_audit/cli.py`, `probe.py`, and `findings.py` carry too much policy, contract, and finalize logic.
- The product promise is now bigger than "collect some JSON".
  The bundle contract, evidence lineage, and MCP surface are product features.

## Key Opportunities

- Architecture:
  split planning, auth, collector execution, diagnostics, and bundle finalization into explicit services.
- Contract stability:
  stop treating run artifacts as incidental implementation detail.
  Version them and freeze them with golden tests.
- Evidence quality:
  make evidence refs complete and machine-checked for every finding.
- Operator UX:
  improve `guided-run`, `doctor`, probe blockers, and response blockers so the next step is obvious.
- Auth hardening:
  unify token inspection, saved auth context freshness, adapter readiness, and profile gating.
- Performance:
  improve large-tenant flow with clearer concurrency rules, chunk limits, and resume behavior.
- Security:
  keep redaction and local-only raw evidence strict.
  Validate that `ai_safe` output never drifts into unsafe territory.
- Release and ops:
  make bootstrap, provenance, notices, and CI align with a reproducible release path.

## Prioritized Roadmap

### Phase 1: Freeze the Contract

- Define versioned schemas for:
  `run-manifest.json`, `summary.json`, `reports/report-pack.json`, `capability-matrix.json`, `blockers/blockers.json`, `ai_context.json`, and `validation.json`.
- Add golden fixtures for:
  offline run, delegated run, probe run, compare output, and guarded response bundle.
- Add contract tests for `auditex.mcp_server` so MCP tools cannot drift from CLI behavior.
- Make bundle validation fail loudly when required artifacts or refs are missing.

### Phase 2: Split Orchestration

- Break `azure_tenant_audit/cli.py` into:
  parser, auth resolution, collector planning, execution loop, diagnostics builder, artifact finalizer.
- Break `probe.py` into:
  toolchain readiness, auth resolution, surface probing, blocker synthesis, bundle finalization.
- Keep collectors narrow.
  Cross-collector policy must live outside collector implementations.
- Move shared finalize logic out of command entrypoints so run, probe, and response use one contract path where possible.

### Phase 3: Strengthen Evidence and Findings

- Make evidence refs mandatory for generated findings.
- Push more reporting and compare logic through `index/evidence.sqlite` instead of ad hoc JSON walks.
- Add backward-compatible readers or explicit migrations for older run bundles.
- Add integrity checks:
  duplicate finding IDs, broken artifact refs, missing normalized sections, bad record keys.
- Make coverage ledger semantics precise and durable.
  Keep exact distinctions like exact scope, effective role, blocked permission, not-run, and runtime failure.

### Phase 4: Harden Auth and Adapters

- Build one adapter capability registry:
  auth mode, required tools, supported profiles, supported actions, write risk, expected commands.
- Expand `auditex doctor` and `auditex auth capability` to show:
  token audience, expiry, delegated scopes, app roles, tenant id, and toolchain readiness.
- Add saved-auth rotation and stale-context warnings.
- Keep response plane gated by profile, explicit intent, and lab tenant allowlist.
- Add auth-path-specific smoke tests:
  Azure CLI, saved context, app token, missing toolchain, expired token.

### Phase 5: Improve Scale and Runtime Behavior

- Introduce explicit collector concurrency groups.
  Do not let "fast" mode become unbounded parallelism.
- Tune batching and paging with collector-local defaults instead of one global assumption.
- Cache identity and role lookups once per run.
- Expand checkpoint coverage for export-style or command-driven collectors.
- Add memory-budget tests around chunking and large-tenant sample truncation.

### Phase 6: Tighten Release and Operations

- Turn the runbook into a release-grade checklist:
  env bootstrap, optional adapters, sample audit, probe smoke, response smoke, MCP smoke.
- Test `tenant-bootstrap/` from a clean environment so it cannot silently drift from root runtime behavior.
- Generate a release bundle manifest that ties shipped code, notices, provenance docs, and output schemas together.
- Keep sample outputs and docs aligned with the real bundle contract.

## Guardrails

- Do not change root artifact names or paths without migration tests.
- Do not let `tenant-bootstrap/` fork behavior from the root runtime.
- Do not mix raw evidence and AI-safe artifacts.
- Do not weaken secret scrubbing in logs, manifests, or auth context artifacts.
- Do not move response actions closer to the default audit plane.
- Keep config, profile, schema, and doc changes paired.
- Prefer narrow collector changes over broad cross-cutting rewrites.

## Acceptance Signals

- Offline, delegated, probe, compare, report render, and response flows all produce stable goldens.
- Every successful bundle contains a valid `index/evidence.sqlite`, `ai_context.json`, and `validation.json`.
- MCP tool outputs match CLI outputs for the same inputs.
- A blocked collector produces structured blockers, actionable guidance, and stable coverage semantics.
- Large-tenant runs stream safely into chunks without memory blowups.
- Bootstrap and root runtime behave the same for shared flows.
- Provenance docs, notices, and shipped code stay aligned.

## Output Required At End

- A full zip containing the updated source code, this improvement plan, and all implementation changes.
