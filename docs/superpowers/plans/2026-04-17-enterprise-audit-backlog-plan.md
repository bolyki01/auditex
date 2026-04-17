# Enterprise Audit Backlog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework Auditex so it can audit large Microsoft 365 tenants with streaming collection, broader enterprise workload coverage, normalized evidence, and adapter-backed export/response foundations.

**Architecture:** Keep `src/azure_tenant_audit` as the canonical runtime, but replace list-materializing collection with streaming/chunked output, then add the first missing P0 workload families and an adapter registry for non-Graph surfaces. Use the existing bootstrap catalogs as workload intent, not as the production runtime.

**Tech Stack:** Python 3.11+, requests, msal, optional m365 CLI, optional PowerShell adapters, Markdown, JSON, pytest

---

## Execution status (2026-04-17)

Tasks 1–9 are implemented in-tree for all listed features: streaming transport, chunked writers, canonical security/auth/m365-sharepoint collectors, adapter registry, and diffing.

Verification status:

- Full Task 10 command executed in this environment:
  - `pytest tests/test_auditex_product.py tests/test_cli.py tests/test_output.py tests/test_graph_streaming.py tests/test_security_collectors.py tests/test_auth_methods_collector.py tests/test_sharepoint_collector.py tests/test_adapters.py tests/test_diffing.py -q`
  - PASS
- Next recommended action: run the same matrix against one large tenant fixture and exercise the optional `m365` adapter path.

### Task 1: Establish the enterprise runtime contract

**Files:**
- Create: `docs/superpowers/specs/2026-04-17-enterprise-audit-architecture-design.md`
- Modify: `README.md`
- Modify: `docs/specs/2026-04-16-auditex-product-spec.md`
- Test: `tests/test_auditex_product.py`

- [ ] **Step 1: Align the product docs with the enterprise target**

Add references in `README.md` and `docs/specs/2026-04-16-auditex-product-spec.md` to the new enterprise architecture spec so the canonical runtime no longer reads like a small collector runner only.

- [ ] **Step 2: Run focused regression checks**

Run: `pytest tests/test_auditex_product.py -q`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add README.md docs/specs/2026-04-16-auditex-product-spec.md docs/superpowers/specs/2026-04-17-enterprise-audit-architecture-design.md
git commit -m "docs: add enterprise audit architecture spec"
```

### Task 2: Replace full-list paging with streaming primitives

**Files:**
- Modify: `src/azure_tenant_audit/graph.py`
- Modify: `src/azure_tenant_audit/collectors/base.py`
- Modify: `src/azure_tenant_audit/config.py`
- Create: `tests/test_graph_streaming.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write the failing streaming transport tests**

Add tests that prove:
- `iter_pages()` follows `@odata.nextLink`
- `result_limit` stops global enumeration
- `page_size` does not imply full collection

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/test_graph_streaming.py tests/test_cli.py -q`
Expected: FAIL because the runtime only exposes `get_all()` semantics today.

- [ ] **Step 3: Implement streaming transport**

Add:
- `iter_pages()`
- `iter_items()`
- explicit `result_limit`
- backward-compatible wrapper behavior only where still required

Also rename CLI semantics so `--top` no longer lies about row caps.

- [ ] **Step 4: Run focused transport tests**

Run: `pytest tests/test_graph_streaming.py tests/test_cli.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/azure_tenant_audit/graph.py src/azure_tenant_audit/collectors/base.py src/azure_tenant_audit/config.py tests/test_graph_streaming.py tests/test_cli.py
git commit -m "feat: add streaming graph transport"
```

### Task 3: Add chunked evidence writing and keep memory bounded

**Files:**
- Modify: `src/azure_tenant_audit/output.py`
- Modify: `src/azure_tenant_audit/cli.py`
- Create: `tests/test_output_streaming.py`
- Modify: `tests/test_output.py`

- [ ] **Step 1: Write the failing writer tests**

Add tests that prove:
- page/chunk records can be appended to disk incrementally
- command/event logs still exist
- run manifests include chunk/index paths

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_output_streaming.py tests/test_output.py -q`
Expected: FAIL because current output writes whole collector payloads only.

- [ ] **Step 3: Implement chunked raw/index output**

Add directories and writer support for:
- `chunks/`
- `logs/`
- `blockers/`

Keep `raw/<collector>.json` only for small or synthesized summary payloads; large endpoint data must stream to chunked `jsonl`.

- [ ] **Step 4: Run focused writer tests**

Run: `pytest tests/test_output_streaming.py tests/test_output.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/azure_tenant_audit/output.py src/azure_tenant_audit/cli.py tests/test_output_streaming.py tests/test_output.py
git commit -m "feat: add chunked evidence writing"
```

### Task 4: Add canonical audit-log collectors

**Files:**
- Modify: `src/azure_tenant_audit/collectors/security.py`
- Modify: `configs/collector-definitions.json`
- Modify: `configs/collector-permissions.json`
- Create: `tests/test_security_collectors.py`

- [ ] **Step 1: Write the failing collector tests**

Add tests for:
- `directoryAudits`
- time-partitioned `signIns`
- partial status when one audit surface is blocked

- [ ] **Step 2: Run the new tests**

Run: `pytest tests/test_security_collectors.py -q`
Expected: FAIL because the canonical collector does not implement these behaviors yet.

- [ ] **Step 3: Implement partitioned security collection**

Extend the security collector to:
- collect `directoryAudits`
- support `since`/`until` partition windows
- record checkpoint metadata
- preserve blocker output when one surface returns `403` or similar

- [ ] **Step 4: Run focused collector tests**

Run: `pytest tests/test_security_collectors.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/azure_tenant_audit/collectors/security.py configs/collector-definitions.json configs/collector-permissions.json tests/test_security_collectors.py
git commit -m "feat: add partitioned audit log collectors"
```

### Task 5: Add MFA and auth-methods coverage

**Files:**
- Create: `src/azure_tenant_audit/collectors/auth_methods.py`
- Modify: `src/azure_tenant_audit/collectors/__init__.py`
- Modify: `configs/collector-definitions.json`
- Modify: `configs/collector-permissions.json`
- Create: `tests/test_auth_methods_collector.py`

- [ ] **Step 1: Write the failing auth-methods tests**

Cover:
- auth methods policy collection
- registration/reporting surfaces when available
- blocked status with useful escalation diagnostics

- [ ] **Step 2: Run the tests**

Run: `pytest tests/test_auth_methods_collector.py -q`
Expected: FAIL because no canonical auth-methods collector exists.

- [ ] **Step 3: Implement the collector**

Create a collector family for:
- auth methods policy
- registration campaign posture
- SSPR/auth posture references where available

Keep per-user deep reads optional and permission-aware.

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_auth_methods_collector.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/azure_tenant_audit/collectors/auth_methods.py src/azure_tenant_audit/collectors/__init__.py configs/collector-definitions.json configs/collector-permissions.json tests/test_auth_methods_collector.py
git commit -m "feat: add auth methods collector"
```

### Task 6: Add normalized, AI-safe, findings, and report scaffolding

**Files:**
- Create: `src/azure_tenant_audit/normalize.py`
- Create: `src/azure_tenant_audit/findings.py`
- Modify: `src/azure_tenant_audit/output.py`
- Modify: `schemas/finding.schema.json`
- Modify: `schemas/report_pack.schema.json`
- Create: `tests/test_normalize.py`
- Create: `tests/test_findings.py`

- [ ] **Step 1: Write failing normalization/finding tests**

Add tests that prove:
- raw/chunk records can normalize into canonical object records
- blocked surfaces create blocker artifacts
- simple findings and report-pack directories are emitted

- [ ] **Step 2: Run the tests**

Run: `pytest tests/test_normalize.py tests/test_findings.py -q`
Expected: FAIL because these runtime components do not exist yet.

- [ ] **Step 3: Implement minimal scaffolding**

Add:
- `normalized/`
- `ai_safe/`
- `findings/`
- `reports/`
- `blockers/`

Use simple first-pass transforms driven by collector coverage and diagnostics.

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_normalize.py tests/test_findings.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/azure_tenant_audit/normalize.py src/azure_tenant_audit/findings.py src/azure_tenant_audit/output.py schemas/finding.schema.json schemas/report_pack.schema.json tests/test_normalize.py tests/test_findings.py
git commit -m "feat: add normalized evidence and findings scaffolding"
```

### Task 7: Add the adapter registry for non-Graph enterprise surfaces

**Files:**
- Create: `src/azure_tenant_audit/adapters/__init__.py`
- Create: `src/azure_tenant_audit/adapters/base.py`
- Create: `src/azure_tenant_audit/adapters/m365_cli.py`
- Create: `src/azure_tenant_audit/adapters/m365dsc.py`
- Create: `src/azure_tenant_audit/adapters/powershell_graph.py`
- Create: `tests/test_adapters.py`
- Modify: `src/azure_tenant_audit/collectors/exchange.py`

- [ ] **Step 1: Write the failing adapter tests**

Add tests that prove:
- adapters declare dependency, auth mode, and output normalization contract
- exchange collector can resolve command execution through the registry rather than hard-coded variants only

- [ ] **Step 2: Run the tests**

Run: `pytest tests/test_adapters.py tests/test_exchange_collector.py -q`
Expected: FAIL because no adapter registry exists.

- [ ] **Step 3: Implement the adapter registry**

Create a common adapter contract with:
- `name`
- `dependency_check()`
- `auth_requirements`
- `run()`
- `normalize()`

Use it first for Exchange command collection and future Purview/response integrations.

- [ ] **Step 4: Run focused adapter tests**

Run: `pytest tests/test_adapters.py tests/test_exchange_collector.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/azure_tenant_audit/adapters src/azure_tenant_audit/collectors/exchange.py tests/test_adapters.py tests/test_exchange_collector.py
git commit -m "feat: add enterprise adapter registry"
```

### Task 8: Add first-class SharePoint/OneDrive inventory collectors

**Files:**
- Create: `src/azure_tenant_audit/collectors/sharepoint.py`
- Modify: `src/azure_tenant_audit/collectors/__init__.py`
- Modify: `configs/collector-definitions.json`
- Modify: `configs/collector-permissions.json`
- Create: `tests/test_sharepoint_collector.py`

- [ ] **Step 1: Write the failing tests**

Cover:
- tenant SharePoint settings
- site inventory
- graceful partial results when OneDrive/site surfaces are not provisioned

- [ ] **Step 2: Run the tests**

Run: `pytest tests/test_sharepoint_collector.py -q`
Expected: FAIL because no canonical SharePoint collector exists.

- [ ] **Step 3: Implement the collector**

Build read-only inventory coverage for:
- tenant settings
- site inventory
- basic sharing posture

Treat OneDrive readiness failures as expected blocker states, not fatal errors.

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_sharepoint_collector.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/azure_tenant_audit/collectors/sharepoint.py src/azure_tenant_audit/collectors/__init__.py configs/collector-definitions.json configs/collector-permissions.json tests/test_sharepoint_collector.py
git commit -m "feat: add sharepoint inventory collector"
```

### Task 9: Add diff-ready run snapshots

**Files:**
- Create: `src/azure_tenant_audit/diffing.py`
- Modify: `src/auditex/mcp_server.py`
- Modify: `src/azure_tenant_audit/output.py`
- Create: `tests/test_diffing.py`

- [ ] **Step 1: Write failing diff tests**

Add tests that prove:
- normalized snapshots can compare `added`, `removed`, and `changed`
- MCP can summarize a diff between two run directories

- [ ] **Step 2: Run the tests**

Run: `pytest tests/test_diffing.py -q`
Expected: FAIL because diffing does not exist in the runtime yet.

- [ ] **Step 3: Implement minimal diffing**

Create object-keyed snapshot comparison for:
- users
- groups
- policies
- devices

Expose a new MCP tool after the core diffing path works locally.

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_diffing.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/azure_tenant_audit/diffing.py src/auditex/mcp_server.py src/azure_tenant_audit/output.py tests/test_diffing.py
git commit -m "feat: add run diffing support"
```

### Task 10: Run a full focused verification pass

**Files:**
- Modify: `README.md`
- Modify: `docs/audit-runbook.md`
- Test: `tests/test_auditex_product.py`
- Test: `tests/test_cli.py`
- Test: `tests/test_output.py`
- Test: `tests/test_graph_streaming.py`
- Test: `tests/test_security_collectors.py`
- Test: `tests/test_auth_methods_collector.py`
- Test: `tests/test_sharepoint_collector.py`
- Test: `tests/test_adapters.py`
- Test: `tests/test_diffing.py`

- [ ] **Step 1: Update operator docs**

Document:
- streaming output behavior
- new collectors
- blocker semantics
- adapter dependency model
- diff workflow

- [ ] **Step 2: Run the focused verification suite**

Run:
```bash
pytest \
  tests/test_auditex_product.py \
  tests/test_cli.py \
  tests/test_output.py \
  tests/test_graph_streaming.py \
  tests/test_security_collectors.py \
  tests/test_auth_methods_collector.py \
  tests/test_sharepoint_collector.py \
  tests/test_adapters.py \
  tests/test_diffing.py -q
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add README.md docs/audit-runbook.md tests
git commit -m "docs: update auditex enterprise runtime docs"
```

## Self-Review

- spec coverage:
  - streaming scale: covered by Tasks 2-3
  - missing P0 collectors: covered by Tasks 4, 5, 8
  - normalized/findings/report model: covered by Task 6
  - adapter-backed enterprise surfaces: covered by Task 7
  - diff/drift: covered by Task 9
- placeholder scan:
  - no `TBD` or unresolved placeholders remain
- type consistency:
  - new modules are named consistently with the canonical runtime package

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-17-enterprise-audit-backlog-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** - dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - execute tasks in this session using executing-plans, batch execution with checkpoints
