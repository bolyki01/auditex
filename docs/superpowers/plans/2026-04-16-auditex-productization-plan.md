# Auditex Productization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the current Microsoft tenant audit repo into a portable Codex-operated product with stable CLI aliases, profiles, local skills, MCP scaffolding, and auditable outputs.

**Architecture:** Keep `src/azure_tenant_audit` as the canonical runtime, then wrap it with a thin `auditex` product layer. Package operator behavior in repo-local skills and docs, and expose a small local MCP surface for repeatable agent usage.

**Tech Stack:** Python 3.11+, setuptools, requests, msal, optional mcp, Markdown, JSON

---

### Task 1: Add the stable product surface

**Files:**
- Create: `src/auditex/__init__.py`
- Create: `src/auditex/cli.py`
- Create: `src/auditex/mcp_server.py`
- Modify: `pyproject.toml`
- Test: `tests/test_auditex_product.py`

- [ ] **Step 1: Add the wrapper package and scripts**

Create a thin wrapper around `azure_tenant_audit.cli:main` and add `auditex` / `auditex-mcp` console scripts.

- [ ] **Step 2: Run focused packaging tests**

Run: `pytest tests/test_auditex_product.py -q`
Expected: PASS

### Task 2: Promote audit profiles into the canonical runtime

**Files:**
- Create: `src/azure_tenant_audit/profiles.py`
- Modify: `src/azure_tenant_audit/cli.py`
- Modify: `src/azure_tenant_audit/config.py`
- Modify: `src/azure_tenant_audit/output.py`
- Test: `tests/test_auditex_product.py`

- [ ] **Step 1: Add built-in profile definitions**

Define `auto`, `global-reader`, `security-reader`, `exchange-reader`, `intune-reader`, and `app-readonly-full`.

- [ ] **Step 2: Wire profile selection into CLI and manifests**

Add `--auditor-profile` and record it in run outputs and diagnostics.

- [ ] **Step 3: Run focused tests**

Run: `pytest tests/test_auditex_product.py tests/test_cli.py -q`
Expected: PASS

### Task 3: Package the operator knowledge

**Files:**
- Create: `SOUL.md`
- Create: `docs/specs/2026-04-16-auditex-product-spec.md`
- Create: `skills/auditex-operator/SKILL.md`
- Create: `skills/delegated-auth/SKILL.md`
- Create: `skills/app-readonly-escalation/SKILL.md`
- Create: `skills/evidence-pack/SKILL.md`

- [ ] **Step 1: Write the product contract**
- [ ] **Step 2: Write the Codex skill pack**

### Task 4: Add machine-readable packaging artifacts

**Files:**
- Create: `profiles/global-reader.md`
- Create: `profiles/security-reader.md`
- Create: `profiles/exchange-reader.md`
- Create: `profiles/intune-reader.md`
- Create: `profiles/app-readonly-full.md`
- Create: `schemas/run_manifest.schema.json`
- Create: `schemas/collector_result.schema.json`
- Create: `schemas/blocker.schema.json`
- Create: `schemas/finding.schema.json`
- Create: `schemas/report_pack.schema.json`

- [ ] **Step 1: Write the profile docs**
- [ ] **Step 2: Write the output schemas**

### Task 5: Verify and publish

**Files:**
- Modify: `README.md`
- Test: `tests/test_auditex_product.py`

- [ ] **Step 1: Run verification**

Run: `pytest tests/test_auditex_product.py tests/test_cli.py tests/test_output.py tests/test_config.py -q`
Expected: PASS

- [ ] **Step 2: Create or update the GitHub repository**

Run:
```bash
gh repo create bolyki01/auditex --public --source=. --remote=origin --push
```

Expected: repository created or a clear “already exists” message, with branch pushed afterward.
