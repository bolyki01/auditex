# Enterprise Tenant Bootstrap Expansion Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the bootstrap kit from a small seed to a full enterprise-style tenant model by generating 20+ users plus 200+ realistic identity/group constructs, including dynamic membership, security and collaboration group families, and enterprise auditability.

**Architecture:** Extend `02-seed-identities-groups.ps1` to build a predictable group catalog from config-driven recipes, while keeping all IDs/idempotent checks in a single identity step. Keep configuration-only knobs for enterprise scale and optional dry-run-safe preview.

**Tech Stack:** PowerShell 7+, Microsoft Graph PowerShell SDK (`New-Mg*`, `Get-Mg*`, `Invoke-MgGraphRequest`).

---

### Task 1: Add enterprise seeding schema

**Files:**
- Modify: `tenant-bootstrap/config.example.json`
- Modify: `tenant-bootstrap/README.md`

- [ ] Add enterprise scale configuration fields:
  - `enterpriseScale.enabled`
  - `enterpriseScale.targetStaticGroupCount`
  - `enterpriseScale.includeDynamicFamilies` and `enterpriseScale.dynamicRules`
  - department role templates used by seeding loops
- [ ] Add generated group-family metadata needed by licensing and team mapping.
- [ ] Update README with a short “scale knobs” section and examples for turning down/up group volume.

### Task 2: Implement scalable identity/group seeding

**Files:**
- Modify: `tenant-bootstrap/scripts/02-seed-identities-groups.ps1`
- Optionally: `tenant-bootstrap/scripts/00-shared.ps1` (only if group membership helpers become necessary)

- [ ] Introduce helper `New-EnterpriseGroupSeedSet` and deterministic seed arrays for:
  - department app groups (M365 and security),
  - function/discipline groups,
  - environment/tier groups,
  - policy/risk/overshare scenario groups,
  - nested security sub-groups.
- [ ] Add 200+ group creation path when enabled by config while preserving existing seed groups (`allUsers`, admins, break-glass, copilot, reporting, Entra P2, it/sales/finance M365).
- [ ] Ensure all static and dynamic groups are created with `Ensure-Group` / `Ensure-DynamicGroup` and logged once per step.
- [ ] Add post-seed memberships for:
  - all users into `GG-L0-AllUsers`,
  - break-glass users into break-glass group,
  - named admin + P2 role pilots into admin security and P2 groups,
  - selected Copilot and reporting user rings.
- [ ] Expand final summary details to include actual user and group counts.

### Task 3: Validate and log run shape

**Files:**
- Modify: `tenant-bootstrap/scripts/02-seed-identities-groups.ps1`

- [ ] Validate script runs in dry-run mode and writes command/audit events without Graph calls.
- [ ] Keep idempotency behavior unchanged: reruns should be safe with no duplicate groups/users.
- [ ] Verify all new config properties are optional defaulted inside script logic so old configs degrade gracefully.

### Execution choice

Plan complete and saved to `docs/superpowers/plans/2026-04-16-tenant-enterprise-bootstrap-plan.md`. Two execution options:

1. Subagent-Driven (recommended) - I dispatch a fresh subagent per task, review between tasks, fast iteration  
2. Inline Execution - Execute tasks in this session using executing-plans, batch execution with checkpoints

Proceeding with Inline Execution now.
