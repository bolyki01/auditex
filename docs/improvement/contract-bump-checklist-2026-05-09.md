# Contract version bump checklist

Bumping `CONTRACT_VERSION` is rare and load-bearing — every artifact in
the bundle inherits it, downstream tools (SARIF / OSCAL exporters,
`auditex gate`, the MCP `auditex_contract_schema_manifest` tool) parse
it, and stale references silently break consumers.

This document is the **complete** list of sites to update for a future
bump. Audited 2026-05-09 against `CONTRACT_VERSION = "2026-04-21"`.
Last C-phase changes (C1, C2, C3) introduced no new version-coupled
sites; the inventory below remains complete.

## When to bump

Bump when:

- adding/removing a required artifact in `ROOT_REQUIRED_ARTIFACTS`
  (`src/azure_tenant_audit/contracts.py:15-22`)
- adding/removing a required JSON field in `_REQUIRED_FIELDS`
  (`src/azure_tenant_audit/contracts.py:24-41`)
- changing the shape of a normalized record-section (key columns)
- adding/removing tables in `_SCHEMA`
  (`src/azure_tenant_audit/evidence_db.py:12-34`)
- changing `evidence_refs` shape (`_EVIDENCE_REF_REQUIRED`)
- changing `framework_mappings` taxonomy in `_KNOWN_FRAMEWORK_KEYS`

Do NOT bump for:

- additive collectors / new rule_ids / new findings (these are covered
  by the per-rule_id catalog tests and don't break consumers)
- non-breaking field additions inside existing artifacts
- internal helper refactors that preserve artifact bytes

## Bump checklist

### Source

| File                                              | Site                                                                      | Action                       |
| ------------------------------------------------- | ------------------------------------------------------------------------- | ---------------------------- |
| `src/azure_tenant_audit/contracts.py`             | `CONTRACT_VERSION = "..."` (line 13)                                      | Update string                |
| `src/azure_tenant_audit/output.py`                | `RUN_MANIFEST_SCHEMA_VERSION` (line 13), `SUMMARY_SCHEMA_VERSION` (l. 14) | Update both                  |
| `src/azure_tenant_audit/ai_context.py`            | `"schema_version": "..."` literal in `build_ai_context` (~line 91)         | Update string                |
| `src/azure_tenant_audit/findings.py`              | `"schema_version": "..."` in report-pack builder (~line 1395)             | Update string                |

### JSON schemas

Every schema in `schemas/` carries a `schema_version` constant or `$id`
prefix derived from the contract version. Audit and update:

| File                                  | Notes                                            |
| ------------------------------------- | ------------------------------------------------ |
| `schemas/ai_context.schema.json`      | Field-level `schema_version` enum / `const`      |
| `schemas/report_pack.schema.json`     | Same                                             |
| `schemas/run_manifest.schema.json`    | Same — manifest's `schema_version` and `schema_contract_version` |
| `schemas/summary.schema.json`         | Same                                             |
| `schemas/validation.schema.json`      | `contract_version` const                         |
| `schemas/blocker.schema.json`         | Confirm — currently version-coupled?             |
| `schemas/blockers.schema.json`        | Confirm                                          |
| `schemas/capability_matrix.schema.json`| Confirm                                         |
| `schemas/collector_result.schema.json`| Confirm                                          |
| `schemas/finding.schema.json`         | Confirm                                          |

Run `grep -l '2026-04-21' schemas/` after the constant bump and
update each match.

### Tests (hardcoded version literals)

Search-and-replace these test fixtures every bump:

| File                                  | Sites                                            |
| ------------------------------------- | ------------------------------------------------ |
| `tests/support.py`                    | line 106 — `"created_utc"` literal (test fixture only; date, not version, but coupled in some assertions) |
| `tests/test_contract.py`              | lines 34, 37 — manifest + summary `schema_version` |
| `tests/test_output.py`                | line 51 — manifest `schema_version`              |
| `tests/test_auditex_product.py`       | line 128 — manifest `contract_version`           |
| `tests/test_sarif_oscal_exports.py`   | lines 55, 146 — summary + manifest                |

### Docs

| File                          | Action                                            |
| ----------------------------- | ------------------------------------------------- |
| `docs/OUTPUT_CONTRACT.md`     | Update the leading "Contract version" line       |
| `docs/RELEASE_CHECKLIST.md`   | Confirm the contract-bump pre-flight section is current |
| `CLAUDE.md`                   | The two `2026-04-21` references in the project intro section |
| `README.md`                   | If it cites the contract version (verify)         |

### Sample bundle + smoke fixtures

| File                                          | Action                                |
| --------------------------------------------- | ------------------------------------- |
| `examples/sample_audit_bundle/sample_result.json` | If the sample has any pre-baked `schema_version` literals (currently it does NOT — it ships collector payloads only — confirm before bump) |
| `make sample` then `make contract-smoke`      | Run both and verify a clean exit       |
| `tenant-bootstrap/azure_tenant_audit/`        | Vendored copy of the runtime — confirm the contracts.py / output.py / ai_context.py / findings.py copies are kept in sync per AGENTS.md; if drifted, sync after the bump |

### MCP / tooling surfaces

| Component                                   | Action                                      |
| ------------------------------------------- | ------------------------------------------- |
| `src/auditex/mcp_registry.py`               | Confirm `auditex_contract_schema_manifest` returns the new version (uses `contract_schema_manifest` which reads `CONTRACT_VERSION`) — should be automatic |
| `src/auditex/exporters.py` (SARIF + OSCAL)  | Confirm the SARIF tool driver `version` and OSCAL `metadata.version` aren't coupled to the contract version (currently they are NOT — they use their own format-specific versions) |

### Final verification gates

After all the above:

1. `make lint`
2. `make test` (full pytest suite)
3. `make contract-smoke`
4. `pytest tests/test_architecture_modules.py::test_catalog_validates_registry_config_profiles`
5. `pytest tests/test_finding_templates_complete.py` (B1+B2 floor)
6. `pytest tests/test_normalize_coverage.py` (A7 coverage lock)
7. `pytest tests/test_finalize_idempotent.py` (C1 idempotency)
8. `pytest tests/test_evidence_db_migration.py` (C2 migration)
9. `pytest tests/test_validation_error_coverage.py` (C3 validators)
10. Generate one offline run via `make sample`, sha256 the `validation.json`,
    delete the run, regenerate, sha256 again — must match (idempotency
    regression introduced by C1 must hold under the new version).
11. Open a draft PR titled `contract: bump <old> → <new>` summarising what
    changed and which consumer SDKs / downstream auditors were notified.

## Notes for future you

- **`tests/support.py` line 106 is a date, not the contract version.** It
  fakes `created_utc` for fixture stability. Don't touch it during a bump.
- Searching `2026-04-21` across the repo (excluding `__pycache__`) should
  yield exactly the sites listed above. After the bump, the same grep on
  the new version should yield the same sites — any drift is a missed
  update.
- The catalog test (`test_catalog_validates_registry_config_profiles`)
  doesn't reference the version directly but indirectly enforces every
  collector has a config entry. Bumps that add required fields to
  `collector-definitions.json` need to update fixtures.
- `tenant-bootstrap/` is vendored, not symlinked. After a bump, the
  vendored copies of `contracts.py` / `output.py` / `ai_context.py` /
  `findings.py` (and any other version-bearing module) MUST be synced.
  AGENTS.md says no behavioural fork; the bump enforces this contract.
