# Auditex Output Contract

Contract version: `2026-04-21`.

Auditex treats completed run directories as product contracts, not incidental implementation output. `run`, `probe`, and `response` flows must finish through the shared bundle finalizer so the same required artifacts and validation semantics are applied.

## Required root artifacts

Every successful bundle must contain:

- `run-manifest.json`
- `summary.json`
- `reports/report-pack.json`
- `index/evidence.sqlite`
- `ai_context.json`
- `validation.json`

`validation.json` is built last and records the contract version, required artifact list, issue count, and issue details. The final `run-manifest.json` mirrors this with `schema_contract_version`, `contract_status`, and `contract_issue_count`.

## Evidence discipline

Findings must include `evidence_refs`. Each reference must identify at least `artifact_path`, `artifact_kind`, `collector`, and `record_key`. Bundle validation checks duplicate finding IDs, missing references, malformed references, and references pointing at missing artifacts.

Raw evidence remains local-only. `ai_safe/` artifacts are checked for sensitive key names and token-like values so redacted reasoning surfaces do not drift into raw credential or claim storage.

## Normalized and indexed surfaces

`normalized/*.json` payloads may expose `records`. Record rows need a stable machine key via `key`, `id`, `name`, `display_name`, `collector`, or `surface`.

`index/evidence.sqlite` is rebuilt during finalization. The required tables are:

- `run_meta`
- `section_stats`
- `normalized_records`

Report and compare code can use this database as the durable lookup surface instead of rewalking every JSON file.

## MCP contract surface

`auditex_summarize_run` returns the same contract status and evidence index path exposed by CLI output. `auditex_contract_schema_manifest` lists shipped schema files and the active contract version so MCP clients can detect drift before interpreting a bundle.
