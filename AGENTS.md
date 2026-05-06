# Auditex Agent Notes

## Canon docs

- `README.md` for repo overview.
- `RUNBOOK.md` for setup, operator flows, and tenant bootstrap usage.
- `docs/OUTPUT_CONTRACT.md` for bundle contract rules.
- `docs/RELEASE_CHECKLIST.md` for ship checks.
- `docs/provenance/provenance.md` and `THIRD_PARTY_NOTICES.md` for provenance and legal context.

Deleted plan, status, and duplicate AI docs are not part of the working canon.

## Commands

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
make test
make lint
auditex doctor
auditex guided-run
auditex-mcp
make contract-smoke
```

## Repo rules

- Core audit engine lives in `src/azure_tenant_audit/`.
- Product wrapper CLI and MCP surface live in `src/auditex/`.
- Keep `configs/`, `profiles/`, and `schemas/` aligned with code and tests.
- Treat `skills/` and `agent/` as shipped operator/runtime content, not scratch notes.
- Treat `tenant-bootstrap/` as a portable helper kit; keep it aligned with the root runtime instead of forking behavior into separate docs.
- Do not hand-edit generated outputs, tenant evidence bundles, or anything under local secrets/output folders.

## Editing guidance

- Use Python 3.11+ and match nearby style.
- Keep collector and adapter changes narrow by service or concern.
- Add or update focused pytest coverage in `tests/` when behavior changes.
- Keep raw tenant evidence, tokens, and secrets out of git.

## Telemetry

- Do not add Sentry or external crash telemetry. Keep diagnostics local unless a repo runbook says otherwise.
