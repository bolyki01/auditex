# Release Checklist

Use this before tagging a customer-ready Auditex release.

## Version

- bump `version` in `pyproject.toml`
- review schema versions in `schemas/`
- confirm README and runbook match actual CLI help

## Validation

- run `python -m pytest`
- run `auditex --help`
- run `auditex doctor --json`
- run `auditex guided-run --help`
- run `auditex --offline --tenant-name smoke --sample examples/sample_audit_bundle/sample_result.json`

## Live checks

- run one `Global Reader` probe or audit path
- run one deeper-profile path: `security-reader`, `app-readonly-full`, or `exchange-reader`
- confirm blocker output matches real permission/tooling limits
- confirm `compare`, `report render`, `export list`, and `notify send` work on a real run directory

## Artifacts

- verify `run-manifest.json`
- verify `findings/findings.json`
- verify `reports/report-pack.json`
- verify `index/evidence.sqlite`
- verify `blockers/blockers.json` when blockers exist

## Release note points

- supported auth/profile matrix
- current Exchange/tooling requirements
- known GR-only limits
- schema version changes
