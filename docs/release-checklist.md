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

## OSS / provenance gate

- run `./scripts/oss-taint-scan.sh`
- confirm `LICENSE` is present and proprietary
- confirm `THIRD_PARTY_NOTICES.md` matches retained vendored/dependency material
- confirm `docs/provenance/provenance.csv` has a row for every retained third-party influence or vendored component
- confirm `docs/taint/` remains private and is not included in public/customer collateral unless explicitly intended

## History gate

- release from a sanitized repository root, not from the old git history
- do not merge the sanitized tree into the old repository
- recreate only clean tags and releases
- verify old release archives, old tags, and old hosted caches are removed or access-controlled
