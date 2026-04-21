# Clean-Room Remediation Record

Date: 2026-04-18

Scope: remove GPL/no-license source exposure from the distributable Auditex tree and document remaining permissive components.

## Completed actions

| Surface | Previous risk | Action |
| --- | --- | --- |
| `src/auditex/reporting.py` | Mapped to GPL/no-license report-renderer influence | Rewritten from Auditex report-pack contract. |
| `configs/report-sections.json` | Mapped to GPL section registry influence | Rewritten with Auditex-owned titles/descriptions. |
| `src/azure_tenant_audit/friendly_names.py` | Mapped to GPL friendly-name map influence | Rewritten as a generic deterministic label catalog. |
| `configs/finding-templates.json` | Mapped to no-license review-template influence | Rewritten with Auditex-owned finding language. |
| `src/azure_tenant_audit/findings.py` fallback templates | Same text surface as finding templates | Rewritten to match the owned registry language. |
| `docs/research/*` | Stored direct-port/competitor research records | Removed from the distributable tree. |
| `src/auditex/research.py` and CLI research command | Could recreate competitor mirrors and direct-port records | Removed from the product tree. |
| `LICENSE` | Missing proprietary product license | Added proprietary top-level license. |
| `THIRD_PARTY_NOTICES.md` | Missing consolidated notices | Added notices for retained/declared third-party materials. |
| `docs/provenance/provenance.csv` | Missing provenance sheet | Added file-by-file provenance/action sheet. |

## Release gate

Do not reintroduce source, generated templates, screenshots, report text, or documentation copied from GPL or no-license upstream projects. Permissive third-party material may be used only with the required notice files and a provenance row.

## Still needed

- Git history still contains old research and taint records.
- No external forensic similarity audit has been done.
- No external legal counsel sign-off has been done.
- Commercial release should use the provenance sheet and notices as part of release review.
