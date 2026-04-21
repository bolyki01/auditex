# Upstream Risk Matrix

This is a private record of source risk, not a statement that current product files remain copied.

| Upstream | License seen locally | Risk | Repo-recorded port intent | Current remediated or retained surfaces |
| --- | --- | --- | --- | --- |
| `ThomasKur/M365Documentation` | `GPLv3+` | High | Friendly-name translation map, section registry, format-split writers | `src/azure_tenant_audit/friendly_names.py`, `configs/report-sections.json`, `src/auditex/reporting.py` |
| `System-Admins/m365assessment` | No visible license file | High | Review template registry, overview-detail HTML split | `configs/finding-templates.json`, `src/auditex/reporting.py` |
| `cisagov/ScubaGear` | `CC0-1.0` | Notice/process | Waiver model, result envelope, control registry | `src/azure_tenant_audit/waivers.py`, `configs/control-mappings.json` |
| `maester365/maester` | `MIT` | Notice/process | Rule-pack inventory, merged compare, notification sinks | `src/auditex/rules.py` |
| `microsoft/EntraExporter` | `MIT` | Notice/process | Collector presets, ordered snapshots, Graph batch helper | `configs/collector-presets.json`, `src/azure_tenant_audit/graph.py` |
| `dirkjanm/ROADtools` | `MIT` | Notice/process | Offline evidence DB, plugin export contract, thin CLI | `src/auditex/evidence_db.py`, `src/auditex/exporters.py` |
| `CompliantSec/M365SAT` | `MIT` | Notice/process | Finding result schema, rule routing, operator mode flags | `configs/finding-templates.json`, `configs/rule-packs.json` |

## Reading rule

- `High` means bad fit for a proprietary ship target unless clean-room rewrite or permission exists.
- `Notice/process` means the license may allow commercial use, but copied code or text still needs proof and may need attribution.
- In the current tree, high-risk mapped surfaces were rewritten or removed.

## Sample compare note

Small spot checks done so far did **not** show obvious verbatim copy in these files:
- `src/auditex/reporting.py`
- `src/auditex/rules.py`
- `src/auditex/evidence_db.py`
- `src/azure_tenant_audit/friendly_names.py`
- `src/azure_tenant_audit/waivers.py`
- `configs/finding-templates.json`
- `configs/report-sections.json`

That lowers plagiarism confidence. It does **not** clear provenance taint.

## Still needed

- outside legal review for commercial release
- outside similarity review if stronger assurance is needed
- separate decision on whether old git history needs handling outside the product tree
