# Auditex Surface Map

This file records where taint was mapped and what was remediated.

## High-risk taint history

### `ThomasKur/M365Documentation`

Repo records say these port slices were intended:
- friendly-name translation map
- section registry
- format-split writers

These surfaces were remediated in the current tree:
- `src/azure_tenant_audit/friendly_names.py`
- `configs/report-sections.json`
- `src/auditex/reporting.py`

### `System-Admins/m365assessment`

Repo records say these port slices were intended:
- review template registry
- overview-detail HTML split

These surfaces were remediated in the current tree:
- `configs/finding-templates.json`
- `src/auditex/reporting.py`

## Lower-risk permissive influence history

### `cisagov/ScubaGear`

Recorded ideas:
- waiver file
- result envelope
- control mappings

Remediated or retained with provenance:
- `src/azure_tenant_audit/waivers.py`
- `configs/control-mappings.json`

### `maester365/maester`

Recorded ideas:
- rules inventory
- compare model
- notifications

Remediated or retained with provenance:
- `src/auditex/rules.py`

### `microsoft/EntraExporter`

Recorded ideas:
- collector presets
- stable ordered snapshots
- batch helper

Remediated or retained with provenance:
- `configs/collector-presets.json`
- `src/azure_tenant_audit/graph.py`

### `dirkjanm/ROADtools`

Recorded ideas:
- evidence DB
- exporter/plugin contract

Remediated or retained with provenance:
- `src/auditex/evidence_db.py`
- `src/auditex/exporters.py`

### `CompliantSec/M365SAT`

Recorded ideas:
- finding schema
- rule routing
- operator flags

Remediated or retained with provenance:
- `configs/finding-templates.json`
- `configs/rule-packs.json`

## Still needed

1. review historic git records separately from current tree state
2. get outside legal review before commercial release
3. get an outside similarity review if you want stronger proof
