# Steal Backlog

## Now

- `cisagov/ScubaGear`: Policy waiver file -> Auditex findings and report policy layer. Add annotation, omission, expiration, and per-policy exclusion fields for accepted risk.
- `cisagov/ScubaGear`: Consolidated result envelope -> Auditex reports bundle. Emit one stable top-level result file plus fail-only action-plan export.
- `maester365/maester`: Rule-pack inventory -> Auditex rules namespace. Discover checks by path and tag and export a machine-readable inventory.
- `microsoft/EntraExporter`: Collector preset exports -> Auditex profile and preset planning. Add named export sets like config-only, identity-only, or full with include and exclude switches.
- `microsoft/EntraExporter`: Stable ordered snapshots -> Auditex normalized and diff outputs. Sort keys and flatten schema output so git diffs stay clean across runs.
- `ThomasKur/M365Documentation`: Friendly-name translation map -> Auditex normalize and ai_safe layers. Resolve GUIDs, policy IDs, and role IDs into stable human labels with missing-map warnings.
- `CompliantSec/M365SAT`: Finding result schema -> Auditex findings and reports. Standardize fields like title, expected value, returned value, risk, impact, remediation, and references.

## Next

- `cisagov/ScubaGear`: Mapped control registry -> Auditex finding metadata. Attach CIS, NIST, or ATT&CK mapping keys to findings without changing raw evidence.
- `maester365/maester`: Merged run compare model -> Auditex diffing and report compare. Load one or many run bundles and compare by tenant and execution time.
- `microsoft/EntraExporter`: Graph batch helper -> Auditex transport layer. Add 20-item batch chunking and nextLink handling for safe batched reads.
- `dirkjanm/ROADtools`: Offline evidence database -> Auditex snapshots and diff engine. Persist normalized records into a queryable local store for cross-run analysis.
- `dirkjanm/ROADtools`: Plugin export contract -> Auditex report and export adapters. Define plugin entrypoints with description, args, and main function for offline exports.
- `ThomasKur/M365Documentation`: Section registry -> Auditex report generation. Let reports select include and exclude sections by stable IDs.
- `ThomasKur/M365Documentation`: Format-split writers -> Auditex report renderers. Keep html, markdown, csv, and json writers isolated behind one report contract.
- `System-Admins/m365assessment`: Review template registry -> Auditex findings content. Store one template per finding ID with category, impact, and remediation text.
- `CompliantSec/M365SAT`: Inspector folder routing -> Auditex rule-pack loader. Route checks by product family, license tier, and audit level.

## Later

- `maester365/maester`: Notification sinks -> Auditex post-run hooks. Add optional Teams, mail, or Slack summary emitters after the run bundle is final.
- `dirkjanm/ROADtools`: Thin CLI shell -> Auditex product CLI. Keep command dispatch thin and move business logic into reusable modules.
- `System-Admins/m365assessment`: Overview-detail HTML split -> Auditex HTML reporting. Keep one overview table with links into detailed finding sections.
- `CompliantSec/M365SAT`: Operator mode flags -> Auditex guided-run and report UX. Expose local mode, skip login, skip checks, and report type flags in a controlled way.

## Avoid

- `ROADtools`: no roadtx or offensive token flows.
- `ScubaGear`: no GUI and no OPA runtime in Auditex core.
- `m365assessment`: no undocumented API dependency and no admin-only assumption.
- `M365Documentation`: no DOCX-heavy path in the critical audit flow.
