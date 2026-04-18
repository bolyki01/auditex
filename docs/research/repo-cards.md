# Repo Cards

## cisagov/ScubaGear

- Head: `f5d7edcaf3a6009b3d52c49f2664d71864a3c0a3`
- Stack: PowerShell + OPA/Rego + YAML
- License: CC0-1.0
- Best fit: Waiver model, control mapping, final result envelope, tri-format reports.
- Weak fit: Too baseline-specific and too PowerShell/OPA-heavy for Auditex core runtime.

Worth stealing:

- YAML risk acceptance with annotation, omission, and exclusion fields.
- Single final result envelope with action-plan style fail export.
- Control mapping from finding IDs to external frameworks.

Avoid:

- Do not port the GUI or the OPA runtime into Auditex core.
- Do not force baseline-only semantics onto evidence-first collectors.

Exact upstream paths:

- `PowerShell/ScubaGear/Modules/Orchestrator.psm1`
- `docs/execution/reports.md`
- `docs/configuration/configuration.md`
- `PowerShell/ScubaGear/Modules/ScubaConfigApp/ScubaConfigAppHelpers/ScubaConfigAppImportHelper.psm1`
- `PowerShell/ScubaGear/Sample-Config-Files/scuba_compliance.yaml`
- `docs/misc/tooloutputschema.md`
- `PowerShell/ScubaGear/Sample-Reports/ScubaResults_dfd70a15-3042-4bc9.json`
- `PowerShell/ScubaGear/Sample-Reports/BaselineReports.html`
- `Testing/Functional/Products/TestPlans`

Direct port slices:

- `now`: Policy waiver file -> Auditex findings and report policy layer. Add annotation, omission, expiration, and per-policy exclusion fields for accepted risk.
- `now`: Consolidated result envelope -> Auditex reports bundle. Emit one stable top-level result file plus fail-only action-plan export.
- `next`: Mapped control registry -> Auditex finding metadata. Attach CIS, NIST, or ATT&CK mapping keys to findings without changing raw evidence.

## maester365/maester

- Head: `d39cf580e29b1e4af8095f7544db34fdb866a707`
- Stack: PowerShell + Pester + React report UI
- License: MIT
- Best fit: Check-pack discovery, report merge flow, multi-view result UI, notifications.
- Weak fit: Test harness first, not collector runtime first.

Worth stealing:

- Test inventory and tag discovery can become Auditex rule-pack inventory.
- Merged result model supports multi-tenant and historical comparison cleanly.
- Report views reuse one result set in markdown, print, excel, and config modes.

Avoid:

- Do not turn Auditex into a Pester clone.
- Do not adopt React report UI before the canonical result schema is stable.

Exact upstream paths:

- `powershell/public/Get-MtTestInventory.ps1`
- `tests/maester-config.json`
- `powershell/public/core/Get-MtHtmlReport.ps1`
- `powershell/public/core/Import-MtMaesterResult.ps1`
- `powershell/public/core/Merge-MtMaesterResult.ps1`
- `powershell/public/Compare-MtTestResult.ps1`
- `report/src/pages/MarkdownPage.tsx`
- `report/src/pages/ExcelPage.tsx`
- `report/src/pages/PrintPage.tsx`
- `report/src/components/TestResultsTable.jsx`

Direct port slices:

- `now`: Rule-pack inventory -> Auditex rules namespace. Discover checks by path and tag and export a machine-readable inventory.
- `next`: Merged run compare model -> Auditex diffing and report compare. Load one or many run bundles and compare by tenant and execution time.
- `later`: Notification sinks -> Auditex post-run hooks. Add optional Teams, mail, or Slack summary emitters after the run bundle is final.

## microsoft/EntraExporter

- Head: `ce0d04cf096611183258d65a8e5aa487c55a1f5f`
- Stack: PowerShell module + Graph + JSON export
- License: MIT
- Best fit: Scoped export presets, stable ordered JSON, batch request helpers.
- Weak fit: Export-only. No real findings layer.

Worth stealing:

- Export types map well to Auditex collector presets.
- Ordered dictionaries make diffs stable and readable.
- Batch helpers can reduce request overhead on Graph-heavy surfaces.

Avoid:

- Do not adopt export-only framing as the product surface.

Exact upstream paths:

- `src/Export-Entra.ps1`
- `src/Get-EEFlattenedSchema.ps1`
- `src/Get-EERequiredScopes.ps1`
- `src/internal/ConvertTo-OrderedDictionary.ps1`
- `src/internal/New-GraphBatchRequest.ps1`
- `src/internal/Invoke-GraphBatchRequest.ps1`

Direct port slices:

- `now`: Collector preset exports -> Auditex profile and preset planning. Add named export sets like config-only, identity-only, or full with include and exclude switches.
- `now`: Stable ordered snapshots -> Auditex normalized and diff outputs. Sort keys and flatten schema output so git diffs stay clean across runs.
- `next`: Graph batch helper -> Auditex transport layer. Add 20-item batch chunking and nextLink handling for safe batched reads.

## dirkjanm/ROADtools

- Head: `e6ed3c10373f2a15d920bcaa82f2236a4a461b38`
- Stack: Python library + async gatherer + offline DB + plugin CLI
- License: MIT
- Best fit: Thin CLI, offline store, async gatherer, plugin exports.
- Weak fit: Too much offensive auth and token tradecraft outside Auditex scope.

Worth stealing:

- Core library plus thin CLI split matches Auditex direction well.
- Async gather and offline query plugins fit large-tenant evidence work.
- Generated metadata model hints at future schema automation.

Avoid:

- Do not import roadtx flows or offensive token exchange logic.
- Do not ship the Angular UI inside Auditex.

Exact upstream paths:

- `roadrecon/roadtools/roadrecon/main.py`
- `roadrecon/roadtools/roadrecon/gather.py`
- `roadrecon/roadtools/roadrecon/server.py`
- `roadrecon/roadtools/roadrecon/plugins/xlsexport.py`
- `roadrecon/roadtools/roadrecon/plugins/road2timeline.py`
- `roadlib/roadtools/roadlib/dbgen.py`
- `roadlib/roadtools/roadlib/metagen.py`
- `roadlib/roadtools/roadlib/metadef/database.py`

Direct port slices:

- `next`: Offline evidence database -> Auditex snapshots and diff engine. Persist normalized records into a queryable local store for cross-run analysis.
- `next`: Plugin export contract -> Auditex report and export adapters. Define plugin entrypoints with description, args, and main function for offline exports.
- `later`: Thin CLI shell -> Auditex product CLI. Keep command dispatch thin and move business logic into reusable modules.

## ThomasKur/M365Documentation

- Head: `13a9aa34ff6b8c295926c5ae1a8f2ad54727f143`
- Stack: PowerShell 7 + MSAL + multi-renderer documentation
- License: GPLv3+
- Best fit: Section registry, name translation, one-writer-per-format renderers, backup replay.
- Weak fit: Word-first docs product, not evidence-first audit runtime.

Worth stealing:

- Section selection maps well to Auditex report sections.
- Translation maps solve ugly GUID and ID output.
- Renderer-per-format split keeps report logic clean.

Avoid:

- Do not make DOCX or Word templates part of the critical path.

Exact upstream paths:

- `PSModule/M365Documentation/Functions/Connect-M365Doc.ps1`
- `PSModule/M365Documentation/Functions/Get-M365Doc.ps1`
- `PSModule/M365Documentation/Functions/Get-M365DocValidSection.ps1`
- `PSModule/M365Documentation/Functions/Optimize-M365Doc.ps1`
- `PSModule/M365Documentation/Functions/Write-M365DocHTML.ps1`
- `PSModule/M365Documentation/Functions/Write-M365DocMD.ps1`
- `PSModule/M365Documentation/Functions/Write-M365DocCsv.ps1`
- `PSModule/M365Documentation/Functions/Write-M365DocJson.ps1`
- `PSModule/M365Documentation/Data/LabelTranslation`

Direct port slices:

- `now`: Friendly-name translation map -> Auditex normalize and ai_safe layers. Resolve GUIDs, policy IDs, and role IDs into stable human labels with missing-map warnings.
- `next`: Section registry -> Auditex report generation. Let reports select include and exclude sections by stable IDs.
- `next`: Format-split writers -> Auditex report renderers. Keep html, markdown, csv, and json writers isolated behind one report contract.

## System-Admins/m365assessment

- Head: `7aa59a7d5277afe1b47f450cb55d5f89f06d32de`
- Stack: PowerShell module + HTML zip reports
- License: No obvious license
- Best fit: Operator flow, typed review templates, HTML overview-detail split.
- Weak fit: Requires broad admin rights and undocumented APIs.

Worth stealing:

- Install, connect, run, disconnect flow is simple and readable.
- Typed review templates fit finding authoring well.
- HTML overview and per-review drilldown split is useful for operator reports.

Avoid:

- Do not copy undocumented API dependencies.
- Do not require Global Administrator or user_impersonation-level behavior.

Exact upstream paths:

- `src/SystemAdmins.M365Assessment/public/Install-M365Dependency.ps1`
- `src/SystemAdmins.M365Assessment/public/Connect-M365Tenant.ps1`
- `src/SystemAdmins.M365Assessment/public/Invoke-M365Assessment.ps1`
- `src/SystemAdmins.M365Assessment/public/Disconnect-M365Tenant.ps1`
- `src/SystemAdmins.M365Assessment/private/helper/html/Get-HtmlReport.ps1`
- `src/SystemAdmins.M365Assessment/private/helper/html/Get-HtmlOverviewTable.ps1`
- `src/SystemAdmins.M365Assessment/private/helper/html/Get-HtmlReview.ps1`
- `src/SystemAdmins.M365Assessment/private/class/class.review.ps1`

Direct port slices:

- `next`: Review template registry -> Auditex findings content. Store one template per finding ID with category, impact, and remediation text.
- `later`: Overview-detail HTML split -> Auditex HTML reporting. Keep one overview table with links into detailed finding sections.

## CompliantSec/M365SAT

- Head: `a1fdec4a95571989b26103a2079fc5f35bccfd75`
- Stack: PowerShell + inspector folders + HTML/CSV reports
- License: MIT
- Best fit: Inspector folder contract, local-vs-remote mode, result schema, packaging.
- Weak fit: Product and commercial split may drift hard from repo state.

Worth stealing:

- Inspector folders by product, license, and level are easy to reason about.
- Local mode, skip login, and skip checks fit Auditex operator UX.
- Rich fixed result schema can tighten Auditex findings output.

Avoid:

- Do not depend on remote inspector zip fetches for core runtime.

Exact upstream paths:

- `M365SAT.psm1`
- `core/Connect-M365SAT.ps1`
- `core/Get-M365SATChecks.ps1`
- `core/Get-M365SATHTMLReport.ps1`
- `core/Get-M365SATCSVReport.ps1`
- `core/m365connectors`
- `inspectors`

Direct port slices:

- `now`: Finding result schema -> Auditex findings and reports. Standardize fields like title, expected value, returned value, risk, impact, remediation, and references.
- `next`: Inspector folder routing -> Auditex rule-pack loader. Route checks by product family, license tier, and audit level.
- `later`: Operator mode flags -> Auditex guided-run and report UX. Expose local mode, skip login, skip checks, and report type flags in a controlled way.
