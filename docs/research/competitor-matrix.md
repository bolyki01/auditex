# Competitor Matrix

| Repo | Stack | Strongest steal | Weak fit | First port |
| --- | --- | --- | --- | --- |
| `cisagov/ScubaGear` | PowerShell + OPA/Rego + YAML | Waiver model, control mapping, final result envelope, tri-format reports. | Too baseline-specific and too PowerShell/OPA-heavy for Auditex core runtime. | Policy waiver file |
| `maester365/maester` | PowerShell + Pester + React report UI | Check-pack discovery, report merge flow, multi-view result UI, notifications. | Test harness first, not collector runtime first. | Rule-pack inventory |
| `microsoft/EntraExporter` | PowerShell module + Graph + JSON export | Scoped export presets, stable ordered JSON, batch request helpers. | Export-only. No real findings layer. | Collector preset exports |
| `dirkjanm/ROADtools` | Python library + async gatherer + offline DB + plugin CLI | Thin CLI, offline store, async gatherer, plugin exports. | Too much offensive auth and token tradecraft outside Auditex scope. | Offline evidence database |
| `ThomasKur/M365Documentation` | PowerShell 7 + MSAL + multi-renderer documentation | Section registry, name translation, one-writer-per-format renderers, backup replay. | Word-first docs product, not evidence-first audit runtime. | Friendly-name translation map |
| `System-Admins/m365assessment` | PowerShell module + HTML zip reports | Operator flow, typed review templates, HTML overview-detail split. | Requires broad admin rights and undocumented APIs. | Review template registry |
| `CompliantSec/M365SAT` | PowerShell + inspector folders + HTML/CSV reports | Inspector folder contract, local-vs-remote mode, result schema, packaging. | Product and commercial split may drift hard from repo state. | Finding result schema |
