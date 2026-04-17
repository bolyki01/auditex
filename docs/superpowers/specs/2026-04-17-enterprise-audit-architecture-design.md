# Enterprise Audit Architecture Design

## Goal

Turn Auditex from a small tenant collector into a scalable Microsoft 365 audit platform that can operate against tenants with `4,000-10,000` users, thousands of groups, thousands of devices, and large audit-log volumes without collapsing on memory, coverage, or operator trust.

The system must:

- run delegated-first with `Global Reader` or equivalent read roles,
- support optional customer-local read-only app escalation,
- preserve a full command and evidence trail,
- keep raw tenant evidence local,
- collect partial evidence without aborting on blocked surfaces,
- support high-volume export and later diffing,
- expose a stable Codex/MCP operating surface,
- separate read-only auditing from privileged response actions.

## Problem Statement

The current canonical runtime is structurally useful but not enterprise-ready.

Observed repo facts:

- canonical runtime has `5` collectors only:
  - `identity`
  - `security`
  - `intune`
  - `teams`
  - `exchange`
- `GraphClient.get_all()` materializes full result sets in memory
- `--top` acts as page size, not a global limit
- audit-log collection is not partitioned or checkpointed
- Teams inventory is partially sampled
- Intune and Exchange coverage are shallow
- Purview, eDiscovery, SharePoint, OneDrive, Defender depth, MFA/auth methods, and Entra governance are missing from the canonical runtime
- output model is still mostly:
  - `raw/`
  - `coverage`
  - `summary`
  - `diagnostics`

This is acceptable for homelab/bootstrap use and small delegated audits. It is not acceptable for Magrathean-scale enterprise audits.

## Non-Goals

- do not use one shared Magrathean multi-tenant app
- do not ship privileged response actions inside the default delegated audit path
- do not send raw tenant evidence to AI by default
- do not vendor large third-party repos directly into the canonical runtime without normalization boundaries
- do not claim “full tenant copy” when licensing, retention, or service-side blockers prevent it

## Operating Model

### Plane 1: Inventory

Read-only tenant posture collection.

Purpose:

- policies
- roles
- users
- groups
- devices
- workloads
- governance
- configuration

Default auth:

- delegated Azure CLI token reuse
- delegated supplied token
- optional customer-local read-only app

### Plane 2: Evidence Export

High-volume copy-out of logs and tenant evidence.

Purpose:

- sign-ins
- directory audits
- unified audit
- mailbox/search exports
- SharePoint/OneDrive evidence export
- Purview/eDiscovery export
- message trace / transport evidence

This plane must be resumable, checkpointed, and chunked to disk.

### Plane 3: Response

Privileged, explicitly separated operator actions.

Purpose:

- message purge / pullback
- search-and-purge workflows
- containment scripts
- targeted rollback helpers

This plane is not part of default audit runs. It requires explicit operator intent, higher roles, and stronger logging.

## Core Requirements

### Scale

- support `10,000+` user tenants without full in-memory materialization
- support `100,000+` sign-in and audit-log events per run via partitions and checkpoints
- support `10,000+` devices, groups, and group memberships through streaming writers
- support long-running exports with resumable checkpoints

### Coverage

Required P0 workload families:

- Entra core
- Conditional Access
- MFA and auth methods
- sign-ins
- directory audits
- unified audit export adapters
- Exchange posture
- SharePoint / OneDrive posture
- Defender posture
- Purview posture
- eDiscovery posture

Required P1 workload families:

- Teams depth
- Intune depth
- Windows 365
- app consent and workload identities
- PIM / access reviews / entitlement management
- drift / diff / change tracking

### Auditability

Every run must always produce:

- run manifest
- command log
- API request log
- blocker ledger
- permission ledger
- raw artifact index
- normalized artifact index
- findings
- report pack

### Privacy

- raw evidence stays local
- AI reads `ai_safe` artifacts by default
- token values and secrets are always masked
- deeper content access is explicit and logged as a data-handling event

## Target Architecture

## 1. Transport Layer

Replace list-materializing collection with a streaming transport.

Required behaviors:

- `iter_pages()`
- `iter_items()`
- explicit `page_size`
- explicit `result_limit`
- checkpoint support
- bounded concurrency
- Graph `$batch` support where safe
- retry policy for `429`, `5xx`, and transient network failures
- response metadata capture:
  - request URL
  - status
  - retry count
  - duration
  - page number
  - checkpoint cursor

Output behavior:

- write page/chunk artifacts incrementally to disk
- keep counters and small samples in memory only

## 2. Collector Layer

Collectors must become families, not one-off endpoints.

### 2.1 Entra Identity and Governance

- organization
- domains
- users
- groups
- service principals
- applications
- directory roles
- role assignments
- role eligibility and PIM-adjacent data where available
- access reviews
- entitlement management
- app consent posture
- security defaults state
- break-glass monitoring signals

### 2.2 Authentication and MFA

- authentication methods policy
- authentication method registrations
- per-user method posture where role/scopes allow
- registration campaign posture
- SSPR posture
- MFA requirement correlations against Conditional Access

### 2.3 Audit and Change

- sign-ins
- directory audits
- unified audit adapters
- change checkpoints
- delta-backed object snapshots for users/groups/devices where supported

### 2.4 Conditional Access

- policies
- named locations
- authentication strength references
- report-only vs enforced state
- exclusions
- break-glass coverage
- policy-to-target resolution

### 2.5 Intune and Devices

- managed devices
- compliance policies
- configuration policies
- settings catalog / security baselines where reachable
- app protection
- enrollment restrictions
- Autopilot
- device categories
- assignment targeting
- compliance and config state summaries

### 2.6 Windows 365

- Cloud PCs
- provisioning policies
- user settings
- assignment mappings
- readiness/licensing evidence
- linkage to Intune managed device evidence

### 2.7 Teams and Collaboration

- all Team-backed groups
- channels
- shared/private channel posture
- team ownership/membership
- meeting/calling policy posture
- app setup/policy posture where available

### 2.8 Exchange and Mail Security

- accepted domains
- mailbox posture
- mailbox audit settings
- transport rules
- forwarding posture
- anti-phish
- Safe Links
- Safe Attachments
- malware/spam filter posture
- quarantine posture
- organization config
- message trace adapters

### 2.9 SharePoint and OneDrive

- tenant settings
- site inventory
- sharing posture
- external sharing settings
- site sensitivity/retention references where visible
- OneDrive inventory and readiness posture

### 2.10 Defender

- alerts
- incidents
- secure score
- exposure/recommendations where APIs allow
- endpoint/mail/collab security posture references

### 2.11 Purview and eDiscovery

- DLP policies
- retention policies
- labels / label policies where accessible
- insider risk posture references
- cases
- holds
- searches
- review/export artifacts

## 3. Adapter Layer

Use external ecosystems as adapters, not as the product core.

### Approved upstreams

- `Microsoft365DSC`
  - use for deep configuration extraction and baseline comparison
- `CLI for Microsoft 365`
  - use for command fallback and surfaces not convenient in Graph
- `msgraph-sdk-powershell`
  - use for Graph gaps and bulk export helpers
- `DFIR-O365RC`
  - use as a pattern/reference for forensic evidence export
- `365Inspect`
  - use as a rules/reference set, not as canonical output
- `Microsoft-Extractor-Suite`
  - use as reference for export flows and acquisition patterns

### Adapter rules

- each upstream lives behind an `Auditex adapter`
- every adapter must declare:
  - tool dependency
  - auth mode
  - permission set
  - expected artifact types
  - normalization contract
  - failure signatures
- adapter outputs must normalize into canonical Auditex evidence schemas
- no raw third-party output becomes canonical without a normalizer

## 4. Evidence Model

Target run tree:

- `raw/`
- `chunks/`
- `normalized/`
- `ai_safe/`
- `blockers/`
- `findings/`
- `reports/`
- `snapshots/`
- `checkpoints/`
- `index/`
- `logs/`

Required artifact classes:

- raw page/chunk exports
- normalized object records
- relationship edges
- run/blocker metadata
- AI-safe summaries
- findings with severity and rationale
- comparison snapshots between runs

## 5. Diff and Drift Model

Required capabilities:

- compare runs by object type
- detect policy drift
- detect role and group membership drift
- detect device posture drift
- detect mailbox/security config drift
- produce machine-readable `changed|added|removed` outputs

This is required for repeat enterprise assessments and quarterly reviews.

## 6. MCP and Skills Surface

Current MCP is orchestration-only. Target MCP must expose:

- list profiles
- list collectors and required permissions
- run audit with explicit mode:
  - inventory
  - export
  - response
- summarize run
- diff two runs
- enumerate blockers
- list available adapters
- run targeted collector families

Skills must teach Codex:

- delegated-first auth
- app escalation boundaries
- how to interpret blockers
- when to stay in read-only inventory mode
- when response actions are allowed

## 7. Response Plane Design

This is the operator-controlled remediation surface.

Examples:

- mail pullback via Purview search-and-purge workflow
- message trace and post-delivery investigation
- targeted export of user audit history
- legal hold / search workflow scaffolding

Rules:

- separate CLI namespace from read-only audit
- explicit confirmation requirement
- separate permission profiles
- stronger logging with change intent and target scope

## External Reference Set

Reference repos and docs to evaluate and integrate:

- `https://github.com/microsoft/Microsoft365DSC`
- `https://github.com/pnp/cli-microsoft365`
- `https://github.com/pnp/cli-microsoft365-mcp-server`
- `https://github.com/microsoftgraph/msgraph-sdk-powershell`
- `https://github.com/ANSSI-FR/DFIR-O365RC`
- `https://github.com/soteria-security/365Inspect`
- `https://github.com/invictus-ir/Microsoft-Extractor-Suite`

Official Microsoft references:

- sign-ins:
  - `https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0`
- directory audits:
  - `https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0`
- authentication methods:
  - `https://learn.microsoft.com/en-us/graph/authenticationmethods-get-started`
- security API:
  - `https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0`
- SharePoint Graph:
  - `https://learn.microsoft.com/en-us/graph/api/resources/sharepoint?view=graph-rest-1.0`
- Intune Graph:
  - `https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-devicecompliancepolicy?view=graph-rest-1.0`
- Cloud PC:
  - `https://learn.microsoft.com/en-us/graph/api/resources/cloudpc?view=graph-rest-1.0`
- Purview:
  - `https://learn.microsoft.com/en-us/purview/audit-search`
  - `https://learn.microsoft.com/en-us/purview/edisc-features-components`

## Priority Backlog

### P0

- streaming Graph transport
- chunked/raw writer
- directory audits collector
- sign-in windowing and checkpoints
- MFA/auth methods collector
- SharePoint/OneDrive collectors
- Exchange posture adapters
- Defender posture collectors
- Purview/eDiscovery adapters
- normalized/blocker/findings/report directories

### P1

- Windows 365 canonical collector
- Intune depth collectors
- Teams depth collectors
- run diff engine
- unified audit export adapters
- adapter registry and test harness

### P2

- response plane CLI and guarded actions
- full comparison reporting
- long-horizon trend summaries

## Acceptance Criteria

- a delegated-first run on a large tenant completes without full-memory materialization
- large log exports are resumable and checkpointed
- blocked surfaces produce blocker artifacts instead of aborting the run
- the system can compare two runs and emit object-level drift
- raw evidence remains local and AI-safe artifacts are produced by default
- Exchange/Purview/response actions are adapter-backed and explicitly separated from default audit

## Immediate Next Step

Write and execute a first implementation tranche focused on:

1. streaming transport and chunked outputs
2. audit-log + MFA/auth methods collectors
3. normalized/blocker/findings/report scaffolding
4. adapter registry for Exchange/Purview-class tools
