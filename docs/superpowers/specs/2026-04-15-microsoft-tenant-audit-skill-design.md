# Microsoft Tenant Audit Skill – Design (2026-04-15)

## Goal
Create a portable folder that carries everything needed for Codex or another AI agent to run repeatable Microsoft tenant audits (Intune, Security, Defender, Exchange, Teams, and core Entra/Identity checks) with minimal per-tenant configuration.

The system must:

- run from this folder on macOS/Linux/Windows without repository-specific dependencies,
- use Microsoft Graph first and support optional command-based collectors for data not available in Graph,
- produce a local, versioned audit bundle (raw JSON + manifest + summary),
- provide offline/sample mode so onboarding and validation work without live credentials,
- include agent-facing instructions and an explicit skill manifest so AI callers can invoke standard commands quickly.

## Scope
In scope:

- CLI-based audit runner with selector for collector groups,
- token acquisition via app credentials (client credentials), plus explicit fallback to provided bearer token,
- standard collector set for:
  - Tenant/identity posture (`organization`, `domains`, `users`, `groups`, `applications`, directory roles),
  - Security posture (`conditionalAccess`, `alerts`, `secureScore`-adjacent checks),
  - Intune/device posture (`managedDevices`, compliance/policy basics),
  - Teams (`teams`, `team`/`channel` metadata),
  - Exchange readiness checks (Graph-first coverage + command-based stubs),
- structured output bundle with summary and machine-readable raw payloads,
- documentation for permissions, command matrix, and tenant handoff process.

Out of scope (initial version):

- full Exchange Online PowerShell implementation,
- vulnerability scan tooling outside Microsoft ecosystems,
- automatic remediation actions.

## Architecture
The toolkit will be a small Python package in `src/azure_tenant_audit`:

- `cli.py` parses options and orchestrates collectors,
- `graph.py` handles auth, pagination, and request retries,
- `collectors/` contains domain-specific collectors that return JSON payloads and metadata,
- `output.py` writes raw + summary artifacts in a deterministic folder layout,
- `agent/` holds a lightweight machine-readable manifest for AI callers.

`collectors` are intentionally independent and can be enabled/disabled individually.

## Data Flow
1. User executes CLI with tenant credentials/config.
2. CLI builds runtime config and resolves collector set.
3. Each collector calls Microsoft Graph (or declared command fallback) and returns:
   - collected data,
   - optional warning/error metadata for unsupported permissions,
   - execution timing.
4. Writer persists:
   - `run-manifest.json` (metadata, selected collectors, timestamps),
   - `raw/<collector>.json` per collector,
   - `summary.json` plus `summary.md`.
5. AI agent reads manifest first, then dives into raw/ or summary.

## Error Handling
- HTTP errors are captured at collector level and stored in output payload rather than aborting the full run.
- Missing permissions or unlicensed features are represented as structured warnings with remediation hints (e.g., “requires Intune license”).
- Optional timeout/retry behavior exists in Graph transport for transient rate limits.

## Security
- No secrets are ever written into output files.
- Token sources are environment variables or explicit CLI flags, not committed defaults.
- Command collectors for Exchange are opt-in and logged with their command name (no command output redaction assumptions in docs).

## Testing Approach
- Unit tests for:
  - collector selection and run wiring,
  - Graph response handling and pagination normalization,
  - sample bundle writer outputs.
- Offline sample mode tested in CI/locally by loading fixture data to validate formatting and CLI behavior without live credentials.

## Agent Integration
- `agent/tenant-audit-skill.json` provides:
  - named actions (e.g., `run_full_audit`, `run_security_scan`, `summarize_last_run`),
  - required arguments,
  - standardized interpretation of outputs.
- This enables Codex or other model agents to call consistent routines without rediscovering command syntax each time.

## Risks
- Some Exchange findings require Exchange Online-specific commands not available via Graph.
  - Mitigation: explicit command-based collectors that can be enabled when tooling is present.
- Permission creep/rate limits in large tenants.
  - Mitigation: collector-by-collector failure isolation and short retry windows.
- No licensed services in a tenant.
  - Mitigation: sample/offline mode and graceful “not available” collector outputs.

## Success Criteria
- With synthetic/sample data, the toolkit runs and emits a fully formed bundle.
- In a live tenant, one command can produce identity/security/intune/teams outputs into a local audit folder.
- Agents can execute repeatable workflows using the manifest without ad-hoc command discovery.
