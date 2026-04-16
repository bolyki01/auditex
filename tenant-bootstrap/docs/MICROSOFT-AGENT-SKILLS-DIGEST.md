# Microsoft Agent Skills Digest For Tenant Auditor

This digest converts the Microsoft Agent Skills repository into local operating guidance for this tenant-auditor folder.

Sources:

- https://microsoft.github.io/skills/
- https://github.com/microsoft/skills
- Full upstream copy: `tenant-bootstrap/vendor/microsoft-skills/upstream/`
- Full local catalog: `tenant-bootstrap/vendor/microsoft-skills/ALL-SKILLS-CATALOG.md`
- Curated fast-path skills: `tenant-bootstrap/vendor/microsoft-skills/`

## Core Takeaways

Microsoft Agent Skills are small, task-specific instruction packs for coding agents. They are intended to give agents current SDK/service patterns without loading a whole documentation universe into every prompt.

The important rule from Microsoft's repository is selective use. Do not load every skill. Pick the smallest skill set that matches the current task.

The repo now contains all upstream Microsoft skills, but the recommended tenant-auditor subset supports four workstreams:

- Microsoft documentation lookup.
- Entra app registration, Graph permissions, OAuth, and Azure identity.
- MCP server construction for repeatable tenant audit tools.
- Microsoft 365 / Foundry agent packaging if we later turn the auditor into a hosted agent.

## How Codex Should Use These Skills Here

When working in this folder:

1. Prefer local tenant-auditor scripts first.
2. Search `tenant-bootstrap/vendor/microsoft-skills/ALL-SKILLS-CATALOG.md` for the current task.
3. Open exactly one or a small number of relevant `SKILL.md` files.
4. If the task is about current Microsoft product behavior, consult `microsoft-docs`.
5. If the task is about authentication, app registrations, Graph permissions, service principals, or OAuth, consult `entra-app-registration` and `azure-identity-py`.
6. If the task is about a dedicated agent identity, consult `entra-agent-id`.
7. If the task is about making a local or hosted tool server for tenant auditing, consult `mcp-builder`.
8. If the task is about publishing a Microsoft 365 or Foundry agent experience, consult `m365-agents-py`, `agent-framework-azure-ai-py`, and `microsoft-foundry`.
9. If the task is about Azure RBAC/compliance/diagnostics around the tenant, consult `azure-rbac`, `azure-compliance`, or `azure-diagnostics`.

## Tenant Auditor Mapping

### Microsoft Docs

Use for:

- Confirming current Graph endpoints and permissions.
- Verifying Exchange, Defender, Intune, Entra, Teams, SharePoint, Windows 365 behavior.
- Checking current limitations before changing audit logic.

Local skill:

- `tenant-bootstrap/vendor/microsoft-skills/skills/microsoft-docs/SKILL.md`

### Entra App Registration

Use for:

- Creating the audit app registration.
- Adding Graph API permissions.
- Understanding delegated vs application permissions.
- Building admin-consent flows.
- Fixing redirect URI problems like `AADSTS500113`.

Local skill:

- `tenant-bootstrap/vendor/microsoft-skills/plugins/azure-skills/skills/entra-app-registration/SKILL.md`

### Azure Identity For Python

Use for:

- Replacing ad hoc Azure CLI token acquisition with Azure SDK credential patterns.
- Designing local-dev vs production credential chains.
- Managed identity and service principal authentication.
- Token provider construction.

Local skill:

- `tenant-bootstrap/vendor/microsoft-skills/plugins/azure-sdk-python/skills/azure-identity-py/SKILL.md`

Important local decision:

- The current auditor deliberately supports Azure CLI login because the operator flow is interactive tenant access.
- Future app-based audit mode should move toward certificate/service-principal or managed identity and record exactly which permissions are consented.

### Entra Agent ID

Use for:

- Dedicated OAuth-capable agent identities.
- Agent Identity Blueprint and BlueprintPrincipal exploration.
- Separating agent identity from human admin identity.

Local skill:

- `tenant-bootstrap/vendor/microsoft-skills/skills/entra-agent-id/SKILL.md`

Important caution:

- The skill says Agent Identity endpoints are `/beta`.
- It also says Azure CLI tokens containing `Directory.AccessAsUser.All` can be rejected by Agent Identity APIs, so use a dedicated app registration/client credentials or explicit delegated scopes where required.

### MCP Builder

Use for:

- Turning this auditor into a proper MCP server.
- Designing tool schemas for tenant collection, policy export, evidence replay, and remediation.
- Tool naming, pagination, error handling, response schemas, and read-only/destructive annotations.

Local skill:

- `tenant-bootstrap/vendor/microsoft-skills/skills/mcp-builder/SKILL.md`

Tenant-auditor MCP candidate tools:

- `tenant_get_summary`
- `tenant_export_identity`
- `tenant_export_groups`
- `tenant_export_conditional_access`
- `tenant_export_intune`
- `tenant_export_exchange`
- `tenant_export_teams`
- `tenant_export_sharepoint`
- `tenant_export_windows365`
- `tenant_collect_evidence_bundle`
- `tenant_list_required_permissions`
- `tenant_check_graph_scope`
- `tenant_replay_command_log`

MCP safety model:

- Export/list tools should be read-only.
- Populate/remediate tools should be explicit, idempotent where possible, and require clear operator intent.
- Every tool must log command name, arguments, timestamp, caller mode, result, and artifact path.

### Microsoft 365 Agents / Foundry

Use for:

- Packaging the auditor as a Microsoft 365 / Teams agent.
- Hosted Foundry agent with persistent threads and tool orchestration.
- MCP integration with hosted agents.

Local skills:

- `tenant-bootstrap/vendor/microsoft-skills/plugins/azure-sdk-python/skills/m365-agents-py/SKILL.md`
- `tenant-bootstrap/vendor/microsoft-skills/plugins/azure-sdk-python/skills/agent-framework-azure-ai-py/SKILL.md`
- `tenant-bootstrap/vendor/microsoft-skills/plugins/azure-skills/skills/microsoft-foundry/SKILL.md`

Practical sequence:

1. Keep the CLI auditor solid first.
2. Build a local MCP server around the proven collectors.
3. Add app/certificate auth and permission manifests.
4. Only then wrap it in a hosted M365/Foundry agent.

## Full Upstream Copy

All upstream Microsoft skills are available under:

- `tenant-bootstrap/vendor/microsoft-skills/upstream/`

Use:

- `tenant-bootstrap/vendor/microsoft-skills/ALL-SKILLS-CATALOG.md`

to find the right path. Do not recursively read the full upstream tree into context.

## Operational Rule For Future Agents

Before using online docs, check these local files:

- `tenant-bootstrap/docs/MICROSOFT-AGENT-SKILLS-DIGEST.md`
- `tenant-bootstrap/vendor/microsoft-skills/MANIFEST.md`
- `tenant-bootstrap/vendor/microsoft-skills/ALL-SKILLS-CATALOG.md`
- the relevant local `SKILL.md`

Browse online only when:

- Microsoft docs may have changed,
- the local skill says to verify current API behavior,
- a permission/scope error is ambiguous,
- or the task is high-impact enough that current source verification matters.
