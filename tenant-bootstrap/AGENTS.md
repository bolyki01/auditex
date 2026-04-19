# Tenant Bootstrap Agent Instructions

This folder is a Microsoft tenant-auditor and tenant-population toolkit.

## Local Microsoft Skills

Microsoft Agent Skills are vendored under:

- `vendor/microsoft-skills/`

Read the digest first:

- `docs/MICROSOFT-AGENT-SKILLS-DIGEST.md`

Retained skill catalog:

- `vendor/microsoft-skills/ALL-SKILLS-CATALOG.md`

Use local skills selectively:

- Microsoft docs/current service behavior: `vendor/microsoft-skills/skills/microsoft-docs/SKILL.md`
- Entra app registrations/OAuth/Graph permissions: `vendor/microsoft-skills/plugins/azure-skills/skills/entra-app-registration/SKILL.md`
- Python Azure authentication: `vendor/microsoft-skills/plugins/azure-sdk-python/skills/azure-identity-py/SKILL.md`
- Agent identities: `vendor/microsoft-skills/skills/entra-agent-id/SKILL.md`
- MCP server work: `vendor/microsoft-skills/skills/mcp-builder/SKILL.md`
- Microsoft 365/Foundry agent packaging: `vendor/microsoft-skills/plugins/azure-sdk-python/skills/m365-agents-py/SKILL.md`, `vendor/microsoft-skills/plugins/azure-sdk-python/skills/agent-framework-azure-ai-py/SKILL.md`, `vendor/microsoft-skills/plugins/azure-skills/skills/microsoft-foundry/SKILL.md`

Do not load all vendored skills at once. Pick the smallest relevant set.

If no curated skill matches, search `vendor/microsoft-skills/ALL-SKILLS-CATALOG.md`; if it is not listed there, refresh the vendored subset outside the product tree before adding it.

## Tenant Audit Rules

- The agent runs the audit/population commands itself.
- Log every command and Graph/API call into the run artifacts.
- Never hide partial failures. Warnings must be captured with service name, endpoint, status code, and missing permission/scope when known.
- Keep break-glass accounts excluded from normal Conditional Access and normal productivity licensing unless the operator explicitly says otherwise.
- Do not remove or reassign existing user licenses unless explicitly requested.
- Prefer read-only audit first. Write/populate/remediate actions must be explicit, logged, and idempotent where possible.

## Current Toolkit Entry Points

- Full Azure CLI flow: `run-bootstrap-azurecli.sh`
- Max enterprise lab flow: `run-enterprise-lab-max.sh`
- Enterprise wrapper: `scripts/run-enterprise-audit.sh`
- Identity seed: `scripts/identity_seed_az.py`
- Workload seed: `scripts/seed-workload-az.py`
- Verifier: `scripts/verify-population-az.py`
- Audit collector: `scripts/run-audit-collector.sh`
- Log inspectors: `scripts/inspect-bootstrap-log.sh`, `scripts/inspect-audit-logs.sh`

## Evidence

Keep live-run notes untracked and local.

Important generated artifacts:

- `runs/<run-name>/run-manifest.json`
- `runs/<run-name>/population-verification-manifest.json`
- `runs/<run-name>-identity/identity-seed-az-manifest.json`
- `runs/<run-name>-workload/workload-seed-az-manifest.json`
- `runs/<run-name>-workload/license-readiness-manifest.json`
- `runs/<run-name>-workload/cloudpc-readiness-manifest.json`
- `runs/<run-name>-workload/enterprise-policy-artifact-plan.json`
- `runs/<run-name>-workload/enterprise-scenario-plan.json`
- `audit-output/<run-name>-evidence/**`

For owned lab tenants that should look like a large enterprise, use
`config.enterprise-lab-max.json` and `docs/ENTERPRISE-LAB-MAX-POPULATION.md`.
Run dry-run first. Live runs may create hundreds of groups and users.
