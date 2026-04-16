# Microsoft Agent Skills Vendor Manifest

Source:

- Site: https://microsoft.github.io/skills/
- Repository: https://github.com/microsoft/skills
- Vendored commit: `33b598366fd91350f032be9b385389ff14876dcc`
- License: MIT, copied to `tenant-bootstrap/vendor/microsoft-skills/LICENSE`
- Vendored on: 2026-04-16

## Layout

Full upstream copy:

- `upstream/`
- Contains every `SKILL.md` found in the cloned Microsoft repository at the vendored commit.
- Current count: 177 `SKILL.md` files.

Full local catalog:

- `ALL-SKILLS-CATALOG.md`
- Generated from all upstream `SKILL.md` frontmatter.
- Use this file to pick one relevant skill path before opening a full skill.

Recommended fast-path subset:

- `skills/`
- `plugins/azure-sdk-python/skills/`
- `plugins/azure-skills/skills/`
- This is the smaller curated copy for the tenant-auditor's most likely work.

## Why Keep A Recommended Subset

Microsoft's own guidance says to use skills selectively because loading all skills causes context rot: diluted attention, wasted tokens, and conflated patterns. The full upstream copy is available locally, but agents should start from `ALL-SKILLS-CATALOG.md` or the curated subset and load only the smallest relevant `SKILL.md`.

## Selected Skills

Core selected skills:

- `skills/microsoft-docs`
  - Use for Microsoft Learn lookup, current limits, configuration docs, and authoritative Microsoft references.
- `skills/mcp-builder`
  - Use when building a dedicated Microsoft tenant-auditor MCP server or local tool server.
- `skills/entra-agent-id`
  - Use when exploring Microsoft Entra Agent ID and dedicated OAuth-capable agent identities.

Python / agent selected skills:

- `plugins/azure-sdk-python/skills/azure-identity-py`
  - Use for Python authentication patterns with `DefaultAzureCredential`, `AzureCliCredential`, managed identity, service principals, and token acquisition.
- `plugins/azure-sdk-python/skills/m365-agents-py`
  - Use when building Microsoft 365 / Teams / Copilot Studio agents in Python.
- `plugins/azure-sdk-python/skills/agent-framework-azure-ai-py`
  - Use when building Azure AI Foundry persistent agents with tools, threads, streaming, and MCP integration.

Azure operations selected skills:

- `plugins/azure-skills/skills/entra-app-registration`
  - Use for app registrations, redirect URIs, API permissions, OAuth flows, and service principals.
- `plugins/azure-skills/skills/azure-rbac`
  - Use for Azure RBAC role assignments and least-privilege design.
- `plugins/azure-skills/skills/azure-diagnostics`
  - Use for Azure troubleshooting and diagnostics flows.
- `plugins/azure-skills/skills/azure-compliance`
  - Use for compliance and governance checks.
- `plugins/azure-skills/skills/microsoft-foundry`
  - Use when moving the tenant auditor toward Azure AI Foundry project/agent deployment.

## Installation Notes

Project-local portable copy:

- `tenant-bootstrap/vendor/microsoft-skills/`
- Full upstream skills: `tenant-bootstrap/vendor/microsoft-skills/upstream/`
- Full skill catalog: `tenant-bootstrap/vendor/microsoft-skills/ALL-SKILLS-CATALOG.md`

Codex home copy for future local sessions:

- `/home/bolyki/.codex/skills/microsoft-selected/`

Current Codex sessions may not reload the skill registry automatically. If a future session does not list these skills, read the project-local `SKILL.md` directly from the vendor path. The Codex home copy intentionally contains the selected subset only; the repo contains all upstream skills.

## Update Command

To refresh the vendored set:

```bash
rm -rf /tmp/microsoft-skills
git clone --depth 1 https://github.com/microsoft/skills.git /tmp/microsoft-skills
git -C /tmp/microsoft-skills rev-parse HEAD
```

Then:

1. Replace `tenant-bootstrap/vendor/microsoft-skills/upstream/` with the new upstream copy.
2. Refresh the selected subset if needed.
3. Regenerate `ALL-SKILLS-CATALOG.md`.
4. Update this manifest commit and counts.
