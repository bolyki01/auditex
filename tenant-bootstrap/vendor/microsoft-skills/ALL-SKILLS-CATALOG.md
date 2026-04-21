# Microsoft Agent Skills Catalog

Source: curated vendored subset from `microsoft/skills`.

Total retained skills: 11

Use this catalog to select the smallest relevant retained skill. The product source package intentionally does not carry the full upstream repository.

| Skill | Path | Description |
| --- | --- | --- |
| `agent-framework-azure-ai-py` | `plugins/azure-sdk-python/skills/agent-framework-azure-ai-py/SKILL.md` | Build Azure AI Foundry agents using the Microsoft Agent Framework Python SDK (agent-framework-azure-ai). Use when creating persistent agents with AzureAIAgentsProvider, using hosted tools (code interpreter, file search, web search), integra |
| `azure-identity-py` | `plugins/azure-sdk-python/skills/azure-identity-py/SKILL.md` | Azure Identity SDK for Python authentication with Microsoft Entra ID. Use for DefaultAzureCredential, managed identity, service principals, and token caching. Triggers: "azure-identity", "DefaultAzureCredential", "authentication", "managed  |
| `m365-agents-py` | `plugins/azure-sdk-python/skills/m365-agents-py/SKILL.md` | Microsoft 365 Agents SDK for Python. Build multichannel agents for Teams/M365/Copilot Studio with aiohttp hosting, AgentApplication routing, streaming responses, and MSAL-based auth. Triggers: "Microsoft 365 Agents SDK", "microsoft_agents", |
| `azure-compliance` | `plugins/azure-skills/skills/azure-compliance/SKILL.md` | Run Azure compliance and security audits with azqr plus Key Vault expiration checks. Covers best-practice assessment, resource review, policy/compliance validation, and security posture checks. WHEN: compliance scan, security audit, BEFORE  |
| `azure-diagnostics` | `plugins/azure-skills/skills/azure-diagnostics/SKILL.md` | Debug Azure production issues on Azure using AppLens, Azure Monitor, resource health, and safe triage. WHEN: debug production issues, troubleshoot container apps, troubleshoot functions, troubleshoot AKS, kubectl cannot connect, kube-system |
| `azure-rbac` | `plugins/azure-skills/skills/azure-rbac/SKILL.md` | Helps users find the right Azure RBAC role for an identity with least privilege access, then generate CLI commands and Bicep code to assign it. Also provides guidance on permissions required to grant roles. WHEN: bicep for role assignment,  |
| `entra-app-registration` | `plugins/azure-skills/skills/entra-app-registration/SKILL.md` | Guides Microsoft Entra ID app registration, OAuth 2.0 authentication, and MSAL integration. USE FOR: create app registration, register Azure AD app, configure OAuth, set up authentication, add API permissions, generate service principal, MS |
| `microsoft-foundry` | `plugins/azure-skills/skills/microsoft-foundry/SKILL.md` | Deploy, evaluate, and manage Foundry agents end-to-end: Docker build, ACR push, hosted/prompt agent create, container start, batch eval, prompt optimization, prompt optimizer workflows, agent.yaml, dataset curation from traces. USE FOR: dep |
| `entra-agent-id` | `skills/entra-agent-id/SKILL.md` | Microsoft Entra Agent ID (preview) for creating OAuth2-capable AI agent identities via Microsoft Graph beta API. Covers Agent Identity Blueprints, BlueprintPrincipals, Agent Identities, required permissions, sponsors, and Workload Identity  |
| `mcp-builder` | `skills/mcp-builder/SKILL.md` | Guide for creating high-quality MCP (Model Context Protocol) servers that enable LLMs to interact with external services through well-designed tools. Use when building MCP servers to integrate external APIs or services, whether in Python (F |
| `microsoft-docs` | `skills/microsoft-docs/SKILL.md` | Understand Microsoft technologies by querying official documentation. Use whenever the user asks how something works, wants tutorials, needs configuration options, limits, quotas, or best practices for any Microsoft technology (Azure, .NET, |
