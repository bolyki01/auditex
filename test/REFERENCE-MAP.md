# Auditex Reference Map

## Primary Product Docs

- `README.md`
- `docs/specs/2026-04-16-auditex-product-spec.md`
- `docs/audit-runbook.md`
- `docs/superpowers/specs/2026-04-17-enterprise-audit-architecture-design.md`
- `docs/superpowers/plans/2026-04-17-enterprise-audit-backlog-plan.md`
- `docs/superpowers/plans/2026-04-17-enterprise-audit-status.md`

## Runtime Entry Points

- `src/azure_tenant_audit/cli.py`
- `src/auditex/cli.py`
- `src/auditex/mcp_server.py`
- `src/azure_tenant_audit/response.py`
- `src/azure_tenant_audit/probe.py`

## Core Runtime Modules

- `src/azure_tenant_audit/config.py`
- `src/azure_tenant_audit/graph.py`
- `src/azure_tenant_audit/output.py`
- `src/azure_tenant_audit/normalize.py`
- `src/azure_tenant_audit/findings.py`
- `src/azure_tenant_audit/profiles.py`

## Collector Layer

- `src/azure_tenant_audit/collectors/__init__.py`
- `src/azure_tenant_audit/collectors/base.py`
- `src/azure_tenant_audit/collectors/identity.py`
- `src/azure_tenant_audit/collectors/security.py`
- `src/azure_tenant_audit/collectors/conditional_access.py`
- `src/azure_tenant_audit/collectors/defender.py`
- `src/azure_tenant_audit/collectors/auth_methods.py`
- `src/azure_tenant_audit/collectors/intune.py`
- `src/azure_tenant_audit/collectors/sharepoint.py`
- `src/azure_tenant_audit/collectors/teams.py`
- `src/azure_tenant_audit/collectors/exchange.py`
- `src/azure_tenant_audit/collectors/purview.py`
- `src/azure_tenant_audit/collectors/ediscovery.py`

## Adapter Layer

- `src/azure_tenant_audit/adapters/__init__.py`
- `src/azure_tenant_audit/adapters/base.py`
- `src/azure_tenant_audit/adapters/m365_cli.py`
- `src/azure_tenant_audit/adapters/powershell_graph.py`
- `src/azure_tenant_audit/adapters/m365dsc.py`

## Config and Schemas

- `configs/collector-definitions.json`
- `configs/collector-permissions.json`
- `schemas/`

## High-Value Tests

- `tests/test_auditex_product.py`
- `tests/test_auth_namespace.py`
- `tests/test_cli.py`
- `tests/test_config.py`
- `tests/test_output.py`
- `tests/test_normalize.py`
- `tests/test_conditional_access_normalization.py`
- `tests/test_security_collectors.py`
- `tests/test_security_defender_posture.py`
- `tests/test_purview_ediscovery_collectors.py`

## Secondary Context

- `tenant-bootstrap/`
- `profiles/`
- `skills/`

Use these for context, not as the main source of truth for current runtime behavior.
