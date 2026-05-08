# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Stack
Python 3.11+, setuptools (`pyproject.toml`), Makefile. Runtime deps are intentionally minimal: `requests`, `msal`, optional `mcp`.

## Common commands

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[mcp]"

make test                                  # pytest (uses scripts/select-python.sh)
make lint                                  # python -m compileall -q src tests (NOT ruff/mypy)
make contract-smoke                        # offline run + assert validation.json + manifest contract_status
make sample                                # offline sample audit run

pytest tests/test_contract.py              # run a single test file
pytest tests/test_contract.py::test_name   # run a single test
pytest -k <pattern>                        # run by name pattern

auditex doctor                             # local runtime/auth readiness
auditex setup [--mcp|--exchange|--pwsh]    # bootstrap optional adapters
make login TENANT=<tenant-id-or-domain>    # az login --allow-no-subscriptions
auditex gate <run-dir> --fail-on high      # CI gate: exits 2 if findings >= threshold
auditex gate-drift --baseline <run-a> --current <run-b> --fail-on high   # drift gate
auditex export run sarif <run-dir>         # SARIF 2.1.0 (GitHub Code Scanning compatible)
auditex export run oscal <run-dir>         # OSCAL Assessment Results
auditex notify send <run-dir> --sink {teams|slack|smtp|jira|github}      # findings-to-tickets
```

`pytest.ini` sets `pythonpath = src` so tests import the in-tree source directly.

## Two-package architecture

The repo ships two cooperating Python packages under `src/`:

- **`azure_tenant_audit/`** — the **core audit engine**. Owns auth, collectors, adapters, normalization, findings, diffing, the bundle finalizer, contracts, and the `azure-tenant-audit` CLI. This is where audit *behavior* lives.
- **`auditex/`** — the **product wrapper**. Owns the `auditex` CLI, guided operator flow, MCP server (`auditex-mcp`), reporting/exporters/notify surfaces, and saved-auth management. It re-uses `azure_tenant_audit` for the actual audit work — `auditex/cli.py` imports from `azure_tenant_audit.cli`, `.diffing`, `.probe`, `.response`.

When adding a feature, decide which layer it belongs to: collection/normalization/findings → `azure_tenant_audit/`; operator UX, guided flows, MCP tools, or post-run surfaces → `auditex/`.

## Collector + adapter pattern

`azure_tenant_audit/collectors/` contains one module per Microsoft 365 surface. Each collector:
1. Has an entry in `REGISTRY` (collectors/__init__.py)
2. Has a definition in `configs/collector-definitions.json` and `default_order`
3. Has permission hints in `configs/collector-permissions.json`
4. Optionally normalizes records into a section in `normalize.py`
5. Optionally emits findings via rules in `findings.py`

Capability-gated collectors (e.g. `power_platform`, `sentinel_xdr`, `defender_cloud_apps`, `copilot_governance`) use `collectors/_capability_gated.py` to translate missing-license / 403 / 404 into structured `service_not_available` or `insufficient_permissions` diagnostics rather than crashing the run. Add new license-dependent surfaces via this helper.

`azure_tenant_audit/adapters/` wraps non-Graph access paths: `m365_cli.py` (m365 CLI), `m365dsc.py`, `powershell_graph.py`. `capabilities.py` describes what each adapter can do; `base.py` is the common interface.

DNS-over-HTTPS lookups for the `dns_posture` collector live in `azure_tenant_audit/dns_lookup.py` (Cloudflare DoH by default; pluggable via `dns_resolver` in collector context for tests). Power Platform admin BAP API client lives in `azure_tenant_audit/power_platform.py`.

Permission/role expectations live in `configs/collector-permissions.json` and shipped profiles under `profiles/`. Profiles **shape expectations and diagnostics**, not actual permissions — they don't grant access.

## Output contract (load-bearing)

`run`, `probe`, and `response` flows all finish through the **shared bundle finalizer** in `azure_tenant_audit/finalize.py`. Contract version is set in `contracts.py` (currently `2026-04-21`).

Every successful bundle must contain:
- `run-manifest.json` (with `schema_contract_version`, `contract_status`, `contract_issue_count`)
- `summary.json`
- `reports/report-pack.json`
- `index/evidence.sqlite` (rebuilt on finalize; tables `run_meta`, `section_stats`, `normalized_records`)
- `ai_context.json`
- `validation.json` (built last; fails loudly on missing artifacts, broken `evidence_refs`, malformed normalized records, unsafe `ai_safe/` drift)

Findings must include `evidence_refs` with at least `artifact_path`, `artifact_kind`, `collector`, `record_key`. `make contract-smoke` is the canonical regression check — run it after touching collectors, normalize, findings, finalize, contracts, or evidence-DB code.

Full contract notes: [docs/OUTPUT_CONTRACT.md](docs/OUTPUT_CONTRACT.md).

## Findings, framework mappings, and exporters

- Finding **templates** (description / impact / remediation / control IDs) live in `configs/finding-templates.json`, keyed by `rule_id` (e.g. `dns_posture.dmarc_missing`, `app_credentials.secret_expired`, `mailbox_forwarding.external_inbox_rule`).
- **Compliance framework mappings** live in `configs/control-mappings.json`, keyed by `rule_id`. Frameworks: `cis_m365_v3`, `nist_800_53`, `iso_27001`, `soc2`, `nis2`, `dora`, `mitre_attack`. They surface in finding output under `framework_mappings`.
- Output **exporters** are registered in `auditex/exporters.py` (`BUILTIN_EXPORTERS`) and rendered in `auditex/reporting.py`. SARIF 2.1.0 and OSCAL Assessment Results are first-class formats alongside JSON/MD/CSV/HTML.
- **CI gates**: `auditex gate <run-dir> --fail-on <severity>` and `auditex gate-drift --baseline ... --current ...` exit non-zero when findings meet the severity threshold. Used by `.github/workflows/auditex-audit.yml`.
- **Findings-to-tickets** sinks (`jira`, `github`) live in `auditex/notify.py` alongside Teams/Slack/SMTP. Configure via env: `AUDITEX_JIRA_BASE_URL` + `AUDITEX_JIRA_PROJECT_KEY` + `AUDITEX_JIRA_EMAIL` + `AUDITEX_JIRA_API_TOKEN`, or `AUDITEX_GITHUB_TOKEN` + `AUDITEX_GITHUB_REPO`.

## MCP surface

`auditex-mcp` (entry point `auditex.mcp_server:main`) exposes contract, auth, run, probe, report, export, notify, diff, and guarded response tools. Tool registry is in `src/auditex/mcp_registry.py`. When adding a tool, register it there and keep the contract surface (`auditex_summarize_run`, `auditex_contract_schema_manifest`) in sync with the bundle the CLI produces.

## Shipped content discipline

Treat these as **shipped product content**, not scratch space — they are packaged via `pyproject.toml`'s `[tool.setuptools.data-files]`:

- `configs/` — collector definitions, permissions, presets, control mappings, finding templates, report sections, rule packs
- `profiles/` — operator profile notes
- `schemas/` — JSON output contracts
- `agent/` — agent runtime prompts/content
- `skills/` — operator/runtime skills (`app-readonly-escalation`, `auditex-operator`, `delegated-auth`, `evidence-pack`)
- `examples/sample_audit_bundle/` — offline sample data

Keep these aligned with code changes. If a collector's behavior changes, its config/permissions/schema entries usually move with it.

## tenant-bootstrap

`tenant-bootstrap/` is a portable helper kit for tenant onboarding/lab seeding. It must stay aligned with the root runtime — don't fork behavior into separate modules or docs. It vendors a copy of `azure_tenant_audit` plus shell wrappers (`run-bootstrap-azurecli.sh`, `run-enterprise-audit.sh`, `run-enterprise-lab-max.sh`).

## Repo rules (from AGENTS.md)

- **No telemetry.** Do not add Sentry or external crash telemetry — keep diagnostics local. The user's global Sentry MCP guidance does not override this for `auditex`.
- Raw tenant evidence, tokens, and secrets must never enter git. `.secrets/`, `.venv/`, and tenant exports stay local.
- Generated audit outputs are artifacts, not hand-edited source.
- Saved app credentials live only in `.secrets/m365-auth.env`.
- Canon docs: `README.md`, `RUNBOOK.md`, `docs/OUTPUT_CONTRACT.md`, `docs/RELEASE_CHECKLIST.md`, `docs/provenance/provenance.md`, `THIRD_PARTY_NOTICES.md`. Deleted plan/status/duplicate-AI docs are not part of the working canon.

## Response plane

Guarded response actions (`auditex response run`) are isolated from the audit plane. Default is dry-run; execution requires `--execute`, explicit `--intent`, a response-capable profile (only `exchange-reader` ships response-capable today), and lab-tenant gating. Treat any new response actions with the same guardrails.
