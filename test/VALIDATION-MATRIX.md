# Auditex Validation Matrix

## Review Principle

The reviewer should validate the system in layers:

1. static architecture review
2. focused test execution
3. CLI and MCP smoke testing
4. offline artifact contract review
5. delegated live-path review
6. export and response path review
7. scale and recovery review

## Static Review Checks

- verify `src/azure_tenant_audit/` is the canonical runtime
- verify `src/auditex/` is only wrapper/orchestration and not a second runtime
- verify collector registration and config definitions stay aligned
- verify profile defaults and supported planes stay aligned
- verify every collector failure path produces blocker-ready metadata
- verify response remains separate from the default audit plane
- verify docs do not over-claim implemented coverage

## Unit and Integration Test Commands

Minimum focused commands:

```bash
source .venv/bin/activate
pytest -q tests/test_auditex_product.py tests/test_auth_namespace.py
pytest -q tests/test_cli.py tests/test_config.py tests/test_output.py
pytest -q tests/test_normalize.py tests/test_conditional_access_normalization.py
pytest -q tests/test_security_collectors.py tests/test_security_defender_posture.py
pytest -q tests/test_purview_ediscovery_collectors.py
```

Recommended full suite:

```bash
source .venv/bin/activate
pytest -q
```

## CLI Smoke Checks

Offline:

```bash
source .venv/bin/activate
auditex --offline --tenant-name review-smoke --out outputs/offline-review
```

Probe:

```bash
source .venv/bin/activate
auditex probe live --tenant-name review-probe --tenant-id organizations --mode delegated --surface identity --use-azure-cli-token --out outputs/probes
```

Response dry-run:

```bash
source .venv/bin/activate
auditex response list-actions
auditex response run --tenant-name review-response --tenant-id organizations --action message_trace --target user@example.com --intent "review smoke" --out outputs/response
```

## MCP Checks

- verify tool list includes collectors, adapters, blockers, probes, and response actions
- verify MCP command builders generate correct CLI commands
- verify response tools do not bypass response gating

## Artifact Contract Checks

For each run type, verify:

- manifest exists
- summary exists
- audit log exists
- command log exists when commands are used
- normalized artifacts are produced where expected
- blockers are written when access/tooling is missing
- response bundles do not pollute default inventory runs

## Live Tenant Checks

Delegated review path:

- sign in with Global Reader or equivalent
- run profile `global-reader`
- verify partial coverage degrades cleanly
- verify blocked surfaces recommend least-privilege escalation

App-readonly path:

- run profile `app-readonly-full`
- verify Purview/eDiscovery inventory and export surfaces behave better than delegated-only

Response path:

- verify default dry-run behavior
- verify explicit `--execute` changes only the response run bundle
- verify lab guard works
- verify response-capable profile gate works

## Scale Checks

The reviewer should explicitly test or add tests for:

- large user count
- large group count
- large sign-in volume
- chunked output continuity
- checkpoint resume integrity
- export resume integrity
- memory behavior under long runs

## Required Reviewer Additions

The reviewer is expected to add more tests where confidence is weak.

Minimum expected additions:

- one large-tenant fixture or synthetic scale test
- one stronger export-path validation
- one stronger response-path validation
- one blocker-path regression test
