# Agent Onboarding Note

This folder provides everything needed for AI agent assisted tenant analysis:

- `agent/tenant-audit-skill.json` → machine-readable action map.
- `configs/tenant-audit.example.env` → credential template.
- `configs/collector-definitions.json` → collector and permission catalog.
- `examples/sample_audit_bundle/sample_result.json` → offline smoke fixture.
- `python3 -m azure_tenant_audit ...` → runtime execution.
  - For local runs without install: `PYTHONPATH=src python3 -m azure_tenant_audit ...`
  - For browser authentication: add `--interactive --browser-command firefox` and provide `--client-id`.
  - For no-app authentication: run `az login` then pass `--use-azure-cli-token`.

### Recommended operating sequence

1. Start from an environment file or secure secret store.
2. Run `tenant_audit.run_sample_audit` to verify command execution on this machine.
3. Run a narrow live collector set (identity/security).
4. Run full audit only when credentials and permission checks are clean.

### Output conventions

- Each run creates `<tenant>-<run-id>/`.
- `run-manifest.json` is the source of truth for which collectors ran and status.
- `summary.md` is the first file to read.
- `raw/<collector>.json` stores raw payload for deeper analysis.
- `audit-log.jsonl` stores every collector, command, and Graph event for audit trace.
