# Audit Runbook

## 1) Validate tooling

```bash
python3 -m azure_tenant_audit --help
python3 -m azure_tenant_audit --offline --tenant-name test --sample examples/sample_audit_bundle/sample_result.json
```

## 2) Credentialed smoke (app-less via Azure CLI)

```bash
make login TENANT="<tenant-id-or-domain>"   # wrapper around az login + firefox
# or:
./scripts/tenant-audit-login <tenant-id-or-domain> [--browser <cmd>] [--reauth] [--m365] [--m365-app-id <app-id>]
# include --m365 if you plan to run exchange checks
python3 -m azure_tenant_audit --tenant-name "ACME" --use-azure-cli-token --tenant-id "organizations"
```

The run logs show:
- `auth.cli.token.requested`
- `auth.cli.token.acquired`
- `auth.session.context` with signed-in user and directory roles, when using Azure CLI or interactive login
- `run.started` (mode `azure_cli`)

## 3) Credentialed smoke (interactive in browser)

```bash
python3 -m azure_tenant_audit --interactive --tenant-name "ACME" --client-id "<app-id>" --tenant-id "organizations"
```

In interactive mode `tenant-id` defaults to `organizations` if omitted.

## 4) Credentialed smoke (app auth)

Set environment or pass inline:

```bash
export AZURE_TENANT_ID=<tenant-id>
export AZURE_CLIENT_ID=<app-id>
export AZURE_CLIENT_SECRET=<secret>
python3 -m azure_tenant_audit --tenant-name "ACME" --collectors identity,security --top 250
```

## 5) Full audit

```bash
python3 -m azure_tenant_audit --tenant-name "ACME" --collectors identity,security,intune,teams,exchange --include-exchange
```

The live runtime now writes chunked page exports for paged Graph collectors under `chunks/` and keeps smaller summary payloads in `raw/`.
Use `--page-size` to control request page size independently from `--top`, which is now the per-endpoint result limit.

Exchange command collection notes:

- The exchange collector now checks `m365 status --output json` and then `m365 tenant info get --output json` and falls back if needed.
- Mailbox count follows `m365 outlook report mailboxusagemailboxcount --period D30 --output json`; if unsupported, it falls back to `m365 outlook roomlist list --output json` and then `m365 exo mailbox list --output json`.
- If command tooling is unavailable, mailbox collection falls back to `Graph /users?filter=mail ne null` when possible.
- If command tooling has version drift, command-level failures are reported in `diagnostics.json`.

Or run guided CLI session flow:

```bash
./scripts/tenant-audit-full --tenant-id "ACME" --tenant-name "ACME" --include-exchange
```

## 5) Review

- Open `summary.md` for triage.
- Inspect `run-manifest.json` for status and command execution context.
- For deeper investigation, open `raw/<collector>.json`.
- For large paged collectors, inspect `chunks/<collector>/`.
- For full command/Graph evidence, open `audit-log.jsonl` (machine-readable event trail) and `audit-debug.log` (compact text view).
- Use `diagnostics.json` and `blockers/blockers.json` for immediate remediation guidance when collectors return partial/failed.
- Review `ai_safe/run_summary.json`, `normalized/collector-summary.json`, `findings/findings.json`, and `reports/report-pack.json` for the first-pass normalized/reporting artifacts.
- Exchange command collectors are opt-in and require `m365` CLI; if you see `command_not_found:m365`, install `m365` and rerun with `--include-exchange`.

## 6) Repeatability

Use the same `run-name` to align quarterly/daily baselines.

```bash
python3 -m azure_tenant_audit --tenant-name "ACME" --run-name "2026Q2" --collectors identity,security
```

## Troubleshooting common login failures

- `AADSTS500113: No reply address is registered for the application.`  
  Usually indicates delegated/browser login attempted with a non-browser app registration flow that has no redirect URI for this environment. Use Azure CLI token flow or provide a properly configured app registration.
- `AADSTS53003` during interactive app/token flow  
  Usually Conditional Access blocked token issuance. Use a policy-exempt account or a browser-suppressed Azure CLI auth flow if approved by the client.
- `AADSTS500113` when running exchange collection with m365 CLI  
  `m365` may require an app registration in this environment. Re-run login with `--m365-app-id <app-id>` or set `M365_CLI_APP_ID` / `M365_CLI_CLIENT_ID` before rerunning `tenant-audit-full --include-exchange`.
