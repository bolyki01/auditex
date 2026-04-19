# Audit Runbook

## 1) Validate tooling

Bootstrap a local dev shell first:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
auditex setup
```

If you need the MCP server:

```bash
auditex setup --mcp
```

If you need Exchange-backed or PowerShell-backed paths:

```bash
auditex setup --exchange
auditex setup --pwsh
```

Check readiness before a live run:

```bash
auditex doctor
```

JSON doctor output:

```bash
auditex doctor --json
```

Use the guided operator path when you want the full first-run flow:

```bash
auditex guided-run
```

This is the main flow now.

Pick one:

- `gr-audit`
  normal operator run with `Global Reader`
- `ga-setup-app`
  one-time `Global Admin` flow to create and save the Exchange app
- `app-audit`
  app-only run with saved app credentials

Common path:

```bash
auditex guided-run --flow gr-audit --include-exchange
# or repo-local:
./scripts/tenant-audit-flow --flow gr-audit --include-exchange
```

One-time GA setup:

```bash
auditex guided-run --flow ga-setup-app
```

Later app-only run:

```bash
auditex guided-run --flow app-audit
```

Saved local state goes into `.secrets/m365-auth.env`. After GA setup, normal GR runs can reuse the saved app id and only need login.

Supported guided flags:

- `--flow`
- `--auth-mode`
- `--client-id`
- `--client-secret`
- `--tenant-id`
- `--tenant-name`
- `--auditor-profile`
- `--out`
- `--run-name`
- `--top`
- `--page-size`
- `--browser-command`
- `--collectors`
- `--include-exchange`
- `--throttle-mode`
- `--include-blocked`
- `--with-mcp`
- `--non-interactive`
- `--local-mode`
- `--skip-login-check`
- `--skip-tool-check`
- `--report-format`
- `--probe-first` / `--no-probe-first`

App-guided flow:

```bash
auditex guided-run \
  --auth-mode app \
  --tenant-id <tenant-id-or-domain> \
  --tenant-name <label> \
  --client-id <app-id> \
  --client-secret <secret> \
  --auditor-profile app-readonly-full \
  --non-interactive
```

Install the operator tools separately:

- `az` for delegated sign-in and token reuse
- `m365` only if you plan to run Exchange or other CLI-backed collectors

Do not commit `.venv/` or `.secrets/`; they stay local and are already ignored.

```bash
auditex --help
auditex --offline --tenant-name test --sample examples/sample_audit_bundle/sample_result.json
```

If you also add `--include-exchange` in app mode, Auditex now uses `m365` secret auth with the same app id and secret.

## 2) Credentialed smoke (app-less via Azure CLI)

```bash
make login TENANT="<tenant-id-or-domain>"   # wrapper around az login + firefox
# or:
./scripts/tenant-audit-login <tenant-id-or-domain> [--browser <cmd>] [--reauth] [--m365] [--m365-app-id <app-id>]
# include --m365 if you plan to run exchange checks
python3 -m azure_tenant_audit --tenant-name "ACME" --use-azure-cli-token --tenant-id "organizations"
```

For a tenant-level reader account, the live flow is:

1. open the Microsoft sign-in page
2. pick the `global.reader@bolyki.eu` work account
3. confirm the Azure CLI trust prompt
4. accept the tenant-level account selection with no subscription change

The login helper now passes `--allow-no-subscriptions` so this path finishes without manual tenant/subscription selection.

Known login issues seen in this repo:

- `az login` without `--allow-no-subscriptions` stalls for tenant-level accounts.
- browser sign-in can leave the CLI waiting on the callback; device-code flow is the fallback.
- `m365` login is separate and only needed for Exchange-backed collectors.
- `python` is not guaranteed; use `python3`.

### Exchange app setup

If you want `m365` Exchange-backed collectors, you need a tenant-local Entra app for CLI for Microsoft 365.

Fast path with Global Administrator:

1. run `auditex guided-run --flow ga-setup-app`
2. sign in as GA when Safari opens
3. let the flow run `m365 setup`
4. save the created app id when the flow asks
5. optional: save the app secret too if you want later app-only runs
6. run `auditex guided-run --flow gr-audit --include-exchange`

Observed tenant result:

- app name: `CLI for M365`
- app id: `1a943a60-e4db-448c-a946-e825378e4883`

If you do not have GA:

1. ask tenant admin to create a single-tenant app registration
2. app should support delegated sign-in for CLI use
3. add mobile/desktop redirect URI:
   `https://login.microsoftonline.com/common/oauth2/nativeclient`
4. enable public client flows
5. give the app delegated permissions needed for the intended `m365` commands
6. grant admin consent where the chosen permissions require it
7. send back:
   - tenant id
   - application/client id
   - exact delegated permissions granted
8. operator stores the app id in `.secrets/m365-auth.env`
9. operator runs `auditex guided-run --flow gr-audit --include-exchange`

Copy/paste request for customer admin:

- use [docs/notes/exchange-app-request.md](/Users/bolyki/dev/source/auditex/docs/notes/exchange-app-request.md)

Reference:

- CLI for Microsoft 365 setup docs: https://pnp.github.io/cli-microsoft365/beta/cmd/setup/
- Own app registration docs: https://pnp.github.io/cli-microsoft365/beta/user-guide/using-own-identity/

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
App mode does not use `organizations`; pass the real tenant id or tenant domain.

## 3b) Credentialed smoke (customer-provided Graph token)

Save the delegated or app-issued Graph token locally, inspect it, and probe with that exact auth context:

```bash
auditex auth import-token --name customer-token --token "<bearer-token>" --tenant-id "<tenant-id>"
auditex auth inspect-token --token "<bearer-token>"
auditex auth capability --name customer-token --collectors identity,security,sharepoint
auditex probe live \
  --tenant-name "ACME" \
  --auth-context customer-token \
  --mode delegated \
  --surface identity,security \
  --out outputs/probes
```

Saved auth contexts stay local under `.secrets/` unless `AUDITEX_AUTH_CONTEXTS_PATH` points elsewhere.
That same saved context can be passed to `auditex probe live --auth-context <name>` and `auditex response run --auth-context <name>`.

Useful auth checks:

```bash
auditex auth status
auditex auth list
auditex auth use <name>
```

Local auth files default to `.secrets/m365-auth.env` and `.secrets/auditex-auth-contexts.json`.
Override those with `AUDITEX_LOCAL_AUTH_ENV` and `AUDITEX_AUTH_CONTEXTS_PATH` if you need a different local path.

## 4) Credentialed smoke (app auth)

Set environment or pass inline:

```bash
export AZURE_TENANT_ID=<tenant-id>
export AZURE_CLIENT_ID=<app-id>
export AZURE_CLIENT_SECRET=<secret>
python3 -m azure_tenant_audit --tenant-name "ACME" --collectors identity,security --top 250
```

Validated tenant path:

- existing tenant-local app can be reused
- add a client secret
- add admin-consented application permissions for the `app-readonly-full` profile
- current Graph app-role name for app consent depth is `AppRoleAssignment.ReadWrite.All`
- app probe and app full run were both validated in `BOLYKI`

Support matrix:

| Path | CLI profile | Sign-in | Exchange-assisted | Response |
| --- | --- | --- | --- | --- |
| Global Reader | `global-reader` | Delegated | Optional with `--include-exchange` | No |
| Security Reader | `security-reader` | Delegated | No | No |
| App read-only full | `app-readonly-full` | App-only or delegated token | Yes, with `m365` and `powershell_graph` adapters | No |
| Exchange-assisted | `exchange-reader` | Delegated | Yes, built in | Yes |

The live CLI defaults to `--auditor-profile global-reader`. Response planning defaults to `exchange-reader` and only accepts `exchange-reader`, `app-readonly-full`, `global-reader`, `security-reader`, or `auto`.

## 5) Full audit

```bash
python3 -m azure_tenant_audit --tenant-name "ACME" --collectors identity,security,intune,teams,exchange --include-exchange
```

For a profile-driven delegated run:

```bash
auditex \
  --tenant-name ACME \
  --tenant-id organizations \
  --use-azure-cli-token \
  --auditor-profile global-reader \
  --collectors identity,security,exchange,teams,intune \
  --probe-first \
  --throttle-mode safe \
  --out outputs/acme-audit
```

The live runtime now writes chunked page exports for paged Graph collectors under `chunks/` and keeps smaller summary payloads in `raw/`.
Use `--page-size` to control request page size independently from `--top`, which is now the per-endpoint result limit.
Use `--probe-first` to run a low-volume preflight and skip known-blocked collectors unless `--include-blocked` is set.
Use `--throttle-mode safe` or `--throttle-mode ultra-safe` to reduce burst behavior and back off more aggressively on `429` and repeated `403`.
Use `--resume-from` with a prior run directory to reuse completed checkpoint state. Resume skips preserve the prior collector checkpoint/summary status instead of downgrading it to `skipped`, and the checkpoint state file is written atomically to reduce interruption risk.
Saved auth contexts from `auditex auth import-token` can also be reused for full audits with `--auth-context <name>`.

Exchange command collection notes:

- The exchange collector now checks `m365 status --output json` and then `m365 tenant info get --output json` and falls back if needed.
- Mailbox count follows `m365 outlook report mailboxusagemailboxcount --period D30 --output json`; if unsupported, it falls back to `m365 outlook report mailboxusagedetail --period D30 --output json` and then `m365 outlook roomlist list --output json`.
- If command tooling is unavailable, mailbox collection falls back to `Graph /users?filter=mail ne null` when possible.
- If command tooling has version drift, command-level failures are reported in `diagnostics.json`.

Or run guided CLI session flow:

```bash
./scripts/tenant-audit-full --tenant-id "ACME" --tenant-name "ACME" --include-exchange
```

Raw CLI surface:

```bash
auditex compare --run-dir run-a --run-dir run-b
auditex report render <run-dir> --format md
auditex export list
auditex export run <exporter-name> <run-dir>
auditex notify send <run-dir> --sink teams
```

Supported flags:

- `auditex compare`: `--allow-cross-tenant`
- `auditex report render`: `--include-section`, `--exclude-section`, `--output`
- `auditex export run`: `--include-section`, `--exclude-section`, `--output`
- `auditex notify send`: `--execute`
- `auditex notify send --sink`: `teams`, `slack`, `smtp`

## 5) Review

- Keep a live obstacle log in `docs/audit-flow-log.md`.
- Open `summary.md` for triage.
- Inspect `run-manifest.json` for status and command execution context.
- For deeper investigation, open `run-manifest.json` first, then `raw/<collector>.json`.
- For large paged collectors, inspect `chunks/<collector>/`.
- For full command/Graph evidence, open `audit-log.jsonl` (machine-readable event trail) and `audit-debug.log` (compact text view).
- Use `diagnostics.json` and `blockers/blockers.json` for immediate remediation guidance when collectors return partial/failed.
- Review `ai_safe/run_summary.json`, `normalized/collector-summary.json`, `findings/findings.json`, and `reports/report-pack.json` for the first-pass normalized/reporting artifacts.
- Exchange command collectors are opt-in and require `m365` CLI; if you see `command_not_found:m365`, install `m365` and rerun with `--include-exchange`.
- `checkpoints/checkpoint-state.json` captures resumable progress for large tenants and interrupted runs.
- `blockers/` contains structured remediation guidance; use it to rerun with least-privilege scope changes.

## 6) Repeatability

Use the same `run-name` to align quarterly/daily baselines.

```bash
python3 -m azure_tenant_audit --tenant-name "ACME" --run-name "2026Q2" --collectors identity,security
```

## 7) Guarded response plane

The response plane is separate from the default audit run:

```bash
auditex response list-actions
auditex response run \
  --tenant-name "ACME" \
  --tenant-id "organizations" \
  --action message_trace \
  --target "user@contoso.com" \
  --intent "triage suspected delivery issue" \
  --out outputs/response
```

Add `--execute` only when the response is explicitly authorized. The default mode is dry-run and records the planned command trace, blockers, and response bundle. Execution also requires both `--allow-lab-response` and a tenant ID present in `AUDITEX_LAB_TENANT_IDS`.

## Troubleshooting common login failures

- `AADSTS500113: No reply address is registered for the application.`  
  Usually indicates delegated/browser login attempted with a non-browser app registration flow that has no redirect URI for this environment. Use Azure CLI token flow or provide a properly configured app registration.
- `AADSTS53003` during interactive app/token flow  
  Usually Conditional Access blocked token issuance. Use a policy-exempt account or a browser-suppressed Azure CLI auth flow if approved by the client.
- `AADSTS500113` when running exchange collection with m365 CLI  
  `m365` may require an app registration in this environment. Re-run login with `--m365-app-id <app-id>` or set `M365_CLI_APP_ID` / `M365_CLI_CLIENT_ID` before rerunning `tenant-audit-full --include-exchange`.
