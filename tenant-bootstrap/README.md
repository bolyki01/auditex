# Tenant Bootstrap Kit

This kit creates a realistic Microsoft 365 tenant seed for audit training and
security validation. It is intentionally scoped for a fresh/small tenant and
focuses on realistic posture:

- three admin lanes (daily account, named admin, two break-glass/emergency accounts),
- group-based licensing,
- Exchange, Teams, SharePoint, and Intune seed objects,
- sample operational/collaboration/business data,
- command/audit logging from every execution step.

The scripts are written for PowerShell 7+ and can be copied with the rest of this
repo to macOS/Windows hosts.

## Folder Layout

- `config.example.json` — tenant/app/settings template.
- `run-bootstrap.ps1` — orchestrator to execute all steps.
- `scripts/00-shared.ps1` — shared auth, logging, and command wrapper.
- `scripts/01-create-workload-apps.ps1` — create workload apps.
- `scripts/02-seed-identities-groups.ps1` — create users/groups and sample OUs/roles.
- `scripts/identity_seed_az.py` — fallback identity/group seeder using Azure CLI + Graph REST when PowerShell is unavailable.
- `scripts/03-seed-licenses.ps1` — group-based licensing.
- `scripts/seed-workload-az.py` — workload seeding from Azure CLI fallback (licenses/windows365/teams/intune/security/devices/exchange/sample).
- `scripts/verify-population-az.py` — post-seed verification of users, groups, Conditional Access, Intune, Teams, devices, and artifacts.
- `scripts/04-seed-exchange.ps1` — shared/resource mailboxes + baseline anti-phish.
- `scripts/05-seed-teams.ps1` — Teams from groups and channel scaffold.
- `scripts/06-seed-sharepoint-intune.ps1` — SharePoint sites + Intune policies.
- `scripts/07-seed-sample-data.ps1` — mail/calendar/contacts/teams/OneDrive sample data.
- `scripts/08-secure-baseline.ps1` — conditional access report-only rings and hardening baselines.
- `scripts/09-collect-evidence.ps1` — trigger the local audit bundle capture.
- `policies/*` — payloads used by the baseline script.
- `templates/` — sample files for OneDrive/SharePoint content.

### Portable execution model

All audit collection now runs through a single entry wrapper:

- `tenant-bootstrap/scripts/run-audit-collector.sh`

It will prefer a bundled full audit package when available, with local fallback to
the legacy fallback collector if not. In practice the folder now ships the full
audit package inside `tenant-bootstrap/azure_tenant_audit` and collector
definitions in `tenant-bootstrap/configs`, so this folder can run on another host
without the parent repository.

Authentication for audit runs follows this order:

- `--interactive` + delegated app login
- `--token-env` + `AZURE_ACCESS_TOKEN`
- `--use-azure-cli-token` (falls back to current `az account` context)

Each wrapper emits auth metadata in `run-manifest.json` and command logs, so you can
prove which source was used for a given run.

Enterprise-scale controls

Use the optional `enterpriseScale` block in `config.example.json` to increase tenant fidelity:

- department security + collaboration seed groups,
- function/organizational workstream groups,
- resource and program groups,
- risk and oversharing control groups,
- deterministic region/group tags.

Defaults are tuned for a 200+ group tenant build without changing your user volume:

- 28 internal users (plus 4 guests),
- named admin and emergency lane users,
- deterministic static group catalogs,
- dynamic groups by department/job-title/guest/risk patterns,
- seeded Teams, sample SharePoint content, Intune baseline policies, and mail/calendar activity.

## Execution order

1. `01-create-workload-apps.ps1`
2. `02-seed-identities-groups.ps1`
3. `03-seed-licenses.ps1`
4. `04-seed-exchange.ps1`
5. `05-seed-teams.ps1`
6. `06-seed-sharepoint-intune.ps1`
7. `07-seed-sample-data.ps1`
8. `08-secure-baseline.ps1`
9. `09-collect-evidence.ps1` (optional, produces audit output)

### PowerShell availability

Install PowerShell when needed:

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y wget apt-transport-https software-properties-common
source /etc/os-release
wget -q https://packages.microsoft.com/keys/microsoft.asc -O- | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-bookworm-prod bookworm main" > /etc/apt/sources.list.d/microsoft.list'
sudo apt-get update
sudo apt-get install -y powershell

# macOS
brew install --cask powershell
```

Use `pwsh` to run PowerShell bootstrap scripts.

Install the minimum Python dependencies for the Python CLI/audit pipeline:

```bash
python3 -m pip install -r tenant-bootstrap/requirements.txt
```

The package set is intentionally small and portable (`requests`, `msal`).

## Run

### One-command enterprise flow (recommended)

```bash
cd tenant-bootstrap
./run-enterprise-audit.sh \
  --tenant-name "Bolyki Solutions" \
  --inspect
```

This executes:

1. Azure CLI bootstrap/seeding (`run-bootstrap-azurecli.sh`)  
2. Population verification (`scripts/verify-population-az.py`)
3. Full audit collection (`scripts/run-audit-collector.sh`)  
4. Post-run summary (`scripts/inspect-bootstrap-log.sh`, `scripts/inspect-audit-logs.sh`)

PowerShell workflow (legacy):

```powershell
cd tenant-bootstrap
.\run-bootstrap.ps1 -ConfigPath .\config.example.json -TenantName "BOLYKI-LAB"
```

Cross-platform bootstrap flow (uses Azure CLI token mode and avoids PowerShell):

```bash
cd tenant-bootstrap
./run-bootstrap-azurecli.sh --tenant-name "BOLYKI-LAB"
```

If no active Azure CLI session exists, the wrapper can auto-open browser-based login
and continue using that token:

```bash
cd tenant-bootstrap
./run-bootstrap-azurecli.sh --tenant-name "BOLYKI-LAB" --browser-command firefox
```

Dry-run with full chain:

```bash
./run-bootstrap-azurecli.sh --tenant-name "BOLYKI-LAB" --dry-run
```

Enterprise lab max population profile:

```bash
cd tenant-bootstrap
./run-enterprise-lab-max.sh --run-name enterprise-lab-max-dryrun --days 1
./run-enterprise-lab-max.sh --live --run-name enterprise-lab-max-live --days 30
```

The max profile uses `config.enterprise-lab-max.json` and plans a large enterprise-like
tenant: 96 internal users, 12 guests, 700+ groups, 100 endpoint records, dense
Exchange/Defender/Entra/Intune artifacts, and 500+ scenario events. See
`docs/ENTERPRISE-LAB-MAX-POPULATION.md` before running it live.

The wrapper writes:

- `tenant-bootstrap/runs/<run-name>/bootstrap-shell.log` with start/exit events for every wrapper command
- `tenant-bootstrap/runs/<run-name>/bootstrap-debug.log` with the command output stream
- `tenant-bootstrap/runs/<run-name>/run-manifest.json` with run status and run_id mapping
- `tenant-bootstrap/runs/<run-name>/population-verification-manifest.json` with expected/observed population checks
- `tenant-bootstrap/runs/<run-name>/population-verification-log.jsonl` with Graph verifier request events

If you do not have a custom tenant display name to inject, omit `-TenantName`; the config file stays unchanged and the configured `tenant.tenantName` is used.

If you are already authenticated with Azure CLI in the same shell, this is also a safe dry run:

```powershell
az login
.\run-bootstrap.ps1 -ConfigPath .\config.example.json -TenantName "BOLYKI-LAB" -DryRun
```

Dry-run mode:

```powershell
.\run-bootstrap.ps1 -ConfigPath .\config.example.json -TenantName "BOLYKI-LAB" -DryRun
```

The identity/group step can calculate its enterprise seed shape in dry-run mode
without querying Graph. A full bootstrap still needs PowerShell 7 and the
Microsoft Graph/Exchange/PnP modules for live tenant writes.

Azure CLI fallback for identity/group seeding:

```bash
python3 tenant-bootstrap/scripts/identity_seed_az.py --config tenant-bootstrap/config.example.json --dry-run
python3 tenant-bootstrap/scripts/identity_seed_az.py --config tenant-bootstrap/config.example.json
```

This fallback uses the active `az login` session, creates internal users plus
static/dynamic groups and memberships, skips guest invitations, and writes a manifest plus JSONL
command log under `tenant-bootstrap/runs/<run-name>/`.

Collector run (single command path):

```bash
cd tenant-bootstrap
./scripts/run-audit-collector.sh \
  --tenant-name "Bolyki Solutions" \
  --tenant-id "03174e44-540d-43a6-9dc4-fdff48bd182d" \
  --out "audit-output/Bolyki-Solutions-audit" \
  --auditor-profile global-reader \
  --collectors identity,security,intune,teams,exchange \
  --top 500 \
  --token-env .secrets/lab-populator-token.env
```

It writes:

- `run-manifest.json` with run metadata (older directories may include legacy `audit-manifest.json`)
- `<collector>.json` files in the output directory
- `audit-command-log.jsonl` with command execution events
- `audit-log.jsonl` (full event stream, legacy filename)

Interactive browser auth is supported when you provide a delegated client ID. If `--client-id` is omitted, it falls back to
Azure CLI token mode (requires `az login`) so you can run audits without app registration:

```bash
./scripts/run-audit-collector.sh \
  --tenant-name "Bolyki Solutions" \
  --tenant-id "03174e44-540d-43a6-9dc4-fdff48bd182d" \
  --client-id "<YOUR_PUBLIC_CLIENT_ID>" \
  --collectors identity,security \
  --top 250 \
  --interactive \
  --browser-command firefox \
  --auditor-profile enterprise
```

or a no-app fallback:

```bash
./scripts/run-audit-collector.sh \
  --tenant-name "Bolyki Solutions" \
  --tenant-id "03174e44-540d-43a6-9dc4-fdff48bd182d" \
  --collectors identity,security,teams,exchange \
  --top 250 \
  --token-env .secrets/lab-populator-token.env \
  --auditor-profile global-reader
```

You can force dry-run and inspect the exact command before execution:

```bash
./scripts/run-audit-collector.sh --tenant-name "Bolyki Solutions" --dry-run
```

If run through `run-bootstrap-azurecli.sh`, you also get:

- `tenant-bootstrap/runs/<run-name>-identity/identity-seed-az-manifest.json`
- `tenant-bootstrap/runs/<run-name>-identity/identity-seed-az-log.jsonl`
- `tenant-bootstrap/runs/<run-name>-workload/workload-seed-az-manifest.json`
- `tenant-bootstrap/runs/<run-name>-workload/workload-seed-az-log.jsonl`
- `tenant-bootstrap/runs/<run-name>-workload/workload-seed-az-debug.log`
- `tenant-bootstrap/runs/<run-name>/population-verification-manifest.json`
- `tenant-bootstrap/runs/<run-name>/population-verification-log.jsonl`
- `tenant-bootstrap/audit-output/<run-name>-evidence/audit-command-log.jsonl`
- `tenant-bootstrap/audit-output/<run-name>-evidence/audit-log.jsonl`
- `tenant-bootstrap/runs/<run-name>/bootstrap-shell.log`
- `tenant-bootstrap/runs/<run-name>/bootstrap-debug.log`
- `tenant-bootstrap/runs/<run-name>/run-manifest.json`

Azure CLI + Graph workload seeding (non-PowerShell):

```bash
cd tenant-bootstrap
python3 scripts/seed-workload-az.py \
  --config config.example.json \
  --run-name az-workload-seed-20260416 \
  --steps licenses,windows365,teams,intune,security,devices,exchange,sample \
  --days 20
```

This writes:

- `tenant-bootstrap/runs/<run-name>/workload-seed-az-log.jsonl`
- `tenant-bootstrap/runs/<run-name>/workload-seed-az-debug.log`
- `tenant-bootstrap/runs/<run-name>/workload-seed-az-manifest.json`
- `workload-seed-az-manifest.json` includes planned endpoint inventory when `devices` is in the step list.
- `license-readiness-manifest.json` summarizes subscribed SKUs, available seats, mail-enabled users, and license assignment errors. This is the first place to check when Exchange mailboxes, Teams, OneDrive, or Copilot sample data look empty after a population run.
- `windows365-readiness-manifest.json` records Windows 365 visibility checks, preferred Enterprise-vs-Business SKU selection, and delegated/app token posture.
- `windows365-blocker-manifest.json` is written when Windows 365 APIs are still blocked or the tenant is not ready for provisioning.
- Endpoint seeding creates Entra device records and Intune assignment targets (policy coverage surface); it does **not** onboard real virtual/physical hardware into MDM. The run also writes `mdm-fleet-manifest.json` with a concrete Windows/macOS/iOS enrollment playbook and validation command sets to execute through your real Intune/Autopilot/Apple MDM process.
- Real managed-device success is measured against the phased target in config, starting with `devices.managedTargetPhase1` and the Windows 365 pilot lane.
- Exchange baseline seeding in the Azure CLI flow now reads JSON policy catalogs from `policies/exchange/`
  and writes an `exchange-baseline-manifest.json` command catalog plus `commandSummary` block, so you can run policy commands in your preferred admin tooling consistently and replay command outcomes from logs.

Delegated workload auth for Windows 365 / managed-device probing:

```bash
cd tenant-bootstrap
.venv/bin/python scripts/seed-workload-az.py \
  --config config.enterprise-lab-max.json \
  --run-name windows365-interactive \
  --steps windows365 \
  --interactive \
  --client-id 0b6f3604-0168-44be-b11b-5ec7cd3428ef \
  --browser-command firefox
```

Post-seed verification can also be run directly:

```bash
cd tenant-bootstrap
python3 scripts/verify-population-az.py \
  --config config.example.json \
  --run-name "<run-name>" \
  --run-dir "runs/<run-name>" \
  --bootstrap-root .
```

The verifier returns non-zero on hard population failures, such as missing required users, static groups, or directory device objects. Missing guests, Teams provisioning delays, managed-device visibility, and license-gated security surfaces are warnings because they often depend on tenant licensing, invitation acceptance, or service propagation.

For idempotent production runs, run the same command again after initial seeding.

Reader-only posture:

```powershell
# Evidence-only mode (no writes)
.\run-bootstrap.ps1 -ConfigPath .\config.example.json -RunApps:$false -RunIdentity:$false -RunLicensing:$false -RunExchange:$false -RunTeams:$false -RunSharepoint:$false -RunSampleData:$false -RunSecurity:$false -RunEvidence
```

### Output and evidence artifacts

Each script run writes:

- `run-manifest.json` with status, step status, and artifact metadata
- `bootstrap-shell.log` with wrapper command events (Azure CLI flow)
- `bootstrap-debug.log` with command output transcript (Azure CLI flow)
- `population-verification-manifest.json` with pass/warn/fail checks against the configured seed plan
- `population-verification-log.jsonl` with verifier command/Graph request events
- `bootstrap-log.jsonl` for PowerShell flow runs (`run-bootstrap.ps1`)
- `run-manifest.json` with collector inventory and selected modules (audit flow; older output may use legacy `audit-manifest.json`)
- `audit-log.jsonl` and `audit-command-log.jsonl` for command/audit event streams
- `license-readiness-manifest.json`, `windows365-readiness-manifest.json`, and `windows365-blocker-manifest.json` for license, mailbox, Windows 365, and Graph-scope diagnosis

You can pass `-RunEvidence` to execute `09-collect-evidence.ps1` after the standard bootstrap steps and capture audit collector output in the `audit-output` folder.

Useful command to inspect what was collected:

```powershell
Get-Content .\tenant-bootstrap\runs\<run-name>\bootstrap-shell.log | Sort-Object
Get-Content .\tenant-bootstrap\audit-output\<tenant>-<run-name>\audit-command-log.jsonl | ConvertFrom-Json | Sort-Object details.ts_utc
```

You can also use the helper script to summarize an evidence run quickly:

```bash
./scripts/inspect-audit-logs.sh latest
./scripts/inspect-bootstrap-log.sh latest
```

## Important

- Microsoft Agent Skills are vendored in `vendor/microsoft-skills/`, including a
  full upstream copy under `vendor/microsoft-skills/upstream/` and a searchable
  catalog at `vendor/microsoft-skills/ALL-SKILLS-CATALOG.md`. Start with
  `docs/MICROSOFT-AGENT-SKILLS-DIGEST.md` when working on Graph permissions, app
  registrations, MCP servers, or future Microsoft 365 / Foundry agent packaging.
  Do not load all skills at once; use the catalog to open the smallest relevant
  `SKILL.md`.
- Automation uses app-based Graph/Exchange/PnP auth. A human account should not be
  used as a service identity.
- For `authentication.mode = "azure_cli"`, run `az login` with the target tenant and
  set `tenant`/`tenantId` in config if needed before running bootstrap.
- Some actions (notably Defender, PIM, and Entra ID Protection policy depth) can
  fail in tenants without prerequisite licenses or role scope. The scripts capture
  those failures in `bootstrap-shell.log`/`bootstrap-debug.log` (Azure CLI flow) or
  `bootstrap-log.jsonl` (PowerShell flow).
- Mailboxes are license-gated. If the tenant has only one Exchange-capable seat and
  it is already assigned, seeded users will exist in Entra but will not get Exchange
  mailboxes, OneDrive content, or mailbox-backed sample data. The readiness manifest
  will show `CountViolation` license states in this case.
- Some Microsoft 365 add-on SKUs expose Exchange service plans even when the SKU name
  does not include `EXCHANGE`. Use `licenses.mailboxSeed` and
  `licenses.mailboxSeedMaxUsers` to assign an Exchange-capable seed SKU directly to
  lab users without touching break-glass accounts.
- Windows 365 Business seats can be directly assigned with the `licenses.cloudPcBusiness`
  and `licenses.cloudPcBusinessUser` config values. Cloud PC provisioning inventory
  still needs Cloud PC / Intune Graph scopes, so a normal Azure CLI Graph token may
  assign the license but fail to list `/deviceManagement/virtualEndpoint/cloudPCs`.
- Mailbox addresses can appear in Graph before Exchange REST is ready. Sample-data
  seeding logs per-object warnings for `MailboxNotEnabledForRESTAPI` and Graph scope
  failures instead of aborting the run.
- Validate that you have at least:
  - one admin account with Tenant/Global Admin and PIM activation rights,
  - the tenant domains and DNS validated for mail flow,
  - the SKUs referenced in config available in your subscription.
