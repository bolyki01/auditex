# AI Tenant Audit Knowledge Base

> Audience: agentic systems operating this repo.
> Scope: Microsoft 365 tenant population, audit, and Windows 365 / Intune verification.
> Source basis: repo state, run artifacts, commands executed in this workspace, and the full conversation history in this session.

## Canonical Tenant Context

```yaml
tenant:
  tenant_name: Bolyki Solutions
  tenant_domain: bolyki.eu
  tenant_id: 03174e44-540d-43a6-9dc4-fdff48bd182d
  timezone: Pacific Standard Time
  usage_location: US
```

## Objective

Build and audit a realistic Microsoft 365 enterprise tenant seed that can be copied across machines, used by Codex or other AI agents, and later audited with a Global Reader or a broader admin token.

The practical success criterion is not only object creation. The tenant is considered fully populated only when:

1. identity, groups, Teams, Exchange, Entra, and Intune artifacts exist,
2. at least one real Cloud PC or enrolled endpoint is visible as a managed device,
3. Windows 365 provisioning evidence resolves to `managedDeviceId`,
4. verification can observe the managed-device path without relying solely on synthetic directory devices.

## What Was Learned

### Identity and group population

- The lab seed creates a large enterprise-like identity shape.
- The max profile uses:
  - 96 internal users
  - 12 guests
  - 712 static groups
  - 81 dynamic groups
- The identity seed run `enterprise-lab-max-live-20260416b-identity` resolved:
  - `plannedUsers = 108`
  - `resolvedUsers = 108`
  - `resolvedInternalUsers = 96`
  - `resolvedGuestUsers = 12`
  - `plannedStaticGroups = 712`
  - `plannedDynamicGroups = 81`

### Tenant population state

- The tenant is strongly populated for:
  - users
  - groups
  - Teams
  - Exchange policy artifacts
  - Entra policy artifacts
  - Intune policy artifacts
  - scenario event artifacts
- The tenant is not fully populated until managed endpoints are real.
- Synthetic `/devices` records are informational only.
- Real success is measured by:
  - `/deviceManagement/managedDevices`
  - Windows 365 Cloud PC evidence
  - `managedDeviceId`

### Current live blockers

The latest live runs still show these blockers:

- Windows 365 Graph endpoints return `403 Forbidden`:
  - `/deviceManagement/virtualEndpoint/cloudPCs`
  - `/deviceManagement/virtualEndpoint/provisioningPolicies`
  - `/deviceManagement/virtualEndpoint/userSettings`
- Intune policy read visibility is incomplete in the live verifier:
  - `intune.compliance = forbidden`
  - `intune.configurations = forbidden`
  - `devices.managed = forbidden`
- The Windows 365 workflow therefore stops before it can record a real Cloud PC with a `managedDeviceId`.

## Repo-Verified State

### Final verification snapshot

Latest non-dry-run verifier output for `enterprise-lab-max-live-20260416b`:

```yaml
verification:
  users.total: pass
  users.internal: pass
  users.guests: pass
  users.requiredSeedUserUpns: pass
  groups.total: pass
  groups.static.required: pass
  groups.dynamic.required: pass
  groups.staticCategory: pass
  security.conditionalAccess: pass
  security.defaults: warn unknown
  intune.compliance: warn forbidden
  intune.configurations: warn forbidden
  artifacts.exchangePolicies: pass
  artifacts.entraPolicies: pass
  artifacts.intunePolicies: pass
  artifacts.scenarioEvents: pass
  teams.seedGroups: pass
  teams.discovered: pass
  devices.directory: warn
  devices.managed: warn forbidden
```

### Important artifact paths

- [population-verification-manifest.json](/home/bolyki/microsoft/tenant-bootstrap/runs/enterprise-lab-max-live-20260416b/population-verification-manifest.json)
- [population-verification-log.jsonl](/home/bolyki/microsoft/tenant-bootstrap/runs/enterprise-lab-max-live-20260416b/population-verification-log.jsonl)
- [identity-seed-az-manifest.json](/home/bolyki/microsoft/tenant-bootstrap/runs/enterprise-lab-max-live-20260416b-identity/identity-seed-az-manifest.json)
- [workload-seed-az-manifest.json](/home/bolyki/microsoft/tenant-bootstrap/runs/enterprise-lab-max-live-20260416b-workload/workload-seed-az-manifest.json)
- [windows365-readiness-manifest.json](/home/bolyki/microsoft/tenant-bootstrap/runs/enterprise-lab-max-live-20260416b-workload/windows365-readiness-manifest.json)
- [windows365-blocker-manifest.json](/home/bolyki/microsoft/tenant-bootstrap/runs/enterprise-lab-max-live-20260416b-workload/windows365-blocker-manifest.json)
- [exchange-baseline-manifest.json](/home/bolyki/microsoft/tenant-bootstrap/runs/enterprise-lab-max-live-20260416b-workload/exchange-baseline-manifest.json)
- [mdm-fleet-manifest.json](/home/bolyki/microsoft/tenant-bootstrap/runs/enterprise-lab-max-live-20260416b-workload/mdm-fleet-manifest.json)
- [license-readiness-manifest.json](/home/bolyki/microsoft/tenant-bootstrap/runs/enterprise-lab-max-live-20260416b-workload/license-readiness-manifest.json)

## Scripts Used

### Bootstrap and population

- `tenant-bootstrap/run-enterprise-lab-max.sh`
- `tenant-bootstrap/run-bootstrap-azurecli.sh`
- `tenant-bootstrap/scripts/seed-workload-az.py`
- `tenant-bootstrap/scripts/windows365_workload.py`
- `tenant-bootstrap/scripts/identity_seed_az.py`
- `tenant-bootstrap/scripts/verify-population-az.py`

### Auth and app setup

- `tenant-bootstrap/scripts/create-lab-populator-app.py`
- `tenant-bootstrap/scripts/auth-lab-populator.py`

### Evidence and inspection

- `tenant-bootstrap/scripts/run-audit-collector.sh`
- `tenant-bootstrap/scripts/inspect-bootstrap-log.sh`
- `tenant-bootstrap/scripts/inspect-audit-logs.sh`

## Commands Used In This Session

### Status and verification

```bash
cd /home/bolyki/microsoft/tenant-bootstrap && az account show --output json
cd /home/bolyki/microsoft/tenant-bootstrap && python3 scripts/verify-population-az.py --config config.enterprise-lab-max.json --run-name enterprise-lab-max-live-20260416b --run-dir runs/enterprise-lab-max-live-20260416b --bootstrap-root .
cd /home/bolyki/microsoft/tenant-bootstrap && python3 scripts/verify-population-az.py --config config.enterprise-lab-max.json --run-name enterprise-lab-max-live-20260416b --run-dir runs/enterprise-lab-max-live-20260416b --bootstrap-root . --dry-run
```

### W365 probe runs

```bash
cd /home/bolyki/microsoft/tenant-bootstrap && python3 scripts/seed-workload-az.py --config config.enterprise-lab-max.json --run-name windows365-app-live-20260416 --steps windows365 --days 1
cd /home/bolyki/microsoft/tenant-bootstrap && AZURE_ACCESS_TOKEN="<app-token>" python3 scripts/seed-workload-az.py --config config.enterprise-lab-max.json --run-name windows365-app-only-20260416 --steps windows365 --days 1
```

### App registration and token acquisition

```bash
cd /home/bolyki/microsoft/tenant-bootstrap && python3 scripts/create-lab-populator-app.py --config configs/lab-populator-permissions.json --tenant-id 03174e44-540d-43a6-9dc4-fdff48bd182d --admin-consent --create-secret
cd /home/bolyki/microsoft/tenant-bootstrap && python3 scripts/auth-lab-populator.py --tenant-id 03174e44-540d-43a6-9dc4-fdff48bd182d --app-secret-file .secrets/lab-populator-app-secret.json --out .secrets/lab-populator-token-claims-app.json
cd /home/bolyki/microsoft/tenant-bootstrap && python3 scripts/auth-lab-populator.py --tenant-id 03174e44-540d-43a6-9dc4-fdff48bd182d --app-secret-file .secrets/lab-populator-app-secret.json --write-env .secrets/lab-populator-token.env
```

### Validation

```bash
cd /home/bolyki/microsoft/tenant-bootstrap && pytest tests/test_remaining_population_gaps.py -q
```

## Lab Populator App

The tenant populator app was created in this session.

```yaml
lab_populator_app:
  display_name: Bolyki Lab Tenant Populator
  app_id: 0b6f3604-0168-44be-b11b-5ec7cd3428ef
  secret_path: .secrets/lab-populator-app-secret.json
  admin_consent_attempted: true
```

Important note:

- The app token generation helper wrote an empty `AZURE_ACCESS_TOKEN` env file at one point.
- The app secret itself is valid and the token claims decoded correctly when fetched directly.
- The app-only token still did not clear the Windows 365 `403` blockers.

## Windows 365 / Intune Findings

### Current W365 workflow

The W365 path in `tenant-bootstrap/scripts/windows365_workload.py`:

1. builds a Windows 365 plan from config,
2. selects a Cloud PC SKU,
3. resolves the pilot user,
4. creates or reuses a pilot security group,
5. creates or reuses a Cloud PC provisioning policy,
6. assigns that policy to the pilot group,
7. polls for `cloudPc`,
8. records `managedDeviceId` when present.

### Current W365 blocker shape

The latest live runs still fail on:

- `cloudPCs`
- `provisioningPolicies`
- `userSettings`

The blocker artifact reason is `windows365-api-not-ready`.

### What changed in repo to improve verification

The verifier now reads `windows365-provisioning-manifest.json` and can treat a recorded Cloud PC `managedDeviceId` as managed-device evidence if the live `managedDevices` endpoint is hidden.

This means:

- the W365 workflow remains the source of truth for actual provisioning,
- verification no longer relies only on `/deviceManagement/managedDevices`,
- once a real Cloud PC exists, the audit can count it as managed even if endpoint visibility is partial.

### Remaining manual requirement

Tenant-side Windows 365 enablement still needs to succeed for the pilot user and the provisioning policy assignment. Code alone cannot resolve service-level 403s.

## License and Seat Observations

Observed in live manifests:

- `EXCHANGESTANDARD`: 1 enabled, 1 consumed, 0 available
- `BUSINESS_PREMIUM_AND_MICROSOFT_365_COPILOT_FOR_BUSINESS`: 1 enabled, 1 consumed, 0 available
- `MICROSOFT_AGENT_365_TIER_3`: 25 enabled, 25 consumed, 0 available
- `AAD_PREMIUM_P2`: 25 enabled, 1 consumed, 24 available
- `POWER_BI_PRO`: 25 enabled, 5 consumed, 20 available
- `CPC_E_2C_8GB_128GB`: 1 enabled, 0 consumed, 1 available

Implication:

- mailbox and Cloud PC realism are seat-gated,
- some sample-data and mailbox work will fail if the only Exchange-capable seat is already allocated,
- Windows 365 Enterprise seat availability exists, but provisioning still depends on service exposure.

## What The Repo Already Contains

### Portable audit and bootstrap structure

- Cross-platform Azure CLI bootstrap flow
- PowerShell bootstrap flow
- read-only audit collector
- run manifests
- JSONL command logs
- evidence bundle tooling

### Microsoft Agent Skills content

The repo already vendors Microsoft skills and has a local digest for selective use:

- `tenant-bootstrap/docs/MICROSOFT-AGENT-SKILLS-DIGEST.md`
- `tenant-bootstrap/vendor/microsoft-skills/ALL-SKILLS-CATALOG.md`
- `tenant-bootstrap/vendor/microsoft-skills/upstream/`

Recommended skill usage pattern:

- `microsoft-docs` for current Microsoft behavior
- `entra-app-registration` for app registration and permissions
- `azure-identity-py` for credential handling
- `mcp-builder` for a future MCP tenant auditor
- `m365-agents-py` and `microsoft-foundry` only after the CLI auditor is stable

## Open Gaps

1. Windows 365 service exposure still blocks `cloudPCs` and `provisioningPolicies`.
2. Intune policy endpoints still return `forbidden` in the live verifier.
3. No live Cloud PC yet means no real `managedDeviceId` evidence.
4. `security.defaults` remains `unknown` in the live verifier because the token cannot reliably confirm it.

## Practical Next Manual Step

If the tenant owner wants this to complete, the remaining manual action is:

1. verify Windows 365 is enabled in the tenant,
2. verify `GG-W365-Enterprise-Pilot` exists and is assigned,
3. assign the Cloud PC license to `daily.user`,
4. provision one Cloud PC,
5. wait for Intune to surface the managed device.

That is the minimum condition for the audit to transition from seeded-to-real on the endpoint leg.

