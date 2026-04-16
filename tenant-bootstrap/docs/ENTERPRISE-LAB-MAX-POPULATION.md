# Enterprise Lab Max Population

This profile turns the lab tenant into a dense Microsoft 365 enterprise simulation.
It is for owned lab tenants only, not customer Global Reader audits.

## What It Plans

- 96 internal users plus 12 guest personas.
- 712 static groups and 81 dynamic groups.
- 16 Teams-backed Microsoft 365 group targets.
- 100 endpoint records across Windows, macOS, iOS/iPadOS, and Android.
- 27 Exchange / Defender for Office artifacts.
- 26 Entra security and governance artifacts.
- 23 Intune / MDM artifacts.
- 540 scenario events across mail, calendar, Teams, OneDrive, SharePoint, incidents, DLP, phishing, vendor risk, and Copilot oversharing scenarios.

## Main Command

Dry-run first:

```bash
cd tenant-bootstrap
./run-enterprise-lab-max.sh --run-name enterprise-lab-max-dryrun --days 1
```

Live run:

```bash
cd tenant-bootstrap
./run-enterprise-lab-max.sh --live --run-name enterprise-lab-max-live --days 30
```

Use `--days 1` for the first live run if you want identity, group, policy, endpoint, and artifact population without generating a large sample-data attempt.

## Lab Populator App

The broad app permission profile is stored in:

```text
configs/lab-populator-permissions.json
```

Dry-run the app creation plan:

```bash
python3 scripts/create-lab-populator-app.py --config configs/lab-populator-permissions.json --dry-run
```

Create/update the app and attempt admin consent:

```bash
python3 scripts/create-lab-populator-app.py --config configs/lab-populator-permissions.json --tenant-id 03174e44-540d-43a6-9dc4-fdff48bd182d --admin-consent
```

Secrets and token claim diagnostics go under `.secrets/`, which is ignored by git.

## Artifact-Only Behavior

Some Microsoft 365 surfaces cannot be realistically created from a simple Azure CLI delegated token:

- real managed-device enrollment,
- Windows 365 Cloud PC provisioning,
- Teams channel messages in app-only mode,
- Exchange Online / Defender for Office policies without Exchange PowerShell role and module support,
- mailbox/calendar/contact/file writes before mailbox and drive provisioning is ready.

The max-lab tooling does not hide those failures. It writes:

- `enterprise-policy-artifact-plan.json`
- `enterprise-scenario-plan.json`
- `mdm-fleet-manifest.json`
- `cloudpc-readiness-manifest.json`
- `exchange-baseline-manifest.json`
- JSONL command and Graph request logs
- population verification manifests

This makes blocked and planned enterprise posture visible during later audits.

## Current Live State

After the follow-up live reruns on 2026-04-16:

- 12 guest users are invited and resolved.
- 7 Conditional Access policies are now created successfully.
- Security defaults are disabled.
- 4 Intune compliance policies are now created successfully.
- 2 Intune configuration profiles are now created successfully.
- 16 target Teams are now realized successfully.

Still blocked in the current tenant state:

- Managed devices and directory device count because those require real enrollment / Cloud PC / Autopilot style onboarding, not only Graph writes.
- Exchange/Defender real policy creation because the local host currently lacks a working authenticated Exchange PowerShell path.
- Broad mailbox seeding because Exchange-capable seat availability and OneDrive provisioning are constrained.

Managed-device execution model:

- `windows365` is now a first-class workload step.
- Phase 1 target is `1` real managed device, not `100` synthetic directory devices.
- The seeder prefers the Windows 365 Enterprise SKU first and only falls back to Business if explicitly allowed in config.
- Windows 365 API access and provisioning blockers are written into `windows365-readiness-manifest.json` and `windows365-blocker-manifest.json`.

Current live verification snapshot:

- Users total: 109 observed.
- Internal users: 97 observed.
- Guest users: 12 observed.
- Groups total: 800 observed.
- Required static groups: 712 present.
- Required dynamic groups: 81 present.
- Teams: 16 expected Team groups present, 17 Teams discovered total in tenant.
- Directory devices: 2 observed.
- Managed devices: 0 observed.

License posture relevant to mailbox and endpoint realism:

- `EXCHANGESTANDARD`: 1 enabled, 1 consumed, 0 available.
- `BUSINESS_PREMIUM_AND_MICROSOFT_365_COPILOT_FOR_BUSINESS`: 1 enabled, 1 consumed, 0 available.
- `MICROSOFT_AGENT_365_TIER_3`: 25 enabled, 25 consumed, 0 available.
- `AAD_PREMIUM_P2`: 25 enabled, 1 consumed, 24 available.
- `POWER_BI_PRO`: 25 enabled, 5 consumed, 20 available.
- `CPC_E_2C_8GB_128GB`: 1 enabled, 0 consumed, 1 available.

## Current Verified Dry-Run

The wrapper dry-run `enterprise-lab-max-wrapper-dryrun` completed with:

- 108 planned users.
- 793 planned groups total.
- 100 planned directory devices.
- 27 Exchange artifacts.
- 26 Entra artifacts.
- 23 Intune artifacts.
- 540 scenario events.
- verification status `completed`.
