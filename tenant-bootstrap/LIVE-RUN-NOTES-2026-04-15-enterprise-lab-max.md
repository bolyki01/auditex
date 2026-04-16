# Live Run Notes - Enterprise Lab Max - 2026-04-15

Tenant:

- Tenant name: Bolyki Solutions
- Tenant ID: 03174e44-540d-43a6-9dc4-fdff48bd182d
- Primary domain: bolyki.eu
- Azure CLI user: bolyki@bolyki.eu

## Runs

- Dry-run wrapper: `enterprise-lab-max-wrapper-dryrun`
- Live directory/workload run: `enterprise-lab-max-live-20260415-2106`
- App-token workload pass: `enterprise-lab-max-app-workload-20260415-2118`
- Security rerun with defaults disabled: `app-security-rerun-20260416`
- Guest invitation and ownership rerun: `app-identity-rerun-20260416-guests`
- Teams realization rerun: `app-teams-rerun-20260416c`
- Final verification: `final-verify-20260416`
- Windows 365 readiness run with app token: `windows365-app-20260416`
- Final verification with phased managed-device target: `final-verify-20260416c`

## Implemented Toolkit Changes

- Added `config.enterprise-lab-max.json`.
- Added `run-enterprise-lab-max.sh`.
- Added lab app permission matrix: `configs/lab-populator-permissions.json`.
- Added lab app tooling:
  - `scripts/create-lab-populator-app.py`
  - `scripts/auth-lab-populator.py`
- Added enterprise artifact catalog: `configs/enterprise-policy-artifact-catalog.json`.
- Added scenario/policy artifact output to `seed-workload-az.py`.
- Added `AZURE_ACCESS_TOKEN` support to workload seeding and verification.
- Added enterprise max tests in `tests/test_enterprise_lab_max.py`.

## Live Directory Results

The live identity run completed:

- Planned users: 108.
- Resolved internal users: 96 in the original live seed, then 97 observed after follow-up reruns because the tenant also contains the signed-in admin account.
- Guest invitations: 12 planned and 12 invited/resolved after the app-token rerun.
- Static groups: 712 planned and verified.
- Dynamic groups: 81 planned and verified.
- Observed groups after run: 800.
- Membership assignments: 431.
- Team owner assignments added on follow-up rerun: 32.

## App Registration

Created/updated app:

- Display name: `Bolyki Lab Tenant Populator`
- App ID: `0b6f3604-0168-44be-b11b-5ec7cd3428ef`
- Secret stored locally under `.secrets/` and ignored by git.

App-token roles observed:

- `Policy.Read.All`
- `Policy.ReadWrite.ConditionalAccess`
- `Policy.ReadWrite.SecurityDefaults`
- `DeviceManagementConfiguration.ReadWrite.All`
- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementApps.ReadWrite.All`
- `CloudPC.ReadWrite.All`
- `User.Invite.All`
- `Team.Create`
- `Channel.Create`
- `Team.ReadBasic.All`
- `Channel.ReadBasic.All`
- `Mail.Send`
- `Mail.ReadWrite`
- `Calendars.ReadWrite`
- `Contacts.ReadWrite`
- `Files.ReadWrite.All`
- `Sites.ReadWrite.All`
- directory/user/group/application write roles

## Workload Results

Artifact posture:

- Exchange / Defender artifacts: 27.
- Entra security/governance artifacts: 26.
- Intune / MDM artifacts: 23.
- Scenario events: 540.
- Endpoint plan: 100 devices.

Real writes / attempts:

- Sample data with app token created:
  - 1 mail send.
  - 1 calendar event.
  - 1 contact.
- OneDrive file write failed with `User's mysite not found`.
- Teams message writes were skipped in app-token mode because normal channel posting is delegated-only.

Resolved after follow-up reruns:

- Security defaults were disabled through Microsoft Graph:
  - initial blocker: enabled.
  - current state: disabled.
- Conditional Access creation is now complete:
  - 7 of 7 required policies are present.
- Intune policy creation was repaired for the current Graph schema:
  - 4 compliance policies now exist.
  - 2 device configuration profiles now exist.
- Guest personas are now invited:
  - 12 of 12 guest users resolved.
- Teams realization is now complete for all seeded collaboration groups:
  - 16 of 16 expected Team-backed groups are materialized.
  - live tenant shows 17 Team resources because the tenant also has the default `Bolyki Solutions` Team.

Still blocked or warning-only:

- Directory device creation still returns `Authorization_RequestDenied` on `POST /devices`; the current app-token path is not enough to synthesize 100 directory devices through Graph alone.
- Managed devices endpoint is visible with app token but currently returns zero managed devices.
- Exchange PowerShell policy commands remain artifact-only because this host still lacks a working Exchange PowerShell path.
- Broad mailbox-backed sample writes still depend on mailbox and OneDrive provisioning readiness.
- License posture is constrained:
  - `EXCHANGESTANDARD`: 1 enabled, 1 consumed, 0 available.
  - `BUSINESS_PREMIUM_AND_MICROSOFT_365_COPILOT_FOR_BUSINESS`: 1 enabled, 1 consumed, 0 available.
  - `MICROSOFT_AGENT_365_TIER_3`: 25 enabled, 25 consumed, 0 available.
- Mail-enabled users observed in the tenant: 26.

## Follow-up Fixes Applied After Initial Live Run

Additional code changes were implemented and validated after the first live notes capture:

- Added payload normalization tests in `tests/test_workload_payload_fixes.py`.
- Added follow-up regression coverage in `tests/test_remaining_population_gaps.py`.
- Added phased managed-device targets and Windows 365 config surface in `config.example.json` and `config.enterprise-lab-max.json`.
- Added a first-class `windows365` workload step in `seed-workload-az.py`.
- Added delegated interactive Graph auth support to `seed-workload-az.py` for Windows 365 and similar workload probes.
- Added Windows 365 readiness and blocker artifacts:
  - `windows365-readiness-manifest.json`
  - `windows365-blocker-manifest.json`
- Added Windows 365 queries to the Intune audit collector and collector definitions.
- Updated verifier expectations so real phase-1 managed-device success is `1` device, not `100` synthetic directory objects.
- Fixed Teams realization to convert existing Microsoft 365 groups through `PUT /groups/{id}/team`, then wait for readiness and create channels with retry handling.
- Added CA policy normalization in `seed-workload-az.py`:
  - empty controls/placeholders are stripped,
  - `reportOnly` is translated to `enabledForReportingButNotEnforced`.
- Added security-defaults handling in `seed-workload-az.py` and `08-secure-baseline.ps1`:
  - reads `identitySecurityDefaultsEnforcementPolicy`,
  - can disable defaults when explicitly requested,
  - surfaces defaults state in manifests and verification.
- Added Intune policy sanitization in `seed-workload-az.py`:
  - compliance policies now get the required single `block` scheduled action for `PasswordRequired`,
  - unsupported Windows compliance/configuration fields are removed before POST.
- Fixed Exchange command execution so Exchange cmdlets are routed through `pwsh` when available instead of being invoked as bare binaries.
- Added guest invitation flow to `identity_seed_az.py`.
- Added Team owner assignment to seeded Team groups in `identity_seed_az.py`.
- Added Teams conversion retry handling for `429` and `503` responses.

Follow-up reruns:

- `payload-fix-rerun-20260416-security-intune`
  - created 5 Intune policies on first repair pass.
- `payload-fix-rerun-20260416-security-only`
  - created 2 report-only CA policies.
- `payload-fix-rerun-20260416-intune-only`
  - created the last remaining Windows configuration profile.
- `app-security-rerun-20260416`
  - created the remaining 5 enabled CA policies after security defaults were disabled.
- `app-identity-rerun-20260416-guests`
  - invited the 12 guest users and added Team owners.
- `app-teams-rerun-20260416c`
  - converted all 16 target groups into Teams and created their channel sets.
- `windows365-app-20260416`
  - executed the new Windows 365 readiness phase with the app token.
  - selected `CPC_E_2C_8GB_128GB` as the preferred pilot SKU because 1 Enterprise seat is still available.
  - wrote blocker artifacts because `cloudPCs`, `provisioningPolicies`, and `userSettings` still returned `403 Forbidden`.

Delegated Windows 365 probe attempt:

- A delegated interactive run was started with the public client variant of `Bolyki Lab Tenant Populator`.
- The local runtime dependency gap (`msal`) was fixed by creating `.venv/` and installing `requirements.txt`.
- The interactive Firefox flow then opened correctly against `http://localhost:<dynamic-port>`, but the run was canceled after waiting for browser completion, so no delegated Windows 365 result was recorded yet.

Latest observed verification state:

- Conditional Access: 7 of 7 present.
- Intune compliance policies: 4 of 4 present.
- Intune configuration policies: 2 of 2 present.
- Teams realized: 16 of 16 expected, 17 discovered total in tenant.
- Guests invited: 12 of 12.
- Security defaults: disabled.
- Managed devices: 0 of planned fleet.
- Directory devices: 2 of planned 100.
- Managed-device phase 1 target: 1.
- Windows 365 app-token state: blocked on `virtualEndpoint` APIs despite `CloudPC.ReadWrite.All`.

## Verification

Latest app-token verification against the live tenant completed with no hard failures in the core identity, security, Intune, and Teams categories:

- Users: pass.
- Static groups: pass.
- Dynamic groups: pass.
- Guests: pass.
- Conditional Access: pass.
- Security defaults state: pass.
- Teams realization: pass.
- Artifact policy counts: pass.
- Scenario event count: pass.
- Devices remain warning-only because they still require actual enrollment or a delegated/device-specific provisioning path.

Main artifacts:

- `runs/enterprise-lab-max-live-20260415-2106/population-verification-manifest.json`
- `runs/enterprise-lab-max-live-20260415-2106-identity/identity-seed-az-manifest.json`
- `runs/enterprise-lab-max-live-20260415-2106-workload/workload-seed-az-manifest.json`
- `runs/enterprise-lab-max-app-workload-20260415-2118/workload-seed-az-log.jsonl`
- `runs/enterprise-lab-max-app-workload-20260415-2118/enterprise-policy-artifact-plan.json`
- `runs/enterprise-lab-max-app-workload-20260415-2118/enterprise-scenario-plan.json`
- `runs/app-security-rerun-20260416/workload-seed-az-manifest.json`
- `runs/app-identity-rerun-20260416-guests/identity-seed-az-manifest.json`
- `runs/app-teams-rerun-20260416c/workload-seed-az-manifest.json`
- `runs/final-verify-20260416/population-verification-manifest.json`
- `runs/windows365-app-20260416/windows365-readiness-manifest.json`
- `runs/windows365-app-20260416/windows365-blocker-manifest.json`
- `runs/final-verify-20260416c/population-verification-manifest.json`
