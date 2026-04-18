# Audit Flow Log

Living log for the GR-only tenant audit path.

## GA m365 App Setup

- Goal: enable `m365` browser login for Exchange-backed checks.
- Operator: `bolyki@bolyki.eu` with Global Administrator.
- Result: app created.
- App name: `CLI for M365`
- App ID: `1a943a60-e4db-448c-a946-e825378e4883`
- Tenant ID: `03174e44-540d-43a6-9dc4-fdff48bd182d`

Flow that worked:

1. `az login --tenant bolyki.eu --allow-no-subscriptions`
2. sign in as GA in Safari
3. accept tenant/subscription selection
4. run `m365 setup`
5. choose `Create a new app registration`
6. choose `All`
7. choose `Scripting`
8. choose `PowerShell: Yes`
9. choose `Proficient`
10. confirm setup
11. confirm Azure CLI app creation step
12. sign in again in browser when prompted
13. setup returns `clientId` and `tenantId`

What was needed:

- Azure CLI signed in as GA
- `m365` installed
- browser auth allowed
- tenant allows app registration creation by GA

What did not work:

- `m365 setup --scripting` alone did not create the app in this environment
- interactive `m365 setup` did

## Run Snapshot

- Tenant: `BOLYKI`
- Account: `global.reader@bolyki.eu`
- Mode: Azure CLI delegated auth
- Outcome: partial
- Coverage: identity, app consent, security, domains/hybrid worked
- Evidence: `outputs/gr-only/BOLYKI-run_20260418_091631/`

## What Worked

- Local bootstrap and Python env setup.
- Azure CLI sign-in with `--allow-no-subscriptions`.
- Browser flow in Safari.
- Graph access for `identity`, `app_consent`, `security`, and `domains_hybrid`.
- Auth context capture: signed-in user and directory role resolved as `Global Reader`.

## Obstacles

- `conditional_access`
  - `authenticationStrengthPolicies`: bad request, segment not found.
  - `authenticationContextClassReferences`: missing scope.
- `defender`
  - `securityAlerts`, `secureScores`, `secureScoreControlProfiles`: blocked by permissions.
  - `defenderIncidents`: account not provisioned.
- `service_health`
  - all three endpoints returned permission errors.
- `auth_methods`
  - `authenticationMethodsPolicy` denied; `userRegistrationDetails` worked.
- `reports_usage`
  - usage report endpoints returned invalid permission / S2S unauthorized.
- `external_identity`
  - `authenticationFlowsPolicy` needed `Policy.Read.All`.
- `consent_policy`
  - `adminConsentRequestPolicy` denied.
- `licensing`
  - `subscribedSkus` rejected custom page size.
- `intune`
  - managed devices and policy endpoints denied.
- `sharepoint`, `sharepoint_access`, `onedrive_posture`
  - sharepoint settings API denied.
- `teams`
  - channel collection failed on license lookup; 10 blockers.

## What This Means

GR is enough for a baseline audit. It is not enough for full depth. The next unlocks are `Security Reader` for security and service health, plus Exchange app setup if mail-backed checks are needed.

## GR Plus Exchange App

- One-time GA action created tenant-local `m365` app.
- After that, GR worked with the existing app.
- Proven live commands under GR:
  - `m365 status --output json`
  - `m365 tenant info get --output json`
  - `m365 outlook report mailboxusagemailboxcount --period D30 --output json`
  - `m365 outlook report mailboxusagequotastatusmailboxcounts --period D30 --output json`
- Full Exchange collector run finished `ok` with `item_count=122`.
- Conclusion: runtime Exchange report collection does not need GA once the app exists and consent is already in place.

## New Operator Controls

- `auditex setup` wraps first-run local bootstrap.
- `auditex doctor` shows machine, tool, and auth readiness.
- `auditex guided-run` walks setup, login, preflight, and live progress.
- `--probe-first` can skip collectors already proven blocked.
- `--throttle-mode safe` and `--throttle-mode ultra-safe` reduce burst behavior and back off harder on repeated denials and `429`.

## Debug Trail

Use these artifacts first:

- `audit-log.jsonl`
- `audit-debug.log`
- `diagnostics.json`
- `blockers/blockers.json`
- `run-manifest.json`
