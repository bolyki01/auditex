# Live Run Notes - Bolyki Solutions - 2026-04-15

Tenant:

- Tenant name: Bolyki Solutions
- Tenant ID: 03174e44-540d-43a6-9dc4-fdff48bd182d
- Primary domain used by seed config: bolyki.eu
- Interactive account used by Azure CLI: bolyki@bolyki.eu
- Main run name: enterprise-populate-20260416-0405

## Scripts Used

Primary toolkit scripts:

- `tenant-bootstrap/scripts/identity_seed_az.py`
  - Created/resolved internal seed users, security groups, Microsoft 365 groups, dynamic groups, and memberships.
- `tenant-bootstrap/scripts/seed-workload-az.py`
  - Applied group-based licensing.
  - Applied direct Windows 365 Business license.
  - Applied direct Agent 365 / Exchange-capable mailbox seed licenses.
  - Created Teams/Intune/security/device/Exchange/sample-data artifacts where permitted.
  - Wrote readiness diagnostics.
- `tenant-bootstrap/scripts/verify-population-az.py`
  - Verified users, groups, dynamic groups, Conditional Access, Intune visibility, Teams, devices, and artifacts.
- `tenant-bootstrap/scripts/inspect-bootstrap-log.sh`
  - Summarized run and verification state.

Supporting command-line tools used:

- `az rest` for direct Microsoft Graph inspection and license assignment validation.
- `az account get-access-token` for Graph token/scope inspection.
- `jq` for JSON summaries.
- `m365 status` and `m365 exo --help` to check Microsoft 365 CLI availability. CLI was installed but logged out, and the installed `exo` surface did not include mailbox list/create commands.
- `python3 -m py_compile` for syntax validation of modified Python scripts.

## Important Commands Run

Initial live enterprise population:

```bash
python3 tenant-bootstrap/scripts/identity_seed_az.py \
  --config tenant-bootstrap/config.example.json \
  --run-name enterprise-populate-20260416-0405-identity

python3 tenant-bootstrap/scripts/seed-workload-az.py \
  --config tenant-bootstrap/config.example.json \
  --run-name enterprise-populate-20260416-0405-workload \
  --steps licenses,teams,intune,security,devices,exchange,sample

python3 tenant-bootstrap/scripts/verify-population-az.py \
  --config tenant-bootstrap/config.example.json \
  --run-name enterprise-populate-20260416-0405 \
  --run-dir tenant-bootstrap/runs/enterprise-populate-20260416-0405 \
  --bootstrap-root tenant-bootstrap
```

License discovery and diagnostics:

```bash
az rest --method get \
  --url 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits,consumedUnits,servicePlans'

az rest --method get \
  --url 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,assignedLicenses,licenseAssignmentStates&$top=999'

az account get-access-token --resource-type ms-graph --query accessToken -o tsv
```

Focused workload reruns after adding license diagnostics:

```bash
python3 tenant-bootstrap/scripts/seed-workload-az.py \
  --config tenant-bootstrap/config.example.json \
  --run-name enterprise-populate-20260416-0405-workload \
  --steps licenses \
  --days 1

python3 tenant-bootstrap/scripts/seed-workload-az.py \
  --config tenant-bootstrap/config.example.json \
  --run-name enterprise-populate-20260416-0405-workload \
  --steps sample \
  --days 20

python3 tenant-bootstrap/scripts/seed-workload-az.py \
  --config tenant-bootstrap/config.example.json \
  --run-name enterprise-populate-20260416-0405-workload \
  --steps licenses,teams,intune,security,devices,exchange,sample \
  --days 1
```

## License Findings

Subscribed SKU state after the mailbox seed run:

- `MICROSOFT_AGENT_365_TIER_3`
  - 25 enabled, 25 consumed.
  - Includes `EXCHANGE_S_STANDARD`, `TEAMS1`, and SharePoint service plans.
  - Assigned directly to 25 seeded lab users.
- `EXCHANGESTANDARD`
  - 1 enabled, 1 consumed.
  - Assigned to `bolyki@bolyki.eu`.
- `BUSINESS_PREMIUM_AND_MICROSOFT_365_COPILOT_FOR_BUSINESS`
  - 1 enabled, 1 consumed.
  - Assigned to `bolyki@bolyki.eu`.
  - Group-based assignment to seed groups remains in `CountViolation` because there is only one seat.
- `CPC_B_2C_8RAM_128GB`
  - 1 enabled, 1 consumed.
  - Assigned directly to `daily.user@bolyki.eu`.
- `CPC_E_2C_8GB_128GB`
  - 1 enabled, 0 consumed.
  - Not assigned because Enterprise Cloud PC management/visibility requires additional Cloud PC/Intune Graph scope and may require prerequisite licensing.
- `POWER_BI_PRO`
  - 25 enabled, 5 consumed.
- `AAD_PREMIUM_P2`
  - 25 enabled, 1 consumed.

Mailbox state after Agent 365 assignment:

- 26 mail-enabled users observed through Graph.
- 25 seeded users have `MICROSOFT_AGENT_365_TIER_3` active.
- `bolyki@bolyki.eu` remains mail-enabled via existing licenses.
- Break-glass accounts were excluded from mailbox seed licensing.

## Users Licensed With Agent 365 / Exchange-Capable SKU

The mailbox seed logic assigned the first 25 configured lab users, excluding break-glass accounts:

- `daily.user@bolyki.eu`
- `admin.named@bolyki.eu`
- `exec.01.staff@bolyki.eu`
- `exec.02.staff@bolyki.eu`
- `exec.03.staff@bolyki.eu`
- `it.01.staff@bolyki.eu`
- `it.02.staff@bolyki.eu`
- `it.03.staff@bolyki.eu`
- `it.04.staff@bolyki.eu`
- `it.05.staff@bolyki.eu`
- `sales.01.staff@bolyki.eu`
- `sales.02.staff@bolyki.eu`
- `sales.03.staff@bolyki.eu`
- `sales.04.staff@bolyki.eu`
- `sales.05.staff@bolyki.eu`
- `hr.01.staff@bolyki.eu`
- `hr.02.staff@bolyki.eu`
- `hr.03.staff@bolyki.eu`
- `finance.01.staff@bolyki.eu`
- `finance.02.staff@bolyki.eu`
- `finance.03.staff@bolyki.eu`
- `finance.04.staff@bolyki.eu`
- `ops.01.staff@bolyki.eu`
- `ops.02.staff@bolyki.eu`
- `ops.03.staff@bolyki.eu`

## Sample Data Result

The sample-data step was attempted after the 25 Agent 365 seats were assigned.

Observed result:

- Mail-enabled users: 26.
- Mailbox users in the all-users group: 25.
- Mail sends created: 0.
- Calendar events created: 0.
- Contacts created: 0.
- OneDrive files created: 0.

Reasons logged:

- Some newly licensed mailboxes returned `MailboxNotEnabledForRESTAPI`; this usually means Exchange address state is visible in Graph before the mailbox REST endpoint is fully ready.
- Other mailbox operations returned `ErrorAccessDenied`; the current Azure CLI delegated Graph token does not include mailbox workload scopes such as `Mail.Send`, `Calendars.ReadWrite`, or `Contacts.ReadWrite`.
- OneDrive writes were not completed; OneDrive provisioning and file-write scopes still need separate validation.

The sample seeder now logs these as warnings per object instead of aborting the run.

## Windows 365 / Cloud PC Findings

What worked:

- The `CPC_B_2C_8RAM_128GB` Windows 365 Business SKU was assigned to `daily.user@bolyki.eu`.

What is blocked:

- Graph calls to `/deviceManagement/virtualEndpoint/cloudPCs` and `/deviceManagement/virtualEndpoint/provisioningPolicies` returned `403`.
- Current token scopes were:
  - `Application.ReadWrite.All`
  - `AppRoleAssignment.ReadWrite.All`
  - `AuditLog.Read.All`
  - `DelegatedPermissionGrant.ReadWrite.All`
  - `Directory.AccessAsUser.All`
  - `Group.ReadWrite.All`
  - `User.Read.All`
  - `User.ReadWrite.All`
- Missing Cloud PC / Intune scope hints:
  - `CloudPC.Read.All`
  - `CloudPC.ReadWrite.All`
  - `DeviceManagementConfiguration.Read.All`
  - `DeviceManagementManagedDevices.Read.All`

## Verification State

Latest verifier status:

- Status: completed.
- Hard failures: 0.
- Core identity/group checks passed.
- Warnings remain for:
  - guests not invited by Azure CLI flow,
  - Conditional Access policies not present,
  - Intune configuration reads forbidden with current token,
  - managed-device reads forbidden with current token,
  - Teams provisioning only discovered one realized Team so far,
  - directory device creation remains best effort and partly blocked.

Latest verification artifact:

- `tenant-bootstrap/runs/enterprise-populate-20260416-0405/population-verification-manifest.json`

## Main Evidence Artifacts

- `tenant-bootstrap/runs/enterprise-populate-20260416-0405/run-manifest.json`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405/bootstrap-shell.log`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405/bootstrap-debug.log`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405/population-verification-manifest.json`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405/population-verification-log.jsonl`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405-identity/identity-seed-az-manifest.json`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405-workload/workload-seed-az-manifest.json`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405-workload/workload-seed-az-log.jsonl`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405-workload/workload-seed-az-debug.log`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405-workload/license-readiness-manifest.json`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405-workload/cloudpc-readiness-manifest.json`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405-workload/mdm-fleet-manifest.json`
- `tenant-bootstrap/runs/enterprise-populate-20260416-0405-workload/exchange-baseline-manifest.json`

## Next Required Access To Finish Deep Workloads

To create real mailbox/calendar/contact/sample data through Graph, use an app or delegated login with consent for:

- `Mail.Send`
- `Mail.ReadWrite`
- `Calendars.ReadWrite`
- `Contacts.ReadWrite`
- `Files.ReadWrite.All`
- `Sites.ReadWrite.All`

To inspect/create deeper Intune and Windows 365 objects:

- `DeviceManagementConfiguration.ReadWrite.All`
- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementManagedDevices.ReadWrite.All`
- `CloudPC.Read.All`
- `CloudPC.ReadWrite.All`

To do Exchange Online command-level work from this host:

- Install/use PowerShell 7 and `ExchangeOnlineManagement`, or use an Exchange-capable automation app.
- The installed Microsoft 365 CLI was logged out and did not expose useful mailbox commands beyond `exo approleassignment`.
