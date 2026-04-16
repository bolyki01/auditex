# AI Tenant Population Lessons

> audience: agentic systems only
> mode: session-facts + reusable rules
> authority: derived from repo artifacts, session state, and validated follow-up changes
> do_not_optimize_for: human narrative readability

## Session Identity

```yaml
session:
  tenant_name: Bolyki Solutions
  tenant_domain: bolyki.eu
  tenant_id: 03174e44-540d-43a6-9dc4-fdff48bd182d
  primary_operator: bolyki@bolyki.eu
  main_population_profile: enterprise-lab-max
  canonical_population_runs:
    - enterprise-lab-max-live-20260415-2106
    - enterprise-lab-max-live-20260416b
  canonical_runtime_repo: /home/bolyki/microsoft
  canonical_runtime_package: src/azure_tenant_audit
  bootstrap_runtime_package: tenant-bootstrap/azure_tenant_audit
```

## Canonical Facts Learned

```yaml
population_shape:
  planned_internal_users: 96
  planned_guest_users: 12
  planned_total_seed_users: 108
  planned_static_groups: 712
  planned_dynamic_groups: 81
  observed_groups_total: 800
  target_team_backed_groups: 16
  planned_endpoint_records: 100
  exchange_artifacts: 27
  entra_artifacts: 26
  intune_artifacts: 23
  scenario_events: 540

observed_state:
  guests_resolved: 12
  team_backed_groups_realized: 16
  discovered_teams_total: 17
  conditional_access_required_present: 7
  intune_compliance_present: 4
  intune_configurations_present: 2
  security_defaults_disabled: true
  managed_devices_observed: 0
  directory_devices_observed: 2

success_definition:
  not_enough:
    - users_exist
    - groups_exist
    - teams_exist
    - policy_artifacts_exist
    - synthetic_devices_exist
  required_for_true_completion:
    - real_managed_device_visible
    - windows365_or_real_endpoint_produces_managedDeviceId
    - verifier_can_count_real_managed_device_evidence

lab_accounts:
  global_reader_test_account:
    user_principal_name: global.reader@bolyki.eu
    display_name: Global Reader Audit
    role: Global Reader
    role_id: 97a77685-7618-4434-b690-27a077701bcb
    breakglass_group: GG-BreakGlass
    breakglass_group_id: f144621f-1dfe-4dfa-b870-16ee0686e1bd
    force_change_password_next_sign_in: false
    mfa_intent: excluded_for_lab_testing
  named_admin_account:
    user_principal_name: admin.named@bolyki.eu
  daily_ops_account:
    user_principal_name: daily.user@bolyki.eu

lab_app:
  display_name: Bolyki Lab Tenant Populator
  app_id: 0b6f3604-0168-44be-b11b-5ec7cd3428ef
  app_mode: customer-local lab tenant app
  admin_consent_attempted: true
```

## Working Sequences

- `when goal == first-pass audit`: use delegated Azure CLI token reuse before app consent
- `when auth_mode == delegated and no app exists`: `az login --tenant <tenant>` then `auditex --use-azure-cli-token --auditor-profile global-reader`
- `when tenant bootstrap needs enterprise density`: use `tenant-bootstrap/run-enterprise-lab-max.sh`
- `when guest invitations missing`: rerun identity path with guest invite flow, do not rebuild tenant from scratch
- `when Teams-backed M365 groups exist but Teams do not`: convert via `PUT /groups/{id}/team`, then poll, then create channels with retry
- `when Security Defaults blocks CA work`: disable Security Defaults first, then rerun CA creation
- `when Intune policy POST fails on current schema`: sanitize compliance/config payloads to current Graph requirements, then rerun only failed workload slices
- `when W365 managed-device visibility is partial`: trust `windows365-provisioning-manifest.json` `managedDeviceId` if present, not only `/deviceManagement/managedDevices`
- `when lab delegated testing account is needed`: create cloud-only user, assign `Global Reader`, add to `GG-BreakGlass`, verify Security Defaults are off

## Failure Signatures

```yaml
failure_signatures:
  - surface: windows365.virtualEndpoint
    symptom: cloudPCs/provisioningPolicies/userSettings return 403
    error_code_or_http: 403 Forbidden
    meaning: service/api exposure not usable for current tenant/session despite broad roles
    actionable_next_step: treat as service-side blocker, write blocker artifacts, do not claim managed-device success
    is_code_problem: false
    is_service_problem: true

  - surface: intune.managedDevices
    symptom: zero managed devices after broad population pass
    error_code_or_http: no_error_but_zero_state
    meaning: synthetic device plans are not equivalent to enrolled or Cloud PC-backed devices
    actionable_next_step: require real enrollment or successful W365 provisioning
    is_code_problem: false
    is_service_problem: true

  - surface: directory.devices
    symptom: POST /devices returns Authorization_RequestDenied
    error_code_or_http: Authorization_RequestDenied
    meaning: app/delegated path cannot synthesize realistic directory devices through Graph alone
    actionable_next_step: stop treating directory device creation as the primary success path
    is_code_problem: false
    is_service_problem: true

  - surface: onedrive.mysite
    symptom: file write fails with mysite not found
    error_code_or_http: service_not_ready
    meaning: user drive/site provisioning is not ready just because the identity exists
    actionable_next_step: treat sample-data write as readiness-dependent, not guaranteed
    is_code_problem: false
    is_service_problem: true

  - surface: exchange.policy.realization
    symptom: policy creation remains artifact-only
    error_code_or_http: local_tooling_gap
    meaning: Exchange PowerShell path on host not sufficiently ready/authenticated
    actionable_next_step: keep artifacts, do not mislabel as live Exchange policy realization
    is_code_problem: false
    is_service_problem: false

  - surface: auth.helper.env
    symptom: helper wrote empty AZURE_ACCESS_TOKEN
    error_code_or_http: helper_output_bug
    meaning: token helper output cannot be blindly trusted
    actionable_next_step: fetch token directly or validate env file before use
    is_code_problem: true
    is_service_problem: false
```

## Solution Patterns

```yaml
solution_patterns:
  - problem: verifier could not count a real Cloud PC when managedDevices visibility was partial
    what_changed: verifier now reads windows365-provisioning-manifest.json and accepts managedDeviceId as managed evidence
    where_changed:
      - tenant-bootstrap/scripts/verify-population-az.py
      - tenant-bootstrap/tests/test_remaining_population_gaps.py
    verification_evidence:
      - pytest tests/test_remaining_population_gaps.py -q

  - problem: repo runtime drifted between src/ and tenant-bootstrap copy
    what_changed: packaged product wrapper auditex was introduced and canonical runtime declared as src/azure_tenant_audit
    where_changed:
      - src/auditex/
      - docs/specs/2026-04-16-auditex-product-spec.md
      - SOUL.md
    verification_evidence:
      - pytest tests/test_auditex_product.py -q

  - problem: command-level audit trail was mixed into general event log only
    what_changed: canonical runtime now emits audit-command-log.jsonl for command events
    where_changed:
      - src/azure_tenant_audit/output.py
      - tests/test_output.py
    verification_evidence:
      - pytest tests/test_output.py -q

  - problem: bootstrap wrappers could keep using the duplicate runtime even inside the full repo
    what_changed: bootstrap wrapper now prefers repo-root src/azure_tenant_audit before tenant-bootstrap compatibility copy
    where_changed:
      - tenant-bootstrap/scripts/run-audit-collector.sh
      - tests/test_tenant_bootstrap_wrapper.py
    verification_evidence:
      - pytest tests/test_tenant_bootstrap_wrapper.py -q

  - problem: lab delegated audit account would be obstructed by MFA-style CA for testing
    what_changed: created global.reader@bolyki.eu, assigned Global Reader, added to GG-BreakGlass, verified Security Defaults are disabled
    where_changed:
      - .secrets/global-reader-account.json
      - live tenant state
    verification_evidence:
      - session-verified state
```

## Dead Ends

- do not assume app consent alone unlocks Windows 365 virtualEndpoint APIs
- do not count synthetic directory devices as endpoint/MDM success
- do not assume mailbox, OneDrive, or Teams message realism simply because users exist
- do not treat artifact plans as observed tenant state
- do not trust empty token env helper output without validation
- do not use the bootstrap runtime copy as the authoritative product path when repo root is present
- do not call the tenant fully populated while `managedDevices == 0` and no `managedDeviceId` evidence exists

## Decision Rules For Next Tenant

- `if objective == customer audit`: start delegated-first with Global Reader or closest read-only role
- `if delegated path is blocked`: record blockers first; only then justify customer-local read-only app consent
- `if endpoint realism is required`: use real enrolled devices or real Cloud PC evidence; synthetic device plans are insufficient
- `if workload writes fail`: distinguish seat/readiness issues from code defects before changing scripts
- `if CA baseline work is incomplete and Security Defaults are on`: disable or account for Security Defaults before rerunning CA creation
- `if Teams group exists without Team resource`: convert existing M365 group instead of rebuilding identity/group layers
- `if verifier cannot see managedDevices but W365 provisioning artifact has managedDeviceId`: count provisioning artifact as real managed evidence
- `if repo has both src runtime and bootstrap runtime`: treat `src/azure_tenant_audit` as canonical and bootstrap copy as compatibility only
- `if evidence is needed for AI reasoning`: use local artifacts and AI-safe views; keep raw tenant evidence local by default

## Service-Side Blockers

```yaml
service_side_blockers:
  windows365:
    status: unresolved
    blocker: virtualEndpoint APIs return 403 despite broad app roles
    implication: no real Cloud PC evidence, no managedDeviceId, no managed-device completion

  exchange_live_policy_realization:
    status: unresolved
    blocker: local Exchange PowerShell path not fully usable for real policy commands
    implication: Exchange posture remains partly artifact-backed

  mailbox_and_drive_realism:
    status: constrained
    blocker: seat availability and workload provisioning readiness
    implication: broad sample-data realism is not guaranteed
```

## Artifacts To Trust

- `tenant-bootstrap/runs/*/population-verification-manifest.json`
- `tenant-bootstrap/runs/*/population-verification-log.jsonl`
- `tenant-bootstrap/runs/*/identity-seed-az-manifest.json`
- `tenant-bootstrap/runs/*/workload-seed-az-manifest.json`
- `tenant-bootstrap/runs/*/windows365-readiness-manifest.json`
- `tenant-bootstrap/runs/*/windows365-blocker-manifest.json`
- `tenant-bootstrap/runs/*/exchange-baseline-manifest.json`
- `tenant-bootstrap/runs/*/license-readiness-manifest.json`
- `audit-log.jsonl`
- `audit-command-log.jsonl`
- `run-manifest.json`

## Artifacts To Distrust

- synthetic device plan/manifests as proof of real MDM success
- any artifact whose meaning is only `planned` but is read as `observed`
- `.secrets/lab-populator-token.env` when not independently validated
- directory device counts as proxy for Intune managed-device success
- any “tenant fully populated” claim that lacks managed-device evidence

## Next-Time Execution Order

1. verify tenant identity, domain, current auth mode, and active seats
2. run delegated-first baseline audit with `global-reader` profile
3. classify blockers before any escalation
4. validate or populate identity, guests, and group topology
5. validate security defaults and CA interaction
6. realize Teams-backed groups and policy artifacts
7. validate Intune policy creation against current Graph schema
8. test W365 or real managed-device path explicitly
9. run verifier and require real managed-device evidence for completion
10. escalate to customer-local read-only app only if blocker evidence justifies it
