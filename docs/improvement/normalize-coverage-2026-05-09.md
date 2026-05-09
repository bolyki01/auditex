# Normalize section coverage audit (A7)

This audit maps every collector in `REGISTRY` to its consumer in
`src/azure_tenant_audit/normalize.py`. A collector with **no** consumer means
its payload is captured in raw evidence but never indexed in the evidence DB
or surfaced in the report-pack — a downstream consumer gap.

## Result (post-A7)

| Collector              | Consumed by normalize? | Section(s)                                                                                                |
| ---------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------- |
| identity               | yes                    | users, groups, applications, service_principals, role_definitions, role_assignments                       |
| app_consent            | yes                    | application_consents                                                                                      |
| app_credentials        | yes                    | application_credential_objects, service_principal_credential_objects                                      |
| security               | **no (by design)**     | sign-ins / directory-audits — too noisy to flatten; raw evidence files only. See exceptions below.        |
| conditional_access     | yes                    | policies, conditional_access_graph, ca_findings, relationships                                            |
| consent_policy         | yes                    | consent_policy_objects                                                                                    |
| cross_tenant_access    | yes                    | cross_tenant_default_objects, cross_tenant_partner_objects                                                |
| defender               | yes                    | incidents, security_scores                                                                                |
| dns_posture            | yes                    | dns_posture_objects                                                                                       |
| domains_hybrid         | yes                    | domain_hybrid_objects                                                                                     |
| auth_methods           | yes                    | (consumed by conditional_access_graph builder)                                                            |
| external_identity      | yes                    | external_identity_objects                                                                                 |
| intune                 | yes                    | (consumed via devices + conditional_access_graph)                                                         |
| intune_depth           | yes                    | intune_assignment_objects                                                                                 |
| licensing              | yes                    | license_inventory                                                                                         |
| mailbox_forwarding     | yes                    | inbox_rule_objects, mailbox_setting_objects                                                               |
| identity_governance    | yes                    | governance_objects                                                                                        |
| onedrive_posture       | yes                    | onedrive_posture_objects                                                                                  |
| power_platform         | **yes (NEW in A7)**    | power_platform_environment_objects, power_platform_dlp_policy_objects, power_platform_tenant_setting_objects |
| sentinel_xdr           | **yes (NEW in A7)**    | sentinel_xdr_incident_objects, sentinel_xdr_alert_objects                                                 |
| defender_cloud_apps    | **yes (NEW in A7)**    | defender_cloud_apps_profile_objects, defender_cloud_apps_consent_objects                                  |
| copilot_governance     | **yes (NEW in A7)**    | copilot_admin_setting_objects, copilot_usage_objects                                                      |
| sharepoint             | yes                    | sites, sharepoint_site_posture_objects, sharepoint_permission_edges, sharepoint_sharing_findings          |
| sharepoint_access      | yes                    | (consumed via sharepoint_permission_edges)                                                                |
| teams                  | **no (by design)**     | teams data overlaps with `groups` (Microsoft 365 groups w/ Team flag); raw evidence accessible.           |
| teams_policy           | yes                    | teams_policy_objects                                                                                      |
| reports_usage          | yes                    | usage_report_objects                                                                                      |
| service_health         | yes                    | service_health_objects                                                                                    |
| exchange               | yes                    | mailboxes                                                                                                 |
| exchange_policy        | yes                    | exchange_policy_objects                                                                                   |
| purview                | yes                    | purview_audit_jobs, purview_audit_exports, purview_retention_labels, purview_retention_policies, purview_dlp_policies |
| ediscovery             | yes                    | ediscovery_cases, ediscovery_searches, ediscovery_export_jobs, ediscovery_review_sets                     |

## Exceptions (intentionally not normalized)

Two collectors emit data that is **deliberately** kept as raw evidence only:

- **`security`** — sign-in logs and directory audits can be hundreds of thousands
  of records on a busy tenant. Flattening into `normalized_records` would explode
  the evidence DB. Consumers that need these read the raw collector chunks on
  disk under the bundle's `chunks/` directory.
- **`teams`** — the team-group inventory overlaps with `groups` (Microsoft 365
  groups with the Team `resourceProvisioningOptions` flag). Adding a separate
  section duplicates data without adding signal. Per-team channel info is
  available as raw evidence.

The coverage test (`tests/test_normalize_coverage.py`) enforces this list — any
new collector added to the registry without either a normalize consumer or an
exceptions-list entry will fail the build.

## Pre-A7 gap

Pre-A7, the four gated collectors emitted data that vanished into raw evidence
files only. On a tenant licensed for any of them, the data was unindexed and
unreportable. A7 closes the loop by adding minimal record-flattening so the
evidence DB and report-pack pick the data up automatically when the underlying
service is provisioned.
