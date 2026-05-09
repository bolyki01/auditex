# Severity calibration audit (B4)

Walked every emitted `rule_id` and rated its current severity against:

- the CIS Microsoft 365 Foundations Benchmark v3 impact tier,
- the underlying threat model (exploitability × business impact),
- operational signal-to-noise (alerts that fire too often get ignored).

**Result:** no obvious miscalibrations. The current severities are
internally consistent and align with CIS guidance plus Microsoft Entra
UX expectations. Two debatable cases are queued for human review
(see "Debatable, queued" section below) — those are NOT changed in
this iteration to preserve test baselines and consumer dashboards.

## Calibration table

| rule_id                                                       | current  | proposed | rationale                                                                                                                                                                                  |
| ------------------------------------------------------------- | -------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| dns_posture.spf_missing                                       | high     | high     | CIS 4.4 (Level 2). No SPF = trivially-spoofable domain. High is the standard call.                                                                                                          |
| dns_posture.spf_passthrough                                   | high     | high     | `+all` / `?all` is functionally "no SPF". Same severity as missing.                                                                                                                         |
| dns_posture.spf_multiple_records                              | high     | high     | RFC 7208 §4.5 PermError → both records ineffective. Same posture as no-SPF.                                                                                                                 |
| dns_posture.dmarc_missing                                     | high     | high     | CIS 4.6 (Level 2). Domain spoofable with no operator visibility.                                                                                                                            |
| dns_posture.dmarc_monitor_only                                | medium   | medium   | DMARC is published but not enforced (`p=none`). Reduces blast radius vs missing DMARC; CIS 4.6 calls for "quarantine" or "reject".                                                          |
| dns_posture.dmarc_pct_partial                                 | medium   | medium   | Enforcing policy on a fraction of mail (pct<100). Documented bypass — but the policy IS enforcing on the rest. Medium tracks DMARC monitor-only naturally.                                  |
| dns_posture.dmarc_rua_invalid                                 | low      | low      | Reporting-pipeline gap, not a direct compromise. The DMARC enforcement still works.                                                                                                         |
| dns_posture.dkim_missing                                      | medium   | medium   | DMARC can pass via SPF alignment alone, so DKIM gap is partial. Medium.                                                                                                                     |
| dns_posture.bimi_logo_insecure                                | low      | low      | Brand-indicator visibility, not a control. Low is appropriate.                                                                                                                              |
| mailbox_forwarding.external_inbox_rule                        | critical | critical | CIS 6.2.1 (Level 1). The single highest-confidence BEC indicator on M365. Critical.                                                                                                         |
| mailbox_forwarding.hide_from_user                             | high     | high     | Strong BEC signal but the rule alone may be benign (a user routing newsletters to RSS). High balances signal/noise; arguments exist for critical — queued for review.                       |
| app_consent.high_privilege                                    | high     | high     | CIS 5.2.5 (Level 2). Application granted directory/mail/files write tenant-wide. High is the standard call.                                                                                 |
| app_credentials.secret_expired                                | critical | critical | Microsoft Entra UX surfaces this as a critical alert. Defensible at high too (queued — see below) but baselines + tests assert critical.                                                    |
| app_credentials.secret_expiring                               | high     | high     | Same control as secret_expired with rotation lead time. High prompts proactive rotation.                                                                                                    |
| app_credentials.certificate_expired                           | high     | high     | Cert rotation has more lead-time visibility; downstream auth fails on expiry. High.                                                                                                         |
| app_credentials.certificate_expiring                          | medium   | medium   | 30-day window. Not broken yet but needs a calendar entry. Medium.                                                                                                                           |
| app_credentials.secret_long_validity                          | high     | high     | Secrets > 2 years bypass Entra's default cap. Documented supply-chain compromise root cause.                                                                                                |
| app_credentials.credential_dormant                            | low      | low      | Best-effort hint when signInActivity confirms no use. Low to avoid noise on rarely-used apps.                                                                                               |
| app_credentials.redirect_insecure                             | high     | high     | HTTP redirect can leak authorization codes / tokens (OAuth 2.0 BCP). High.                                                                                                                  |
| app_credentials.no_owner                                      | medium   | medium   | Governance gap. App still functional. Medium.                                                                                                                                               |
| app_credentials.multi_tenant_audience                         | medium   | medium   | Wider audience but not direct compromise. Medium with rationale in the template.                                                                                                            |
| cross_tenant_access.default_b2b_collaboration_inbound_open    | high     | high     | Default-allow inbound from any tenant — unconditioned external access. High.                                                                                                                |
| cross_tenant_access.default_b2b_collaboration_outbound_open   | medium   | medium   | Outbound is governance, not direct compromise. Medium.                                                                                                                                      |
| cross_tenant_access.default_b2b_direct_connect_inbound_open   | high     | high     | Shared-channel inbound = native Teams identity for any external. High.                                                                                                                      |
| cross_tenant_access.default_b2b_direct_connect_outbound_open  | medium   | medium   | Outbound DC. Medium.                                                                                                                                                                        |
| cross_tenant_access.auto_user_consent_inbound_enabled         | medium   | medium   | Removes per-app consent prompt for inbound external. Real risk but governance-bounded.                                                                                                      |
| cross_tenant_access.auto_user_consent_outbound_enabled        | low      | low      | Outbound auto-consent. Lower because the data is in the external tenant, not yours.                                                                                                         |
| cross_tenant_access.partner_inbound_no_mfa                    | high     | high     | Per-partner Direct Connect without inbound MFA trust. High.                                                                                                                                 |
| sharepoint.broad_link                                         | high     | high     | "Anyone with the link" sharing. Common ransomware-precursor. High.                                                                                                                          |

## Debatable, queued for human review

These are defensible at the current severity but reasonable people
disagree. Not changed in this iteration to keep baselines and
downstream dashboards stable.

1. **`app_credentials.secret_expired = critical`** — the loop A3 spec
   suggested `high`, the project ships `critical`. Critical is
   defensible because Microsoft Entra UX, CIS Microsoft 365 v3 §5.1.5,
   and Defender for Cloud Apps all flag expired credentials as
   critical-priority. High would also be defensible (the credential
   simply doesn't work; immediate compromise risk is bounded). Either
   choice is consistent. Decision should be made by the user / project
   owner; existing tests assert `critical`.
2. **`mailbox_forwarding.hide_from_user = high`** — strong BEC pattern,
   but a user routing newsletters or mailing-list traffic to RSS
   without bad intent triggers the same rule. High avoids alert
   fatigue; critical would be defensible inside an active IR engagement
   where any auto-hide is treated as suspicious. Suggest: keep at high
   for steady-state audits; consider an `--incident-mode` flag in a
   future release that raises this rule to critical (and others — TBD).

## Methodology

For each rule_id we asked four questions:

1. What CIS Microsoft 365 v3 control number does this map to, and what
   is its impact tier (Level 1 / Level 2 / etc.)?
2. What's the worst-case adversarial outcome if the control is
   absent? (account takeover? data exfil? brand-spoofing?)
3. How likely is the rule to fire on a benign tenant (false-positive
   rate)? Higher false-positive rate → lower severity to avoid fatigue.
4. Does the existing severity match the median expectation of CIS,
   Microsoft, and Defender for Cloud Apps?

When all four answers aligned with the current severity, no change.
When they pulled in opposite directions, the case was queued for human
review rather than ratcheting either way silently.

## Future calibrations to consider

- **Conditional Access posture rules** are not yet in the registry but
  will be (legacy auth, missing MFA, broken session policies). When
  added, they should anchor at high/critical per CIS §1.x impact tier.
- **B5 NIS2/DORA mapping completeness** (next loop iteration) may
  surface rules where the regulatory mapping suggests a sharper
  severity than the technical mapping does — re-review then.
- **Severity bands per profile** (e.g. `auditor-profile=lab`,
  `auditor-profile=production`) — not in scope for this audit, but a
  natural extension if user feedback suggests the same rule deserves
  different severities in different audit contexts.
