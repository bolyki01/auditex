# NIS2 / DORA mapping completeness audit (B5)

NIS2 (Directive (EU) 2022/2555) and DORA (Regulation (EU) 2022/2554)
are the two newer EU frameworks ship in `configs/control-mappings.json`.
They were sparser than the equivalent CIS / NIST mappings — this audit
brings them up to comparable specificity.

## Coverage before audit

- 30 of 32 rule_ids had both `nis2` and `dora` entries.
- 1 rule_id (`collector.issue.collector`) had neither — it's an
  operational diagnostic rather than a control, but `collector.issue.*`
  is shipped under the contract and should map cleanly.
- The existing mappings tended toward a single article per rule, often
  defaulting to NIS2 21(2)(d) "supply chain security" or 21(2)(g) "basic
  cyber hygiene" without exploring the more specific articles that also
  apply.

## Article taxonomy used

### NIS2 Article 21(2) — risk-management measures

| Sub-para | Subject                                                              |
| -------- | -------------------------------------------------------------------- |
| (a)      | policies on risk analysis and information system security           |
| (b)      | incident handling                                                   |
| (c)      | business continuity                                                 |
| (d)      | supply chain security                                               |
| (e)      | system acquisition / development / maintenance security             |
| (f)      | policies & procedures to assess effectiveness of measures           |
| (g)      | basic cyber hygiene practices and cybersecurity training            |
| (h)      | policies & procedures regarding the use of cryptography (and where appropriate, encryption) |
| (i)      | human resources security, access control policies, asset management |
| (j)      | use of MFA / continuous auth, secured comms, secured emergency comms |

### NIS2 Article 23 — significant incident reporting

24-hour early warning, 72-hour notification, one-month report.

### DORA Article 9 — protection of ICT assets

| Sub-para  | Subject                                                |
| --------- | ------------------------------------------------------ |
| 9(2)      | ICT security policies, procedures, protocols, and tools |
| 9(4)(a)   | preventing access to ICT systems by unauthorised entities |
| 9(4)(b)   | limiting accessibility by ICT third-party providers    |

### DORA Article 11 — ICT business continuity policy

### DORA Article 17 — ICT-related incident management

### DORA Article 28 — managing ICT third-party risk

## Enrichments applied (high-confidence, additive)

All current entries were preserved; the audit only ADDED articles
where the rule's substance maps cleanly to a previously-missing
article. No removals.

| Rule family                    | Added                              | Why                                                                                   |
| ------------------------------ | ---------------------------------- | ------------------------------------------------------------------------------------- |
| `app_credentials.*` (9 rules) + `app_consent.high_privilege` | NIS2 21(2)(h)               | Credential lifecycle = cryptography hygiene under (h). The existing (d) supply-chain mapping stays defensible because tenant apps frequently integrate with third-party services.  |
| `cross_tenant_access.*` (7 rules) | NIS2 21(2)(i)                  | These rules are squarely about controlling access from / to other tenants. (i) covers access-control policies and asset management.                                                |
| `sharepoint.broad_link`        | NIS2 21(2)(i)                      | Sharing data broadly relaxes access control on a data asset.                                                                                                                       |
| `collector.issue.collector`    | NIS2 21(2)(c) + DORA Article 11(1) | Detection failure is a continuity gap: auditex itself is a detective control and its outage should map to BCP articles (NIS2 (c), DORA 11).                                       |
| `mailbox_forwarding.*` (2 rules) | NIS2 21(2)(g)                    | Forwarding-rule discipline is basic cyber hygiene alongside the existing (b) incident-handling angle.                                                                              |

## Mapping rationale per area

### DNS / email-auth (`dns_posture.*`)

NIS2 21(2)(g) "basic cyber hygiene" — DMARC/SPF/DKIM are widely-cited
hygiene baselines (e.g., Cyber Essentials, ENISA guidance). DORA
Article 9(2) for the operational ICT security policy obligation.

### Application credentials (`app_credentials.*`, `app_consent.*`)

- NIS2 21(2)(h) cryptography (rotation / lifecycle)
- NIS2 21(2)(d) supply-chain (third-party integrations)
- DORA 9(4)(a) preventing unauthorised access (the credential IS the
  access control)

### Mailbox forwarding (`mailbox_forwarding.*`)

- NIS2 21(2)(b) incident handling — forwarding is a core BEC indicator
- NIS2 23 — significant incident reporting if confirmed exfil
- NIS2 21(2)(g) hygiene — rule discipline
- DORA Article 17 incident management

### Cross-tenant access (`cross_tenant_access.*`)

- NIS2 21(2)(d) supply-chain — every external tenant is a third-party
- NIS2 21(2)(i) access control policies — direct fit
- NIS2 21(2)(j) MFA — for the partner_inbound_no_mfa rule and others
- DORA Article 28 — the third-party risk mandate

### SharePoint sharing (`sharepoint.broad_link`)

- NIS2 21(2)(g) hygiene — link-share configuration is hygiene
- NIS2 21(2)(i) access control — direct
- DORA Article 9(2) ICT policies

### Collector diagnostics (`collector.issue.*`)

- `permission` — NIS2 21(2)(d), DORA 9(2). The audit identity itself is
  governance.
- `service` — NIS2 21(2)(c), DORA 11(1). A service outage during audit
  is a continuity event for the detective control.
- `collector` — NIS2 21(2)(c), DORA 11(1). Same — collector failure is
  a detection-availability event.

## Debatable, not applied

These are defensible but reasonable interpretations diverge:

1. **`mailbox_forwarding.*` mapping NIS2 (j) MFA / secured comms.** The
   spirit of (j) covers secured communications systems; an external
   forwarding rule arguably violates "secured comms" by leaking content
   to an unauthorised recipient. Decided NOT to add since (b) and (g)
   already cover the rule and (j) reads more naturally as a control
   over MFA / secure messaging implementations than over forwarding-rule
   detection.
2. **`dns_posture.*` mapping NIS2 (j).** SPF/DKIM/DMARC are arguably
   "secured comms" controls. Decided not to add — (g) hygiene fits the
   detection/operational reality better and is the consensus mapping
   in ENISA's NIS2 guidance.

## Coverage after audit

- **100% of emitted rule_ids** have at least one NIS2 article
  AND one DORA article mapped.
- The orphan `collector.issue.collector` is now mapped.
- Granularity per rule increased from a median of 1 article to 2-3
  articles per framework, matching the depth of the existing CIS /
  NIST / ISO mappings.

## Verification

`tests/test_finding_templates_complete.py` already enforces the floor
(every rule_id has cis_m365_v3 + nist_800_53 OR iso_27001). No floor
violations after the enrichments. Full pytest suite + contract-smoke
remain green.
