# Auditex polish loop — checkpoint 2026-05-09

**Completed (4 functional commits):**
- A1 DNS parsers: RFC fuzz tests + 4 new findings (multiple SPF, DMARC pct partial, rua invalid, BIMI insecure logo).
- A2 DKIM tiered probe: M365 defaults first, fallback selectors only on miss.
- A3 App credentials: split secret/cert; new long-validity + dormant rules.
- A4 Mailbox forwarding: casing/display-name tolerance; coverage for all forward kinds + shared mailbox.

**Data-quality wins:**
- dns_posture rule_ids: 5 → 9.
- app_credentials rule_ids: 5 → 9.
- Test count: 428 → 448 (+20 new); all green; contract-smoke green every commit.

**Blockers:** none. Live signInActivity fetch for the dormant rule is queued (collector enhancement, separate task).

**Next:** A5 cross-tenant access split, A6 capability-gated shape parity, A7 normalize-section gap audit, then B-phase template/mapping completeness.

---

## Checkpoint 2 — phases A + B done

**Completed since last checkpoint (5 functional commits):**
- A5 cross_tenant_access: 4 new specific rule_ids (collab inbound open, DC outbound open, automatic_user_consent inbound/outbound).
- A6 capability_gated shape parity: parametric tests across 4 gated collectors.
- A7 normalize coverage: 6 new sections for power_platform / sentinel_xdr / defender_cloud_apps / copilot_governance + audit doc + lock test.
- B1 finding templates: parametric regression — every rule_id has a template with non-empty risk_rating / description / impact / remediation.
- B2 control mappings: floor (cis_m365_v3 + nist_800_53 OR iso_27001) enforced per rule_id; orphan template/mapping detection included.

**Data-quality wins:**
- Total rule_ids: 19 → 29 (dns +4, app_credentials +4, cross_tenant_access +4, no removals).
- Test count: 428 → 563 (+135).
- Coverage drift now hard-fails the build (normalize coverage + template/mapping floor).

**Blockers:** none.

**Next:** C-phase contract hardening (idempotent finalize, validation error coverage), D exporters polish, then E/F/G/H/I/J/K.

