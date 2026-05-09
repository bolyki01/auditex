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

---

## Checkpoint 3 — Phase C done

**Completed (4 functional commits):**
- C1 idempotent finalize: TWO real bugs fixed — `_artifact_map` insertion-order leak and finalize-sequencing mismatch. Re-finalising a clean bundle is now byte-stable for the 4 deterministic JSON artifacts plus logically-stable for `evidence.sqlite`.
- C2 evidence-DB migration: ONE real bug fixed — foreign tables/indexes from prior auditex releases survived rebuild because DROP TABLE only enumerated 3 canonical tables. Fix: hard-reset target file (incl. WAL/SHM/journal sidecars) before SQLite reopens.
- C3 validation.json error coverage: 3 new failure-mode validators (`duplicate_record_key`, `unknown_finding_collector`, `unknown_framework_mapping_key` + `invalid_framework_mapping_value`). Caught one design-edge case along the way (the response plane uses `collector="response"` by intent) and added an explicit allow-list rather than a typo-prone regex.
- C4 contract-bump checklist: documents every site that must change when CONTRACT_VERSION leaves "2026-04-21". Read once, copy-paste during the next bump.

**Data-quality wins:**
- Real bug count fixed in C-phase: 3 (`_artifact_map` ordering, finalize sequencing, evidence DB rebuild leak).
- Test count: 563 → 588 (+25 over the C-phase).
- 7 new validators total (3 in C3 + the 4 idempotency/migration tests).

**Blockers:** none.

**Next:** B3 (MITRE ATT&CK tag review), B4 (severity calibration spreadsheet), B5 (NIS2/DORA mapping completeness), then D exporters polish, then E-K.

---

## Checkpoint 4 — Phases B (B3-B5) + D done

**Completed since last checkpoint (8 functional commits):**
- B3 ATT&CK calibration: 6 missing mappings filled; spec-driven swaps (T1566.001 → T1566.002 on 4 DNS rules); 3 spec-prescribed additions; rationale block.
- B4 severity calibration audit: no obvious miscalibrations; 2 debatable cases queued.
- B5 NIS2/DORA enrichment: coverage 100%; granularity 1 → 2-3 articles per rule.
- D1 SARIF help.markdown + helpUri (GitHub Code Scanning UI).
- D2 SARIF stable fingerprints (auditex/v1) — dedup across runs.
- D3 OSCAL reviewed-controls fix (REAL bug — OSCAL 1.1.2 mandate).
- D4 CSV deterministic sort (REAL fix — was input-order-dependent).
- D5 JSON trailing newline + stability test.

**Data-quality wins:**
- Real bugs fixed in this stretch: 2 (OSCAL reviewed-controls missing, CSV sort drift).
- Total real bugs fixed cumulatively: 5.
- Test count: 579 → 602 (+23).
- Total branch commits: 70+ (16+ functional, rest chores/logs).

**Blockers:** none.

**Next:** E-phase notify sink reliability (Jira/GitHub dedup, SMTP TLS strict, Teams/Slack redaction) → F-phase CI/Actions → G-phase tests/safety nets → H-phase perf → I-phase security → J-phase maintenance → K-phase research.



