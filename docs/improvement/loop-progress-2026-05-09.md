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
