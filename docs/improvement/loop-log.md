# Auditex polish loop — log

Branch: `chore/auditex-polish-2026-05-09`
Started: 2026-05-09

| When  | Task | Result | Data delta | Commit |
| ----- | ---- | ------ | ---------- | ------ |
| 00:00 | A1   | green  | dns_posture rules 5→9; tests +57 | e9ca7d8 |
| 00:25 | A2   | green  | tiered DKIM probe; tests +4    | 3eba33e |
| 00:30 | hyg  | green  | untrack .claude/; ignore .venv*/ | 62add24 |
| 01:00 | A3   | green  | app_credentials rules 5→9; tests +9 | 6210f36 |
| 01:25 | A4   | green  | mailbox forward casing/display-name; tests +7 | 00b7ff5 |
| 01:50 | A5   | green  | cross_tenant rules 3→7; auto-consent; tests +5 | dfe77f1 |
| 02:05 | A6   | green  | gated shape parity tests (no code change); +12 | 019e19e |
| 02:30 | A7   | green  | gated normalize sections + coverage lock; +8 | a2f5ae0 |
| 02:50 | B1+B2| green  | template+mapping floor regression; +90 | eb00213 |
| 03:05 | C1   | green  | finalize idempotent (2 real fixes); +3 | d0df9c3 |
| 03:25 | C2   | green  | evidence DB hard-reset (real fix); +4 | d39221a |
| 03:45 | C3   | green  | 3 new validators (dup-key/unknown-collector/framework); +9 | 70ad740 |
| 04:00 | C4   | green  | contract-bump checklist (docs only)        | e8126c8 |
| 04:20 | B3   | green  | ATT&CK calibration: 6 mappings + spec swaps + rationale | f7392ef |
| 04:35 | B4   | green  | severity calibration audit (no source changes) | 7958036 |
| 04:50 | B5   | green  | NIS2/DORA enrichment to 100% coverage     | 6441c1a |
| 05:10 | D1   | green  | SARIF help.markdown + helpUri; tests +3 | 4d354f4 |
| 05:25 | D2   | green  | SARIF stable fingerprints (auditex/v1); tests +3 | 13e05e2 |
| 05:40 | D3   | green  | OSCAL reviewed-controls fix (real bug); tests +3 | f484008 |
| 06:00 | D4   | green  | CSV deterministic sort (real fix); tests +7 | 5c20e4b |
| 06:15 | D5   | green  | JSON trailing newline + stability; tests +7 | 5f21a7d |
