# Taint Review

This folder records source-taint and license-taint risk in `auditex`.

Use it for one job:
- show which upstreams were targeted
- show which `auditex` surfaces look touched
- separate high-risk taint from lower-risk permissive influence

Terms used here:
- `tainted`: repo records direct port/copy intent from that upstream
- `high risk`: GPL, no-license, or unclear-rights source
- `notice risk`: permissive source that may still need attribution if real code or text was copied
- `sampled only`: no full legal code-compare was done yet

Current blunt state:
- `ThomasKur/M365Documentation` is `GPLv3+`
- `System-Admins/m365assessment` has no visible license file
- both are treated here as high-risk taint sources for a proprietary product

Current repo state:
- mapped high-risk product surfaces were rewritten
- `docs/research/` is gone from the tracked product tree
- this folder stays as a private compliance record

Read next:
- [upstream-risk-matrix.md](./upstream-risk-matrix.md)
- [auditex-surface-map.md](./auditex-surface-map.md)
- [evidence.md](./evidence.md)
- [clean-room-remediation.md](./clean-room-remediation.md)
- [history-remediation.md](./history-remediation.md)
