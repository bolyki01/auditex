# Competitor Research Pack

Auditex keeps the cloned upstream repos outside git and keeps the analysis pack in-tree.

- Local mirror root: `/Users/bolyki/dev/library/auditex/competitors/repos`
- Docs root: `/Users/bolyki/dev/source/auditex/docs/research`

Refresh commands:

```bash
auditex research competitors sync
auditex research competitors pack
```

Target repos:

- `cisagov/ScubaGear` at `f5d7edcaf3a6009b3d52c49f2664d71864a3c0a3`
- `maester365/maester` at `d39cf580e29b1e4af8095f7544db34fdb866a707`
- `microsoft/EntraExporter` at `ce0d04cf096611183258d65a8e5aa487c55a1f5f`
- `dirkjanm/ROADtools` at `e6ed3c10373f2a15d920bcaa82f2236a4a461b38`
- `ThomasKur/M365Documentation` at `13a9aa34ff6b8c295926c5ae1a8f2ad54727f143`
- `System-Admins/m365assessment` at `7aa59a7d5277afe1b47f450cb55d5f89f06d32de`
- `CompliantSec/M365SAT` at `a1fdec4a95571989b26103a2079fc5f35bccfd75`

Pack contents:

- `competitor-matrix.md`: one-row matrix per upstream.
- `repo-cards.md`: exact paths and direct port slices per upstream.
- `steal-backlog.md`: ranked `now`, `next`, `later`, and `avoid` backlog.
