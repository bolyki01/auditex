---
name: evidence-pack
description: Use when reviewing or handing off an Auditex run and you need to produce the evidence bundle, blocker trail, and machine-readable outputs.
---

# Evidence Pack

## Required artifacts

- `run-manifest.json`
- `summary.json`
- `summary.md`
- `audit-log.jsonl`
- `audit-debug.log`
- `raw/`
- `diagnostics.json` when blockers exist

## Handoff rule

Never summarize an audit without citing the actual artifact paths. If coverage is partial, say so plainly and point to the blocker evidence.
