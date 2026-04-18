from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any


def load_waivers(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("waivers", payload if isinstance(payload, list) else [])
    if not isinstance(rows, list):
        return []
    return [item for item in rows if isinstance(item, dict)]


def apply_waivers(findings: list[dict[str, Any]], waiver_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    applied: list[dict[str, Any]] = []
    for finding in findings:
        updated = dict(finding)
        waiver = _match_waiver(updated, waiver_rows)
        if waiver:
            updated["status"] = "accepted_risk"
            updated["waiver_applied"] = True
            updated["waiver"] = waiver
        applied.append(updated)
    return applied


def _match_waiver(finding: dict[str, Any], waiver_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    finding_id = str(finding.get("id") or "")
    rule_id = str(finding.get("rule_id") or "")
    collector = str(finding.get("collector") or "")
    category = str(finding.get("category") or "")

    exact_finding: list[dict[str, Any]] = []
    exact_rule: list[dict[str, Any]] = []
    collector_rows: list[dict[str, Any]] = []
    category_rows: list[dict[str, Any]] = []
    for row in waiver_rows:
        if _is_expired(row):
            continue
        if row.get("finding_id") == finding_id:
            exact_finding.append(row)
        elif row.get("rule_id") == rule_id and rule_id:
            exact_rule.append(row)
        elif row.get("collector") == collector and collector:
            collector_rows.append(row)
        elif row.get("category") == category and category:
            category_rows.append(row)

    for matches in (exact_finding, exact_rule, collector_rows, category_rows):
        if matches:
            return matches[0]
    return None


def _is_expired(row: dict[str, Any]) -> bool:
    value = row.get("expires_on")
    if not value:
        return False
    try:
        return date.fromisoformat(str(value)) < date.today()
    except ValueError:
        return False
