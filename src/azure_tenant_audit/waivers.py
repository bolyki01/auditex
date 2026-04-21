from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any


_MATCH_FIELDS = ("finding_id", "rule_id", "collector", "category")
_STATUS_ACCEPTED_RISK = "accepted_risk"


def load_waivers(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return []

    rows = payload.get("waivers") if isinstance(payload, Mapping) else payload
    if not isinstance(rows, list):
        return []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _expired(row: Mapping[str, Any]) -> bool:
    raw_value = row.get("expires_on") or row.get("expires")
    if not raw_value:
        return False
    try:
        return date.fromisoformat(str(raw_value)) < date.today()
    except ValueError:
        return False


def _match_score(finding: Mapping[str, Any], waiver: Mapping[str, Any]) -> int:
    for score, field in enumerate(_MATCH_FIELDS, start=1):
        wanted = waiver.get(field)
        if wanted is None or wanted == "":
            continue
        actual = finding.get("id") if field == "finding_id" else finding.get(field)
        if str(actual or "") == str(wanted):
            return len(_MATCH_FIELDS) - score + 1
    return 0


def _best_waiver(finding: Mapping[str, Any], waiver_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    best_score = 0
    best_row: dict[str, Any] | None = None
    for row in waiver_rows:
        if _expired(row):
            continue
        score = _match_score(finding, row)
        if score > best_score:
            best_score = score
            best_row = row
    return dict(best_row) if best_row is not None else None


def apply_waivers(findings: list[dict[str, Any]], waiver_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for finding in findings:
        updated = dict(finding)
        waiver = _best_waiver(updated, waiver_rows)
        if waiver is not None:
            updated["status"] = _STATUS_ACCEPTED_RISK
            updated["waiver_applied"] = True
            updated["waiver"] = waiver
        output.append(updated)
    return output
