from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_RULE_PACKS_PATH = Path(__file__).resolve().parents[2] / "configs" / "rule-packs.json"


def list_rule_inventory(
    *,
    path: Path | None = None,
    tag: str | None = None,
    path_prefix: str | None = None,
    product_family: str | None = None,
    license_tier: str | None = None,
    audit_level: str | None = None,
) -> list[dict[str, Any]]:
    target = path or DEFAULT_RULE_PACKS_PATH
    if not target.exists():
        return []
    payload = json.loads(target.read_text(encoding="utf-8"))
    rules = payload.get("rules", [])
    if not isinstance(rules, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in rules:
        if not isinstance(item, dict):
            continue
        row = {
            "name": str(item.get("name") or ""),
            "title": item.get("title"),
            "description": item.get("description"),
            "tags": sorted({str(tag_item) for tag_item in item.get("tags", []) if tag_item is not None}),
            "path": str(item.get("path") or ""),
            "enabled": bool(item.get("enabled", True)),
            "product_family": str(item.get("product_family") or ""),
            "license_tiers": sorted({str(value) for value in item.get("license_tiers", []) if value is not None}),
            "audit_levels": sorted({str(value) for value in item.get("audit_levels", []) if value is not None}),
        }
        if not row["name"]:
            continue
        if tag and tag not in row["tags"]:
            continue
        if path_prefix and row["path"] and not row["path"].startswith(path_prefix):
            continue
        if product_family and row["product_family"] != product_family:
            continue
        if license_tier and license_tier not in row["license_tiers"]:
            continue
        if audit_level and audit_level not in row["audit_levels"]:
            continue
        rows.append(row)
    return sorted(rows, key=lambda item: item["name"])
