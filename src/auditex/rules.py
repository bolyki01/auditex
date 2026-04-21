from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any


DEFAULT_RULE_PACKS_PATH = Path(__file__).resolve().parents[2] / "configs" / "rule-packs.json"


def _read_rules(path: Path) -> list[Mapping[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return []
    rows = payload.get("rules") if isinstance(payload, Mapping) else []
    return [row for row in rows if isinstance(row, Mapping)] if isinstance(rows, list) else []


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(item) for item in value if item is not None})


def _rule_row(item: Mapping[str, Any]) -> dict[str, Any] | None:
    name = str(item.get("name") or "").strip()
    if not name:
        return None
    return {
        "name": name,
        "title": item.get("title"),
        "description": item.get("description"),
        "tags": _string_list(item.get("tags")),
        "path": str(item.get("path") or ""),
        "enabled": bool(item.get("enabled", True)),
        "product_family": str(item.get("product_family") or ""),
        "license_tiers": _string_list(item.get("license_tiers")),
        "audit_levels": _string_list(item.get("audit_levels")),
    }


def _matches(row: Mapping[str, Any], *, tag: str | None, path_prefix: str | None, product_family: str | None, license_tier: str | None, audit_level: str | None) -> bool:
    if tag and tag not in row.get("tags", []):
        return False
    if path_prefix and str(row.get("path") or "") and not str(row.get("path")).startswith(path_prefix):
        return False
    if product_family and row.get("product_family") != product_family:
        return False
    if license_tier and license_tier not in row.get("license_tiers", []):
        return False
    if audit_level and audit_level not in row.get("audit_levels", []):
        return False
    return True


def list_rule_inventory(
    *,
    path: Path | None = None,
    tag: str | None = None,
    path_prefix: str | None = None,
    product_family: str | None = None,
    license_tier: str | None = None,
    audit_level: str | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in _read_rules(path or DEFAULT_RULE_PACKS_PATH):
        row = _rule_row(item)
        if row is not None and _matches(
            row,
            tag=tag,
            path_prefix=path_prefix,
            product_family=product_family,
            license_tier=license_tier,
            audit_level=audit_level,
        ):
            rows.append(row)
    return sorted(rows, key=lambda row: row["name"])
