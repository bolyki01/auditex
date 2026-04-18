from __future__ import annotations

from typing import Any


_DISPLAY_NAME_KEYS = (
    "display_name",
    "principal_name",
    "site_name",
    "policy_name",
    "title",
    "service_principal_name",
    "target_name",
)


def build_friendly_name_catalog(records_by_section: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], int]:
    catalog: dict[str, dict[str, Any]] = {}
    warnings = 0
    for section, records in records_by_section.items():
        for record in records:
            object_id = str(record.get("id") or "")
            if not object_id:
                continue
            display_name = _resolve_display_name(record)
            if not display_name:
                warnings += 1
                continue
            object_kind = str(record.get("kind") or section.rstrip("s"))
            key = f"translation:{object_kind}:{object_id}"
            catalog[key] = {
                "key": key,
                "object_kind": object_kind,
                "object_id": object_id,
                "display_name": display_name,
                "source_section": section,
            }
    return sorted(catalog.values(), key=lambda item: item["key"]), warnings


def _resolve_display_name(record: dict[str, Any]) -> str | None:
    for key in _DISPLAY_NAME_KEYS:
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None
