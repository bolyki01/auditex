from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_records(path: Path) -> tuple[str, list[dict[str, Any]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    kind = str(payload.get("kind") or path.stem)
    records = payload.get("records", [])
    if not isinstance(records, list):
        records = []
    return kind, [item for item in records if isinstance(item, dict)]


def _record_key(record: dict[str, Any], kind: str) -> str:
    return str(record.get("key") or f"{kind}:{record.get('id') or record.get('display_name') or 'unknown'}")


def _records_for_run(run_dir: Path) -> tuple[dict[str, str], dict[str, list[dict[str, Any]]]]:
    normalized_dir = run_dir / "normalized"
    if not normalized_dir.exists():
        return {}, {}

    files: dict[str, str] = {}
    records_by_kind: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(normalized_dir.glob("*.json")):
        kind, records = _load_records(path)
        if not records:
            continue
        files[kind] = path.name
        records_by_kind[kind] = records
    return files, records_by_kind


def _run_metadata(run_dir: Path) -> dict[str, Any]:
    manifest = _load_json(run_dir / "run-manifest.json")
    snapshot = _load_json(run_dir / "normalized" / "snapshot.json")
    snapshot_meta = snapshot if isinstance(snapshot, dict) else {}
    return {
        "path": str(run_dir),
        "tenant_name": manifest.get("tenant_name") or snapshot_meta.get("tenant_name"),
        "tenant_id": manifest.get("tenant_id") or snapshot_meta.get("tenant_id"),
        "run_id": manifest.get("run_id") or snapshot_meta.get("run_id"),
        "created_utc": manifest.get("created_utc"),
        "overall_status": manifest.get("overall_status"),
        "auditor_profile": manifest.get("auditor_profile"),
    }


def diff_run_directories(run_a: str | Path, run_b: str | Path) -> dict[str, Any]:
    left = Path(run_a)
    right = Path(run_b)
    left_files, left_records = _records_for_run(left)
    right_files, right_records = _records_for_run(right)
    left_info = _run_metadata(left)
    right_info = _run_metadata(right)

    compared_files = sorted(set(left_files.values()) | set(right_files.values()))
    changes: dict[str, dict[str, list[dict[str, Any]]]] = {}
    total_added = 0
    total_removed = 0
    total_changed = 0

    for kind in sorted(set(left_records) | set(right_records)):
        before_index = {_record_key(item, kind): item for item in left_records.get(kind, [])}
        after_index = {_record_key(item, kind): item for item in right_records.get(kind, [])}
        added_keys = sorted(set(after_index) - set(before_index))
        removed_keys = sorted(set(before_index) - set(after_index))
        shared_keys = sorted(set(before_index) & set(after_index))
        changed = [
            {"key": key, "before": before_index[key], "after": after_index[key]}
            for key in shared_keys
            if before_index[key] != after_index[key]
        ]
        changes[kind] = {
            "added": [after_index[key] for key in added_keys],
            "removed": [before_index[key] for key in removed_keys],
            "changed": changed,
        }
        total_added += len(added_keys)
        total_removed += len(removed_keys)
        total_changed += len(changed)

    return {
        "run_a": str(left),
        "run_b": str(right),
        "run_a_info": left_info,
        "run_b_info": right_info,
        "compare_context": {
            "same_tenant": (
                bool(left_info.get("tenant_id"))
                and left_info.get("tenant_id") == right_info.get("tenant_id")
            )
            or (
                bool(left_info.get("tenant_name"))
                and left_info.get("tenant_name") == right_info.get("tenant_name")
            ),
        },
        "compared_files": compared_files,
        "summary": {
            "added": total_added,
            "removed": total_removed,
            "changed": total_changed,
            "object_kinds": len(changes),
        },
        "changes": changes,
    }
