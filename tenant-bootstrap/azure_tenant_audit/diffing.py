from __future__ import annotations

import json
from pathlib import Path
from typing import Any


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


def diff_run_directories(run_a: str | Path, run_b: str | Path) -> dict[str, Any]:
    left = Path(run_a)
    right = Path(run_b)
    left_files, left_records = _records_for_run(left)
    right_files, right_records = _records_for_run(right)

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
        "compared_files": compared_files,
        "summary": {
            "added": total_added,
            "removed": total_removed,
            "changed": total_changed,
            "object_kinds": len(changes),
        },
        "changes": changes,
    }
