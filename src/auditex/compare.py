from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from azure_tenant_audit.diffing import diff_run_directories

from .evidence_db import load_run_index_summary


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default
    return payload if payload is not None else default


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            parsed = datetime.strptime(value, "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _run_metadata(run_dir: Path) -> dict[str, Any]:
    indexed = load_run_index_summary(run_dir)
    manifest = _load_json(run_dir / "run-manifest.json", default={})
    if not isinstance(manifest, dict):
        manifest = {}
    summary = _load_json(run_dir / "summary.json", default={})
    if not isinstance(summary, dict):
        summary = {}
    if indexed:
        metadata = {
            "path": str(run_dir),
            "run_id": indexed.get("run_id") or manifest.get("run_id"),
            "tenant_name": indexed.get("tenant_name") or manifest.get("tenant_name"),
            "tenant_id": indexed.get("tenant_id") or manifest.get("tenant_id"),
            "created_utc": indexed.get("created_utc") or manifest.get("created_utc"),
            "overall_status": indexed.get("overall_status") or manifest.get("overall_status"),
            "auditor_profile": indexed.get("auditor_profile") or manifest.get("auditor_profile"),
            "section_stats": indexed.get("section_stats") or [],
            "item_count": indexed.get("item_count") or 0,
        }
        metadata["_created_at"] = _parse_utc(metadata.get("created_utc"))
        return metadata
    collector_rows = summary.get("collectors", [])
    if not isinstance(collector_rows, list):
        collector_rows = []
    section_stats: list[dict[str, Any]] = []
    total_items = 0
    for row in collector_rows:
        if not isinstance(row, dict):
            continue
        item_count = int(row.get("item_count") or 0)
        total_items += item_count
        section_stats.append(
            {
                "name": str(row.get("name") or ""),
                "status": row.get("status"),
                "item_count": item_count,
                "message": row.get("message"),
            }
        )

    return {
        "path": str(run_dir),
        "run_id": manifest.get("run_id"),
        "tenant_name": manifest.get("tenant_name"),
        "tenant_id": manifest.get("tenant_id"),
        "created_utc": manifest.get("created_utc"),
        "_created_at": _parse_utc(manifest.get("created_utc")),
        "overall_status": manifest.get("overall_status"),
        "auditor_profile": manifest.get("auditor_profile"),
        "section_stats": section_stats,
        "item_count": total_items,
    }


def _tenant_gate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    tenant_ids = [run.get("tenant_id") for run in runs]
    tenant_names = [run.get("tenant_name") for run in runs]
    if all(tenant_ids) and len(set(tenant_ids)) == 1:
        return {"same_tenant": True, "gate": "same_tenant", "tenant_key": tenant_ids[0]}
    if all(tenant_names) and len(set(tenant_names)) == 1:
        return {"same_tenant": True, "gate": "same_tenant", "tenant_key": tenant_names[0]}
    return {"same_tenant": False, "gate": "same_tenant_required", "tenant_key": None}


def _sort_runs(runs: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        list(runs),
        key=lambda item: (
            item.get("_created_at") is None,
            item.get("_created_at") or datetime.max.replace(tzinfo=timezone.utc),
            str(item.get("run_id") or item.get("path") or ""),
        ),
    )


def _blocked_diff(left_run: dict[str, Any], right_run: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "left_run": _public_run(left_run),
        "right_run": _public_run(right_run),
        "status": "blocked",
        "reason": reason,
        "compare_context": {"same_tenant": False, "gate": reason},
        "summary": {"added": 0, "removed": 0, "changed": 0, "object_kinds": 0},
        "changes": {},
        "compared_files": [],
    }


def _public_run(run: dict[str, Any]) -> dict[str, Any]:
    payload = dict(run)
    payload.pop("_created_at", None)
    return payload


def _compare_pair(left_run: dict[str, Any], right_run: dict[str, Any], same_tenant: bool, *, allow_cross_tenant: bool) -> dict[str, Any]:
    if not same_tenant and not allow_cross_tenant:
        return _blocked_diff(left_run, right_run, "same_tenant_required")
    diff = diff_run_directories(left_run["path"], right_run["path"])
    diff["left_run"] = _public_run(left_run)
    diff["right_run"] = _public_run(right_run)
    diff["status"] = "ok"
    diff["reason"] = None
    diff["compare_context"] = {
        "same_tenant": same_tenant,
        "gate": "same_tenant" if same_tenant else "allow_cross_tenant",
        "tenant_name": left_run.get("tenant_name"),
        "tenant_id": left_run.get("tenant_id"),
    }
    return diff


def compare_run_directories(run_dirs: Iterable[str | Path], *, allow_cross_tenant: bool = False) -> dict[str, Any]:
    runs = [_run_metadata(Path(run_dir)) for run_dir in run_dirs]
    ordered_runs = _sort_runs(runs)
    compare_context = _tenant_gate(ordered_runs)
    ordered_runs_public = [_public_run(run) for run in ordered_runs]

    timeline: list[dict[str, Any]] = []
    for position, run in enumerate(ordered_runs_public):
        timeline.append(
            {
                "position": position,
                **run,
            }
        )

    adjacent_diffs: list[dict[str, Any]] = []
    for left_run, right_run in zip(ordered_runs, ordered_runs[1:]):
        adjacent_diffs.append(
            _compare_pair(left_run, right_run, compare_context["same_tenant"], allow_cross_tenant=allow_cross_tenant)
        )

    if len(ordered_runs) >= 2:
        baseline_diff = _compare_pair(
            ordered_runs[0],
            ordered_runs[-1],
            compare_context["same_tenant"],
            allow_cross_tenant=allow_cross_tenant,
        )
    else:
        baseline_diff = _blocked_diff(
            ordered_runs[0] if ordered_runs else {},
            ordered_runs[0] if ordered_runs else {},
            "needs_at_least_two_runs",
        )

    return {
        "runs": ordered_runs_public,
        "timeline": timeline,
        "adjacent_diffs": adjacent_diffs,
        "baseline_diff": baseline_diff,
        "compare_context": compare_context,
    }


def compare_runs(run_dirs: Iterable[str | Path], *, allow_cross_tenant: bool = False) -> dict[str, Any]:
    return compare_run_directories(run_dirs, allow_cross_tenant=allow_cross_tenant)
