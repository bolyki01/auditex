from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def build_privacy_block(*, safe_for_external_llm: bool) -> dict[str, Any]:
    if safe_for_external_llm:
        return {
            "privacy_level": "ai_safe_redacted",
            "redaction_mode": "summary_only",
            "contains_pii": False,
            "contains_auth_claims": False,
            "safe_for_external_llm": True,
        }
    return {
        "privacy_level": "internal_sensitive",
        "redaction_mode": "none",
        "contains_pii": True,
        "contains_auth_claims": True,
        "safe_for_external_llm": False,
    }


def _artifact_map(run_dir: Path) -> dict[str, list[str]]:
    artifact_map: dict[str, list[str]] = {}
    for path in sorted(run_dir.rglob("*")):
        if path.is_dir():
            continue
        if path.name == ".DS_Store" or "__MACOSX" in path.parts:
            continue
        relative = path.relative_to(run_dir)
        section = relative.parts[0] if len(relative.parts) > 1 else "root"
        artifact_map.setdefault(section, []).append(str(relative))
    return artifact_map


def _read_order() -> list[str]:
    return [
        "ai_context.json",
        "ai_safe/run_summary.json",
        "reports/report-pack.json",
        "findings/findings.json",
        "normalized/snapshot.json",
        "normalized/capability_matrix.json",
        "normalized/coverage_ledger.json",
        "blockers/blockers.json",
        "index/evidence.sqlite",
    ]


def build_ai_context(
    *,
    run_dir: Path,
    run_metadata: dict[str, Any],
    normalized_snapshot: dict[str, Any],
    capability_rows: list[dict[str, Any]],
    coverage_ledger: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    snapshot = normalized_snapshot.get("snapshot", {})
    blocker_classes = Counter(str(item.get("error_class") or "unknown") for item in blockers if isinstance(item, dict))
    collector_status = {
        str(item.get("collector")): {
            "capability_status": item.get("status"),
            "coverage_status": next(
                (
                    row.get("coverage_status")
                    for row in coverage_ledger
                    if isinstance(row, dict) and row.get("collector") == item.get("collector")
                ),
                None,
            ),
        }
        for item in capability_rows
        if isinstance(item, dict) and item.get("collector")
    }
    artifact_map = _artifact_map(run_dir)
    artifact_map.setdefault("root", [])
    for item in ("ai_context.json", "validation.json"):
        if item not in artifact_map["root"]:
            artifact_map["root"].append(item)
    artifact_map["root"] = sorted(artifact_map["root"])
    return {
        "schema_version": "2026-04-19",
        "run": {
            "tenant_name": run_metadata.get("tenant_name"),
            "tenant_id": run_metadata.get("tenant_id"),
            "run_id": run_metadata.get("run_id"),
            "overall_status": run_metadata.get("overall_status"),
            "auditor_profile": run_metadata.get("auditor_profile"),
            "mode": run_metadata.get("mode"),
            "plane": run_metadata.get("plane"),
            "selected_collectors": run_metadata.get("selected_collectors", []),
            "duration_seconds": run_metadata.get("duration_seconds"),
        },
        "privacy": build_privacy_block(safe_for_external_llm=False),
        "counts": {
            "normalized_counts": snapshot.get("normalized_counts", snapshot.get("object_counts", {})),
            "full_counts": snapshot.get("full_counts", {}),
            "sample_counts": snapshot.get("sample_counts", {}),
            "chunk_counts": snapshot.get("chunk_counts", {}),
            "sample_truncated": snapshot.get("sample_truncated", False),
            "truncated_sections": snapshot.get("truncated_sections", []),
        },
        "coverage": {
            "collector_status": collector_status,
            "collector_count": snapshot.get("collector_count", 0),
            "coverage_row_count": snapshot.get("coverage_row_count", 0),
            "blocker_count": snapshot.get("blocker_count", 0),
            "blocker_summary": dict(blocker_classes),
        },
        "findings": {
            "count": len(findings),
            "open_count": sum(1 for item in findings if str(item.get("status") or "open") == "open"),
            "severity_counts": dict(Counter(str(item.get("severity") or "unknown") for item in findings)),
        },
        "artifacts": artifact_map,
        "read_order": _read_order(),
        "known_limitations": sorted(
            {
                collector
                for collector, payload in collector_status.items()
                if payload.get("coverage_status") in {"partial_success", "blocked_permission", "failed_runtime", "not_run"}
            }
        ),
    }


def build_validation_report(
    *,
    run_dir: Path,
    ai_context: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    ids = [str(item.get("id")) for item in findings if isinstance(item, dict) and item.get("id")]
    duplicate_ids = sorted({item for item in ids if ids.count(item) > 1})
    if duplicate_ids:
        issues.append({"code": "duplicate_finding_ids", "details": duplicate_ids})
    missing_refs = sorted(str(item.get("id")) for item in findings if not item.get("evidence_refs"))
    if missing_refs:
        issues.append({"code": "missing_evidence_refs", "details": missing_refs})

    counts = ai_context.get("counts", {})
    if not isinstance(counts.get("normalized_counts"), dict):
        issues.append({"code": "missing_normalized_counts"})

    artifact_paths = [path for values in ai_context.get("artifacts", {}).values() if isinstance(values, list) for path in values]
    missing_artifacts = sorted(
        path for path in artifact_paths if path != "validation.json" and not (run_dir / path).exists()
    )
    if missing_artifacts:
        issues.append({"code": "missing_artifacts", "details": missing_artifacts})

    return {
        "schema_version": "2026-04-19",
        "valid": not issues,
        "issue_count": len(issues),
        "issues": issues,
    }
