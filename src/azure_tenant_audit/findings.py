from __future__ import annotations

from collections import Counter
from typing import Any


_PERMISSION_CLASSES = {"insufficient_permissions", "unauthenticated"}
_SERVICE_CLASSES = {"service_unavailable", "not_found", "not_enabled"}


def _category_for(error_class: str | None) -> str:
    if error_class in _PERMISSION_CLASSES:
        return "permission"
    if error_class in _SERVICE_CLASSES:
        return "service"
    return "collector"


def _severity_for(error_class: str | None, status: str | None) -> str:
    if error_class in _PERMISSION_CLASSES:
        return "high"
    if status == "failed":
        return "high"
    return "medium"


def build_findings(diagnostics: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in diagnostics:
        collector = str(item.get("collector") or "unknown")
        target = item.get("item") or item.get("endpoint") or collector
        error_class = str(item.get("error_class")) if item.get("error_class") else None
        findings.append(
            {
                "id": f"{collector}:{target}",
                "severity": _severity_for(error_class, str(item.get("status") or "")),
                "category": _category_for(error_class),
                "title": f"{collector} collector issue",
                "status": "open",
                "collector": collector,
                "affected_objects": [str(target)] if target else [],
                "error_class": error_class,
                "error": item.get("error"),
                "recommendations": item.get("recommendations", {}),
            }
        )
    return findings


def build_report_pack(
    *,
    tenant_name: str,
    overall_status: str,
    findings: list[dict[str, Any]],
    evidence_paths: list[str],
    blocker_count: int = 0,
    diff_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    severity_counts = Counter(str(item.get("severity") or "unknown") for item in findings)
    summary = {
        "tenant_name": tenant_name,
        "overall_status": overall_status,
        "finding_count": len(findings),
        "blocker_count": blocker_count,
        "severity_counts": dict(severity_counts),
    }
    if diff_summary:
        summary["diff_summary"] = diff_summary
    return {
        "summary": summary,
        "findings": findings,
        "evidence_paths": list(dict.fromkeys(evidence_paths)),
    }
