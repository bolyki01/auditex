"""Regression: aggregate same-finding-id diagnostics into one finding.

Live audit 2026-05-09 surfaced 5 ``sharepoint_access:sitePermissions``
findings collapsing to one finding ID — the C3 duplicate-id validator
flagged it. Fix: build_findings groups diagnostics by ``(collector,
target)`` and emits one aggregated finding per group with all probed
endpoints in ``affected_objects``.
"""
from __future__ import annotations

from azure_tenant_audit.findings import build_findings


def _diag(collector: str, item: str, endpoint: str) -> dict:
    return {
        "collector": collector,
        "item": item,
        "endpoint": endpoint,
        "status": "failed",
        "error_class": "insufficient_permissions",
        "error": "Access denied",
        "evidence_refs": [
            {
                "artifact_path": f"raw/{collector}.json",
                "artifact_kind": "raw_json",
                "collector": collector,
                "record_key": f"{collector}:{item}",
                "source_name": item,
            }
        ],
    }


def test_diagnostics_with_same_finding_id_aggregate_to_one_finding() -> None:
    diagnostics = [
        _diag("sharepoint_access", "sitePermissions", f"/sites/site-{i}/permissions")
        for i in range(5)
    ]
    findings = build_findings(diagnostics)
    matches = [f for f in findings if f["id"] == "sharepoint_access:sitePermissions"]
    assert len(matches) == 1
    finding = matches[0]
    assert finding["aggregated_count"] == 5
    assert len(finding["affected_objects"]) == 5
    assert all("/sites/site-" in obj for obj in finding["affected_objects"])


def test_single_diagnostic_does_not_set_aggregated_count() -> None:
    diagnostics = [_diag("sharepoint_access", "sitePermissions", "/sites/only/permissions")]
    findings = build_findings(diagnostics)
    matches = [f for f in findings if f["id"] == "sharepoint_access:sitePermissions"]
    assert len(matches) == 1
    assert "aggregated_count" not in matches[0]
    assert matches[0]["affected_objects"] == ["/sites/only/permissions"]


def test_diagnostics_with_distinct_targets_do_not_merge() -> None:
    diagnostics = [
        _diag("sharepoint_access", "sitePermissions", "/sites/a/permissions"),
        _diag("sharepoint_access", "sharePointSettings", "/admin/sharepoint/settings"),
    ]
    findings = build_findings(diagnostics)
    ids = {f["id"] for f in findings}
    assert "sharepoint_access:sitePermissions" in ids
    assert "sharepoint_access:sharePointSettings" in ids


def test_aggregation_preserves_evidence_refs_from_every_diagnostic() -> None:
    diagnostics = [
        _diag("sharepoint_access", "sitePermissions", f"/sites/site-{i}/permissions")
        for i in range(3)
    ]
    findings = build_findings(diagnostics)
    finding = next(f for f in findings if f["id"] == "sharepoint_access:sitePermissions")
    assert len(finding["evidence_refs"]) == 3


def test_no_duplicate_finding_ids_after_aggregation() -> None:
    diagnostics = [
        _diag("sharepoint_access", "sitePermissions", "/sites/a/permissions"),
        _diag("sharepoint_access", "sitePermissions", "/sites/a/permissions"),
        _diag("sharepoint_access", "sitePermissions", "/sites/b/permissions"),
    ]
    findings = build_findings(diagnostics)
    ids = [f["id"] for f in findings]
    assert len(ids) == len(set(ids))
