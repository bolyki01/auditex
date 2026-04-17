from __future__ import annotations

from azure_tenant_audit.findings import build_findings, build_report_pack


def test_build_findings_classifies_permission_and_partial_failures() -> None:
    diagnostics = [
        {
            "collector": "security",
            "item": "securityAlerts",
            "status": "failed",
            "error_class": "insufficient_permissions",
            "error": "Forbidden",
            "recommendations": {"required_graph_scopes": ["SecurityEvents.Read.All"]},
        },
        {
            "collector": "sharepoint",
            "item": "sites",
            "status": "partial",
            "error_class": "service_unavailable",
            "error": "Tenant mysite not provisioned",
            "recommendations": {"notes": ["OneDrive not provisioned"]},
        },
    ]

    findings = build_findings(diagnostics)

    assert len(findings) == 2
    permission_finding = findings[0]
    assert permission_finding["id"] == "security:securityAlerts"
    assert permission_finding["severity"] == "high"
    assert permission_finding["category"] == "permission"
    assert permission_finding["recommendations"]["required_graph_scopes"] == ["SecurityEvents.Read.All"]

    service_finding = findings[1]
    assert service_finding["severity"] == "medium"
    assert service_finding["category"] == "service"
    assert service_finding["affected_objects"] == ["sites"]


def test_build_report_pack_includes_findings_and_evidence_paths() -> None:
    findings = [
        {
            "id": "security:securityAlerts",
            "severity": "high",
            "title": "security collector issue",
            "status": "open",
            "category": "permission",
            "affected_objects": ["securityAlerts"],
        }
    ]

    report = build_report_pack(
        tenant_name="acme",
        overall_status="partial",
        findings=findings,
        evidence_paths=["run-manifest.json", "findings/findings.json"],
        blocker_count=1,
    )

    assert report["summary"]["tenant_name"] == "acme"
    assert report["summary"]["overall_status"] == "partial"
    assert report["summary"]["finding_count"] == 1
    assert report["summary"]["blocker_count"] == 1
    assert report["findings"][0]["id"] == "security:securityAlerts"
    assert report["evidence_paths"] == ["run-manifest.json", "findings/findings.json"]
