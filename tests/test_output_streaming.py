from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.output import AuditWriter


def test_writer_supports_chunk_blocker_and_report_artifacts(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="streaming")
    chunk_path = writer.write_chunk_records(
        "security",
        "signIns",
        page_number=1,
        records=[{"id": "signin-1"}, {"id": "signin-2"}],
        metadata={"endpoint": "/auditLogs/signIns"},
    )
    blockers_path = writer.write_blockers(
        [
            {
                "collector": "security",
                "status": "failed",
                "endpoint": "/security/alerts",
                "error_class": "insufficient_permissions",
                "error": "Forbidden",
                "recommendations": {"required_graph_scopes": ["SecurityEvents.Read.All"]},
            }
        ]
    )
    findings_path = writer.write_findings(
        [
            {
                "id": "security-alerts-blocked",
                "severity": "medium",
                "title": "Security alerts blocked",
                "status": "open",
                "affected_objects": ["/security/alerts"],
            }
        ]
    )
    ai_safe_path = writer.write_ai_safe(
        "run_summary",
        {"tenant_name": "acme", "overall_status": "partial"},
    )
    report_path = writer.write_report_pack(
        {
            "summary": {"overall_status": "partial"},
            "findings": [{"id": "security-alerts-blocked"}],
            "evidence_paths": [str(chunk_path.relative_to(writer.run_dir))],
        }
    )
    writer.write_bundle(
        {
            "collectors": ["security"],
            "overall_status": "partial",
            "duration_seconds": 2,
            "mode": "azure_cli",
            "command_line": [],
        }
    )

    assert chunk_path.exists()
    assert blockers_path.exists()
    assert findings_path.exists()
    assert ai_safe_path.exists()
    assert report_path.exists()

    manifest = json.loads((writer.run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert "chunks/security/signIns-00001.jsonl" in manifest["artifacts"]
    assert "blockers/blockers.json" in manifest["artifacts"]
    assert "findings/findings.json" in manifest["artifacts"]
    assert "ai_safe/run_summary.json" in manifest["artifacts"]
    assert "reports/report-pack.json" in manifest["artifacts"]
