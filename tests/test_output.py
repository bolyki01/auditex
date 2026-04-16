from __future__ import annotations

from pathlib import Path

from azure_tenant_audit.output import AuditWriter


def test_writer(tmp_path: Path):
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="baseline")
    payload = {"value": [{"id": "1"}]}
    raw_path = writer.write_raw("identity", payload)
    writer.log_event("test.event", "writer test")
    writer.write_index_records(
        [
            {"collector": "identity", "name": "users", "type": "graph", "status": "ok", "item_count": 1},
            {"collector": "identity", "name": "groups", "type": "graph", "status": "ok", "item_count": 2},
        ]
    )
    writer.write_summary(
        {
            "name": "identity",
            "status": "ok",
            "item_count": 1,
            "message": "ok",
            "coverage_rows": 2,
        }
    )
    writer.write_bundle(
        {
            "collectors": ["identity"],
            "duration_seconds": 1.2,
            "overall_status": "ok",
            "session_context": {"user_principal_name": "admin@contoso.com"},
        }
    )

    assert raw_path.exists()
    assert (writer.run_dir / "run-manifest.json").exists()
    assert (writer.run_dir / "summary.json").exists()
    assert (writer.run_dir / "audit-log.jsonl").exists()
    assert (writer.run_dir / "audit-debug.log").exists()
    assert (writer.run_dir / "coverage.json").exists()
    assert (writer.run_dir / "index" / "coverage.jsonl").exists()
    assert (writer.run_dir / "auth-context.json").exists()

    json_lines = (writer.run_dir / "audit-log.jsonl").read_text(encoding="utf-8").splitlines()
    assert any('"run.completed"' in line for line in json_lines)
