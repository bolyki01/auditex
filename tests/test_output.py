from __future__ import annotations

import json
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
            "collector_preset": "identity-only",
            "waiver_path": "configs/waivers.json",
            "session_context": {"user_principal_name": "admin@contoso.com"},
        }
    )

    assert raw_path.exists()
    assert (writer.run_dir / "run-manifest.json").exists()
    assert (writer.run_dir / "summary.json").exists()
    assert (writer.run_dir / "audit-log.jsonl").exists()
    assert (writer.run_dir / "audit-command-log.jsonl").exists()
    assert (writer.run_dir / "audit-debug.log").exists()
    assert (writer.run_dir / "coverage.json").exists()
    assert (writer.run_dir / "index" / "coverage.jsonl").exists()
    assert (writer.run_dir / "session-context.json").exists()
    manifest = json.loads((writer.run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "2026-04-18"
    assert manifest["collector_preset"] == "identity-only"
    assert manifest["waiver_path"] == "configs/waivers.json"

    json_lines = (writer.run_dir / "audit-log.jsonl").read_text(encoding="utf-8").splitlines()
    assert any('"run.completed"' in line for line in json_lines)


def test_checkpoint_round_trip_preserves_collectors_and_operations(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="checkpoint")

    writer.write_checkpoint(
        "identity",
        {
            "status": "ok",
            "item_count": 7,
            "message": "identity complete",
            "error": None,
            "error_class": None,
        },
    )
    writer.write_export_checkpoint(
        "purview",
        "auditLogJobs",
        status="ok",
        item_count=12,
        message="export complete",
        extra={"summary_path": "raw/purview/auditLogJobs/summary.json"},
    )

    checkpoint_payload = json.loads((writer.run_dir / "checkpoints" / "checkpoint-state.json").read_text(encoding="utf-8"))
    assert checkpoint_payload["collectors"]["identity"]["status"] == "ok"
    assert checkpoint_payload["collectors"]["identity"]["item_count"] == 7
    assert checkpoint_payload["operations"]["purview"]["auditLogJobs"]["status"] == "ok"
    assert checkpoint_payload["operations"]["purview"]["auditLogJobs"]["summary_path"] == "raw/purview/auditLogJobs/summary.json"

    reloaded = AuditWriter(tmp_path, tenant_name="acme", run_dir=writer.run_dir)
    assert reloaded.load_collector_checkpoint_state()["identity"]["item_count"] == 7
    assert reloaded.load_operation_checkpoint_state()["purview"]["auditLogJobs"]["item_count"] == 12


def test_write_checkpoint_serializes_collectors_map_directly(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="checkpoint-shape")

    writer.write_checkpoint(
        "identity",
        {
            "status": "ok",
            "item_count": 3,
            "message": "done",
            "error": None,
            "error_class": None,
        },
    )

    checkpoint_payload = json.loads((writer.run_dir / "checkpoints" / "checkpoint-state.json").read_text(encoding="utf-8"))
    assert checkpoint_payload["collectors"]["identity"]["status"] == "ok"
    assert checkpoint_payload["collectors"]["identity"]["item_count"] == 3
    assert "collectors" not in checkpoint_payload["collectors"]
