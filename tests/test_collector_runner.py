from __future__ import annotations

from typing import Any

from azure_tenant_audit.collector_runner import CollectorRunContext, CollectorRunHooks, CollectorRunner
from azure_tenant_audit.collectors.base import CollectorResult


class _FakeWriter:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any] | None]] = []
        self.raw: list[tuple[str, dict[str, Any]]] = []
        self.coverage: list[list[dict[str, Any]]] = []
        self.checkpoints: list[tuple[str, dict[str, Any]]] = []

    def log_event(self, event: str, message: str, details: dict[str, Any] | None = None) -> None:
        self.events.append((event, message, details))

    def write_raw(self, name: str, payload: dict[str, Any]) -> str:
        self.raw.append((name, payload))
        return f"raw/{name}.json"

    def write_index_records(self, records: list[dict[str, Any]]) -> None:
        self.coverage.append(records)

    def write_checkpoint(self, collector_name: str, payload: dict[str, Any]) -> str:
        self.checkpoints.append((collector_name, payload))
        return "checkpoints/checkpoint-state.json"


class _SuccessfulCollector:
    name = "identity"

    def run(self, context: dict[str, Any]) -> CollectorResult:
        assert context["client"] == "graph"
        assert context["top"] == 5
        assert context["page_size"] == 2
        assert context["plane"] == "inventory"
        assert context["since"] == "2026-04-01T00:00:00Z"
        assert context["collector_checkpoint_state"] == {"status": "partial"}
        assert context["operation_checkpoint_state"] == {"export": {"status": "ok"}}
        context["audit_logger"]("collector.custom", "custom event", {"collector": "identity"})
        return CollectorResult(
            name="identity",
            status="ok",
            item_count=1,
            message="ok",
            payload={"users": [{"id": "1"}]},
            coverage=[
                {
                    "collector": "identity",
                    "type": "graph",
                    "name": "users",
                    "status": "ok",
                    "item_count": 1,
                }
            ],
        )


class _CrashingCollector:
    name = "security"

    def run(self, _context: dict[str, Any]) -> CollectorResult:
        raise RuntimeError("boom")


def test_runner_calls_legacy_collector_and_writes_result_surfaces() -> None:
    writer = _FakeWriter()
    runner = CollectorRunner(writer)

    run = runner.run(
        _SuccessfulCollector(),
        CollectorRunContext(
            client="graph",
            top=5,
            page_size=2,
            plane="inventory",
            since="2026-04-01T00:00:00Z",
            collector_checkpoint_state={"status": "partial"},
            operation_checkpoint_state={"export": {"status": "ok"}},
            hooks=CollectorRunHooks(audit_logger=writer.log_event),
        ),
    )

    assert run.crashed is False
    assert run.result.status == "ok"
    assert run.coverage_rows[0]["name"] == "users"
    assert writer.raw == [("identity", {"users": [{"id": "1"}]})]
    assert writer.coverage == [[run.coverage_rows[0]]]
    assert writer.checkpoints == [
        (
            "identity",
            {
                "name": "identity",
                "status": "ok",
                "item_count": 1,
                "message": "ok",
                "error": None,
                "coverage_rows": 1,
            },
        )
    ]
    assert [event[0] for event in writer.events] == [
        "collector.started",
        "collector.custom",
        "collector.finished",
    ]


def test_runner_turns_collector_crash_into_checkpoint_row() -> None:
    writer = _FakeWriter()
    runner = CollectorRunner(writer)

    run = runner.run(_CrashingCollector(), CollectorRunContext(client="graph", top=1))

    assert run.crashed is True
    assert run.result.status == "failed"
    assert run.result.error == "boom"
    assert run.result_row == {
        "name": "security",
        "status": "failed",
        "item_count": 0,
        "message": "collector crashed",
        "error": "boom",
        "coverage_rows": 0,
    }
    assert writer.raw == []
    assert writer.coverage == []
    assert writer.checkpoints == [("security", run.result_row)]
    assert [event[0] for event in writer.events] == ["collector.started", "collector.failed"]


def test_context_exposes_checkpoint_and_adapter_hooks_to_existing_collectors() -> None:
    calls: list[tuple[str, Any]] = []

    def write_export_checkpoint(
        collector_name: str,
        operation: str,
        status: str,
        item_count: int,
        message: str,
        **extra: Any,
    ) -> str:
        calls.append(("checkpoint", collector_name, operation, status, item_count, message, extra))
        return "checkpoints/checkpoint-state.json"

    def chunk_writer(
        collector_name: str,
        endpoint_name: str,
        page_number: int,
        records: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        calls.append(("chunk", collector_name, endpoint_name, page_number, records, metadata))
        return f"chunks/{collector_name}/{endpoint_name}-{page_number:05d}.jsonl"

    context = CollectorRunContext(
        client="graph",
        top=10,
        hooks=CollectorRunHooks(
            write_export_checkpoint=write_export_checkpoint,
            chunk_writer=chunk_writer,
        ),
    ).to_legacy_dict()

    assert context["write_export_checkpoint"]("purview", "auditLogJobs", "ok", 3, "done", command="Get-Job")
    assert context["chunk_writer"]("identity", "users", 1, [{"id": "1"}], {"endpoint": "/users"})
    assert calls == [
        ("checkpoint", "purview", "auditLogJobs", "ok", 3, "done", {"command": "Get-Job"}),
        ("chunk", "identity", "users", 1, [{"id": "1"}], {"endpoint": "/users"}),
    ]
