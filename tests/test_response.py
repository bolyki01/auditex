from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.response import ResponseConfig, run_response


class _FakeAdapter:
    name = "powershell_graph"

    def __init__(self) -> None:
        self.run_calls: list[str] = []

    def dependency_check(self) -> bool:
        return True

    def run(self, command: str, log_event=None):  # noqa: ANN001, ARG002
        self.run_calls.append(command)
        return {
            "command": command,
            "value": [{"id": "trace-1"}],
            "duration_ms": 1.0,
        }


def test_response_execute_requires_matching_lab_tenant_even_with_allow_flag(tmp_path: Path, monkeypatch) -> None:
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})

    rc = run_response(
        ResponseConfig(
            tenant_name="contoso",
            out_dir=tmp_path,
            tenant_id="not-lab-tenant",
            action="message_trace",
            target="user@example.com",
            intent="review smoke",
            auditor_profile="exchange-reader",
            execute=True,
            allow_lab_response=True,
            run_name="response-blocked",
        )
    )

    assert rc == 1
    assert adapter.run_calls == []

    run_dir = tmp_path / "contoso-response-blocked"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert blockers[0]["error_class"] == "lab_guard"
    assert manifest["overall_status"] == "partial"


def test_response_execute_runs_when_lab_guard_is_satisfied(tmp_path: Path, monkeypatch) -> None:
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})

    rc = run_response(
        ResponseConfig(
            tenant_name="contoso",
            out_dir=tmp_path,
            tenant_id="lab-tenant",
            action="message_trace",
            target="user@example.com",
            intent="review smoke",
            auditor_profile="exchange-reader",
            execute=True,
            allow_lab_response=True,
            run_name="response-allowed",
        )
    )

    assert rc == 0
    assert adapter.run_calls == ['Get-MessageTrace -RecipientAddress "user@example.com" -StartDate "" -EndDate ""']

    run_dir = tmp_path / "contoso-response-allowed"
    normalized = json.loads((run_dir / "normalized" / "response.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert normalized["response"]["ran"] is True
    assert normalized["response"]["adapter"] == "powershell_graph"
    assert manifest["plane"] == "response"
    assert manifest["overall_status"] == "ok"
