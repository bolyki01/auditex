from __future__ import annotations

from azure_tenant_audit.collectors.security import SecurityCollector
from azure_tenant_audit.graph import GraphError


class _SecurityClient:
    def __init__(self) -> None:
        self.calls: dict[str, dict[str, str]] = {}

    def get_all(self, path, params=None):  # noqa: ANN001
        self.calls[path] = dict(params or {})
        if path == "/identity/conditionalAccess/policies":
            return [{"id": "ca-1"}]
        if path == "/identity/conditionalAccess/namedLocations":
            return [{"id": "nl-1"}]
        if path == "/auditLogs/signIns":
            return [{"id": "si-1"}]
        if path == "/auditLogs/directoryAudits":
            return [{"id": "da-1"}]
        if path == "/security/alerts":
            return [{"id": "alert-1"}]
        raise AssertionError(f"unexpected path: {path}")


def test_security_collector_collects_directory_audits_and_time_filters() -> None:
    client = _SecurityClient()
    collector = SecurityCollector()

    result = collector.run(
        {
            "client": client,
            "top": 250,
            "since": "2026-04-01T00:00:00Z",
            "until": "2026-04-02T00:00:00Z",
            "audit_logger": None,
        }
    )

    assert result.status == "ok"
    assert result.payload["directoryAudits"]["value"][0]["id"] == "da-1"
    assert "createdDateTime ge 2026-04-01T00:00:00Z" in client.calls["/auditLogs/signIns"]["$filter"]
    assert "activityDateTime ge 2026-04-01T00:00:00Z" in client.calls["/auditLogs/directoryAudits"]["$filter"]


class _PartialSecurityClient(_SecurityClient):
    def get_all(self, path, params=None):  # noqa: ANN001
        if path == "/auditLogs/directoryAudits":
            raise GraphError("Forbidden", status=403)
        return super().get_all(path, params=params)


def test_security_collector_marks_partial_when_directory_audits_are_blocked() -> None:
    collector = SecurityCollector()
    result = collector.run({"client": _PartialSecurityClient(), "top": 100, "audit_logger": None})

    assert result.status == "partial"
    failed_items = [row for row in (result.coverage or []) if row["status"] != "ok"]
    assert any(row["name"] == "directoryAudits" for row in failed_items)
