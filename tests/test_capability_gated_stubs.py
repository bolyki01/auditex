from __future__ import annotations

from typing import Any

import pytest

from azure_tenant_audit.collectors.sentinel_xdr import SentinelXdrCollector
from azure_tenant_audit.collectors.defender_cloud_apps import DefenderCloudAppsCollector
from azure_tenant_audit.collectors.copilot_governance import CopilotGovernanceCollector


@pytest.mark.parametrize(
    "collector_cls,context_key",
    [
        (SentinelXdrCollector, "client"),
        (DefenderCloudAppsCollector, "client"),
        (CopilotGovernanceCollector, "client"),
    ],
)
def test_capability_gated_when_no_graph_client(collector_cls: type, context_key: str) -> None:
    collector = collector_cls()
    result = collector.run({context_key: None, "top": 100})

    assert result.status == "partial"
    coverage = result.coverage or []
    assert all(row["status"] in {"failed", "skipped"} for row in coverage)
    assert any(row.get("error_class") == "service_not_available" for row in coverage)


class _GraphStub:
    def __init__(self, payloads: dict[str, Any]) -> None:
        self.payloads = payloads
        self.calls: list[str] = []

    def get_json(self, path: str, params: dict[str, Any] | None = None, full_url: bool = False) -> dict[str, Any]:
        self.calls.append(path)
        if isinstance(self.payloads.get(path), Exception):
            raise self.payloads[path]
        return self.payloads.get(path, {})

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        return list(self.payloads.get(path, {}).get("value", []))


def test_sentinel_collector_returns_incidents_and_alerts_when_present() -> None:
    payloads = {
        "/security/incidents": {"value": [{"id": "incident-1", "severity": "high"}]},
        "/security/alerts_v2": {"value": [{"id": "alert-1", "severity": "medium"}]},
    }
    collector = SentinelXdrCollector()
    result = collector.run({"client": _GraphStub(payloads), "top": 100})

    assert result.status == "ok"
    assert result.payload["xdrIncidents"]["value"][0]["id"] == "incident-1"


def test_defender_cloud_apps_records_403_as_license_required() -> None:
    from azure_tenant_audit.graph import GraphError

    payloads = {
        "/security/cloudAppSecurityProfiles": GraphError("forbidden", status=403, request="/security/cloudAppSecurityProfiles"),
    }
    collector = DefenderCloudAppsCollector()
    result = collector.run({"client": _GraphStub(payloads), "top": 100})

    coverage = result.coverage or []
    assert any(row["error_class"] == "insufficient_permissions" for row in coverage)


def test_copilot_governance_handles_404_as_service_not_available() -> None:
    from azure_tenant_audit.graph import GraphError

    payloads = {
        "/copilot/admin/settings": GraphError("not found", status=404, request="/copilot/admin/settings"),
        "/reports/getCopilotUserUsageReport(period='D30')": GraphError("not found", status=404, request="/reports/getCopilotUserUsageReport"),
    }
    collector = CopilotGovernanceCollector()
    result = collector.run({"client": _GraphStub(payloads), "top": 100})

    coverage = result.coverage or []
    assert any(row["error_class"] == "resource_not_found" for row in coverage)
