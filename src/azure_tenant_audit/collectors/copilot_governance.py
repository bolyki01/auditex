"""Capability-gated collector for Microsoft 365 Copilot governance posture."""
from __future__ import annotations

from typing import Any

from ._capability_gated import build_collector_result, run_capability_gated_endpoints
from .base import Collector


class CopilotGovernanceCollector(Collector):
    name = "copilot_governance"
    description = (
        "Microsoft 365 Copilot governance posture: admin settings and usage telemetry. "
        "Capability-gated; requires a Copilot license and Reports.Read.All for usage reports."
    )
    required_permissions = [
        "Reports.Read.All",
        "AiEnterpriseInteraction.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> Any:
        payload, coverage = run_capability_gated_endpoints(
            self.name,
            context.get("client"),
            [
                ("copilotAdminSettings", "/copilot/admin/settings"),
                ("copilotUsageReports", "/reports/getCopilotUserUsageReport(period='D30')"),
            ],
            log_event=context.get("audit_logger"),
            skip_reason="no Graph client; Copilot likely unlicensed",
        )
        return build_collector_result(
            self,
            payload,
            coverage,
            partial_message="Copilot governance collection partial; check capability matrix",
        )
