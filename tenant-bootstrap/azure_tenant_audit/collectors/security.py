from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class SecurityCollector(Collector):
    name = "security"
    description = "Security and sign-in risk posture."
    required_permissions = [
        "SecurityEvents.Read.All",
        "SecurityActions.Read.All",
        "AuditLog.Read.All",
        "Policy.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 500)
        queries = {
            "conditionalAccessPolicies": {
                "endpoint": "/identity/conditionalAccess/policies",
                "params": {},
            },
            "namedLocations": {
                "endpoint": "/identity/conditionalAccess/namedLocations",
                "params": {},
            },
            "securityDefaults": {
                "endpoint": "/policies/identitySecurityDefaultsEnforcementPolicy",
                "params": {},
            },
            "signIns": {
                "endpoint": "/auditLogs/signIns",
                "params": {},
            },
            "securityAlerts": {
                "endpoint": "/security/alerts",
                "params": {},
            },
        }
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            queries,
            top=top,
            log_event=context.get("audit_logger"),
        )
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="security collector completed with partial errors" if partial else "",
            coverage=coverage,
        )

    @staticmethod
    def _safe_count(payload: dict[str, Any]) -> int:
        if not payload or "value" not in payload:
            return 0
        return len(payload["value"]) if isinstance(payload["value"], list) else 0
