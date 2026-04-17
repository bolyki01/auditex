from __future__ import annotations

import time
from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, _classify_graph_error, run_graph_endpoints


class IntuneDepthCollector(Collector):
    name = "intune_depth"
    description = "Deeper Intune policy, script, protection, and sampled assignment inventory."
    required_permissions = [
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementApps.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 250)
        page_size = context.get("page_size")
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "deviceConfigurations": {
                    "endpoint": "/deviceManagement/deviceConfigurations",
                    "params": {},
                },
                "groupPolicyConfigurations": {
                    "endpoint": "/deviceManagement/groupPolicyConfigurations",
                    "params": {},
                },
                "deviceManagementScripts": {
                    "endpoint": "/deviceManagement/deviceManagementScripts",
                    "params": {},
                },
                "androidManagedAppProtections": {
                    "endpoint": "/deviceAppManagement/androidManagedAppProtections",
                    "params": {},
                },
                "iosManagedAppProtections": {
                    "endpoint": "/deviceAppManagement/iosManagedAppProtections",
                    "params": {},
                },
            },
            top=top,
            page_size=page_size,
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )

        configuration_rows = payload.get("deviceConfigurations", {}).get("value", [])
        if not isinstance(configuration_rows, list):
            configuration_rows = []
        assignment_rows: list[dict[str, Any]] = []
        for policy in configuration_rows[:10]:
            policy_id = policy.get("id")
            if not isinstance(policy_id, str) or not policy_id:
                continue
            endpoint = f"/deviceManagement/deviceConfigurations/{policy_id}/assignments"
            start = time.perf_counter()
            try:
                assignments = client.get_all(endpoint, params={"$top": "50"})
                if not isinstance(assignments, list):
                    assignments = []
                assignment_rows.append(
                    {
                        "policyId": policy_id,
                        "displayName": policy.get("displayName"),
                        "assignments": assignments,
                    }
                )
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": "deviceConfigurationAssignments",
                        "endpoint": endpoint,
                        "policy_id": policy_id,
                        "status": "ok",
                        "item_count": len(assignments),
                        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                        "error_class": None,
                        "error": None,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                error_class, error = _classify_graph_error(exc)
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": "deviceConfigurationAssignments",
                        "endpoint": endpoint,
                        "policy_id": policy_id,
                        "status": "failed",
                        "item_count": 0,
                        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                        "error_class": error_class,
                        "error": error,
                    }
                )

        payload["deviceConfigurationAssignments"] = {"value": assignment_rows}
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Intune depth collector partially completed" if partial else "",
            coverage=coverage,
        )
