from __future__ import annotations

import time
from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, _classify_graph_error, run_graph_endpoints


class TeamsCollector(Collector):
    name = "teams"
    description = "Teams inventory and messaging entities."
    required_permissions = [
        "Team.ReadBasic.All",
        "Channel.ReadBasic.All",
        "Group.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 200)
        endpoint_specs = {
            "teamGroups": {
                "endpoint": "/groups",
                "params": {
                    "$select": "id,displayName,description,visibility,resourceProvisioningOptions,createdDateTime",
                    "$filter": "resourceProvisioningOptions/Any(x:x eq 'Team')",
                },
            },
        }
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            endpoint_specs,
            top=top,
            log_event=context.get("audit_logger"),
        )

        teams_rows = payload.get("teamGroups", {}).get("value", [])
        if not isinstance(teams_rows, list):
            teams_rows = []

        team_meta = []
        for team in teams_rows[:10]:
            team_id = team.get("id")
            if not team_id:
                continue
            start_ms = 0.0
            team_error: str | None = None
            team_error_class: str | None = None
            try:
                start = time.perf_counter()
                channels = client.get_all(
                    f"/teams/{team_id}/channels",
                    params={"$select": "id,displayName,description"},
                )
                start_ms = round((time.perf_counter() - start) * 1000, 2)
                if not isinstance(channels, list):
                    channels = []
                team_meta.append({"teamId": team_id, "channels": {"value": channels}})
                item_count = len(channels)
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": "teamChannels",
                        "endpoint": f"/teams/{team_id}/channels",
                        "team_id": team_id,
                        "status": "ok",
                        "item_count": item_count,
                        "duration_ms": start_ms,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                team_error_class, team_error = _classify_graph_error(exc)
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": "teamChannels",
                        "endpoint": f"/teams/{team_id}/channels",
                        "team_id": team_id,
                        "status": "failed",
                        "item_count": 0,
                        "duration_ms": start_ms,
                        "error_class": team_error_class,
                        "error": team_error,
                    }
                )
        payload["teamsByTeam"] = {"value": team_meta}
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Teams collector hit one or more API issues" if partial else "",
            coverage=coverage,
        )
