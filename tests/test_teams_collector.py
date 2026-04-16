from __future__ import annotations

from azure_tenant_audit.collectors.teams import TeamsCollector


class _FakeClient:
    def get_all(self, path, params=None):  # noqa: ANN001
        if path == "/groups":
            assert params == {
                "$select": "id,displayName,description,visibility,resourceProvisioningOptions,createdDateTime",
                "$filter": "resourceProvisioningOptions/Any(x:x eq 'Team')",
                "$top": "200",
            }
            return [{"id": "team-1", "displayName": "Team One"}]
        if path == "/teams/team-1/channels":
            assert params == {"$select": "id,displayName,description"}
            return [{"id": "channel-1", "displayName": "General"}]
        raise AssertionError(f"unexpected path: {path}")


def test_teams_collector_uses_group_based_inventory() -> None:
    collector = TeamsCollector()
    result = collector.run({"client": _FakeClient(), "top": 200, "audit_logger": None})

    assert result.status == "ok"
    assert result.item_count == 2
    assert result.payload["teamGroups"]["value"][0]["id"] == "team-1"
    assert result.payload["teamsByTeam"]["value"][0]["teamId"] == "team-1"
