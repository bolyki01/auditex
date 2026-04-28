from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.diagnostics import build_diagnostics, load_permission_hints


def test_security_defender_posture_config_and_blocker_mapping() -> None:
    definitions = json.loads(Path("configs/collector-definitions.json").read_text(encoding="utf-8"))
    defender_definition = definitions["collectors"]["defender"]

    assert defender_definition["required_permissions"].count("SecurityEvents.Read.All") == 1
    assert "SecurityIncident.Read.All" in defender_definition["required_permissions"]
    assert "defenderIncidents" in defender_definition["query_plan"]
    assert "secureScores" in defender_definition["query_plan"]
    assert "secureScoreControlProfiles" in defender_definition["query_plan"]

    permissions = json.loads(Path("configs/collector-permissions.json").read_text(encoding="utf-8"))
    defender_permissions = permissions["collector_permissions"]["defender"]
    assert "SecurityIncident.Read.All" in defender_permissions["graph_scopes"]
    assert "SecurityIncident.Read.All" in permissions["global_app_recommendation"]

    diagnostics = build_diagnostics(
        result_rows=[
            {
                "name": "defender",
                "status": "partial",
                "message": "defender collector completed with partial errors",
            }
        ],
        coverage_rows=[
            {
                "collector": "defender",
                "type": "graph",
                "name": "defenderIncidents",
                "endpoint": "/security/incidents",
                "status": "failed",
                "error_class": "insufficient_permissions",
                "error": "Forbidden",
                "top": "100",
            }
        ],
        permission_hints=load_permission_hints(Path("configs/collector-permissions.json")),
        auditor_profile="security-reader",
    )

    assert diagnostics[0]["item"] == "defenderIncidents"
    assert "SecurityIncident.Read.All" in diagnostics[0]["recommendations"]["required_graph_scopes"]
