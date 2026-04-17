from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.cli import _build_diagnostics, _load_permission_hints


def test_security_defender_posture_config_and_blocker_mapping() -> None:
    definitions = json.loads(Path("configs/collector-definitions.json").read_text(encoding="utf-8"))
    security_definition = definitions["collectors"]["security"]

    assert security_definition["required_permissions"].count("SecurityEvents.Read.All") == 1
    assert "SecurityIncident.Read.All" in security_definition["required_permissions"]
    assert "defenderIncidents" in security_definition["query_plan"]
    assert "secureScores" in security_definition["query_plan"]
    assert "defenderRecommendations" in security_definition["query_plan"]

    permissions = json.loads(Path("configs/collector-permissions.json").read_text(encoding="utf-8"))
    security_permissions = permissions["collector_permissions"]["security"]
    assert "SecurityIncident.Read.All" in security_permissions["graph_scopes"]
    assert "SecurityIncident.Read.All" in permissions["global_app_recommendation"]

    diagnostics = _build_diagnostics(
        result_rows=[
            {
                "name": "security",
                "status": "partial",
                "message": "security collector completed with partial errors",
            }
        ],
        coverage_rows=[
            {
                "collector": "security",
                "type": "graph",
                "name": "defenderIncidents",
                "endpoint": "/security/incidents",
                "status": "failed",
                "error_class": "insufficient_permissions",
                "error": "Forbidden",
                "top": "100",
            }
        ],
        permission_hints=_load_permission_hints(Path("configs/collector-permissions.json")),
        auditor_profile="security-reader",
    )

    assert diagnostics[0]["item"] == "defenderIncidents"
    assert "SecurityIncident.Read.All" in diagnostics[0]["recommendations"]["required_graph_scopes"]
