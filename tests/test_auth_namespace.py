from __future__ import annotations

import json

from auditex import cli as auditex_cli
from auditex.mcp_server import tool_specs


def test_mcp_tool_specs_include_auth_tools() -> None:
    names = {item["name"] for item in tool_specs()}
    assert "auditex_auth_status" in names
    assert "auditex_auth_list" in names
    assert "auditex_auth_use" in names


def test_auth_status_command_prints_json(monkeypatch, capsys) -> None:
    def _fake_get_auth_status() -> dict:
        return {
            "azure_cli": {"status": "supported"},
            "m365": {"active_connection": "bolyki-lab-user"},
        }

    monkeypatch.setattr("auditex.auth.get_auth_status", _fake_get_auth_status)

    rc = auditex_cli.main(["auth", "status"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["azure_cli"]["status"] == "supported"
    assert payload["m365"]["active_connection"] == "bolyki-lab-user"


def test_auth_list_command_prints_saved_connections(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.auth.list_connections",
        lambda: {
            "connections": [
                {"name": "bolyki-lab-app", "active": False},
                {"name": "bolyki-lab-user", "active": True},
            ]
        },
    )

    rc = auditex_cli.main(["auth", "list"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["connections"][1]["name"] == "bolyki-lab-user"


def test_auth_use_command_switches_connection(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.auth.use_connection",
        lambda name: {"connectionName": name, "connectedAs": "bolyki@bolyki.eu"},
    )

    rc = auditex_cli.main(["auth", "use", "bolyki-lab-user"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["connectionName"] == "bolyki-lab-user"


def test_response_list_actions_command_prints_json(capsys) -> None:
    rc = auditex_cli.main(["response", "list-actions"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert "message_trace" in payload["actions"]
