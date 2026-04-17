from __future__ import annotations

import json
import os
from pathlib import Path

from auditex import cli as auditex_cli
from auditex.mcp_server import tool_specs


def test_mcp_tool_specs_include_auth_tools() -> None:
    names = {item["name"] for item in tool_specs()}
    assert "auditex_auth_status" in names
    assert "auditex_auth_list" in names
    assert "auditex_auth_use" in names
    assert "auditex_auth_import_token" in names
    assert "auditex_auth_inspect_token" in names
    assert "auditex_auth_capability" in names


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


def _jwt(payload: dict[str, object]) -> str:
    import base64

    def _encode(value: dict[str, object]) -> str:
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{_encode({'alg': 'none', 'typ': 'JWT'})}.{_encode(payload)}."


def test_auth_import_token_command_persists_context(monkeypatch, tmp_path: Path, capsys) -> None:
    contexts_path = tmp_path / "contexts.json"
    monkeypatch.setenv("AUDITEX_AUTH_CONTEXTS_PATH", str(contexts_path))
    token = _jwt(
        {
            "tid": "tenant-1",
            "aud": "https://graph.microsoft.com",
            "scp": "Directory.Read.All AuditLog.Read.All",
            "upn": "auditor@contoso.test",
            "exp": 1893456000,
        }
    )

    rc = auditex_cli.main(["auth", "import-token", "--name", "customer-a", "--token", token])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "customer-a"
    assert payload["tenant_id"] == "tenant-1"
    assert payload["auth_type"] == "imported_token"
    stored = json.loads(contexts_path.read_text(encoding="utf-8"))
    assert stored["active_context"] == "customer-a"
    assert stored["contexts"]["customer-a"]["token"] == token


def test_auth_inspect_token_command_prints_claims(monkeypatch, tmp_path: Path, capsys) -> None:
    contexts_path = tmp_path / "contexts.json"
    monkeypatch.setenv("AUDITEX_AUTH_CONTEXTS_PATH", str(contexts_path))
    token = _jwt(
        {
            "tid": "tenant-2",
            "aud": "https://graph.microsoft.com",
            "scp": "Directory.Read.All Reports.Read.All",
            "roles": ["SecurityEvents.Read.All"],
            "upn": "reader@contoso.test",
            "exp": 1893456000,
        }
    )

    rc = auditex_cli.main(["auth", "inspect-token", "--token", token])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tenant_id"] == "tenant-2"
    assert payload["audience"] == "https://graph.microsoft.com"
    assert payload["delegated_scopes"] == ["Directory.Read.All", "Reports.Read.All"]
    assert payload["app_roles"] == ["SecurityEvents.Read.All"]


def test_auth_capability_command_prints_collector_statuses(monkeypatch, tmp_path: Path, capsys) -> None:
    contexts_path = tmp_path / "contexts.json"
    monkeypatch.setenv("AUDITEX_AUTH_CONTEXTS_PATH", str(contexts_path))
    token = _jwt(
        {
            "tid": "tenant-3",
            "aud": "https://graph.microsoft.com",
            "scp": "Directory.Read.All AuditLog.Read.All User.Read.All Group.Read.All Application.Read.All",
            "roles": [],
            "upn": "reader@contoso.test",
            "exp": 1893456000,
        }
    )
    auditex_cli.main(["auth", "import-token", "--name", "customer-cap", "--token", token])
    capsys.readouterr()

    rc = auditex_cli.main(
        [
            "auth",
            "capability",
            "--name",
            "customer-cap",
            "--collectors",
            "identity,security,defender",
            "--auditor-profile",
            "global-reader",
        ]
    )

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    rows = {row["collector"]: row for row in payload["capabilities"]}
    assert rows["identity"]["status"] == "supported"
    assert rows["security"]["status"] == "supported"
    assert rows["defender"]["status"] == "blocked_by_scope"
