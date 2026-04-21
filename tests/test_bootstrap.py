from __future__ import annotations

import json

from auditex import bootstrap
from auditex import cli as auditex_cli


def test_build_doctor_report_includes_versions_and_readiness_split(monkeypatch) -> None:
    monkeypatch.setattr(
        bootstrap,
        "_selected_python",
        lambda: {"status": "supported", "path": "/usr/bin/python3.13", "version": "Python 3.13.2"},
    )
    monkeypatch.setattr(
        bootstrap,
        "_venv_status",
        lambda: {"status": "supported", "path": "/tmp/.venv", "python_path": "/tmp/.venv/bin/python"},
    )
    monkeypatch.setattr(bootstrap, "detect_package_manager", lambda: "brew")

    def _fake_tool_status(name: str, **_: object) -> dict[str, object]:
        if name == "pwsh":
            return {"name": name, "status": "blocked", "path": None, "version": None, "error": "command_not_found"}
        return {"name": name, "status": "supported", "path": f"/usr/bin/{name}", "version": f"{name}-1.0", "error": None}

    monkeypatch.setattr(bootstrap, "_tool_status", _fake_tool_status)
    monkeypatch.setattr(
        "auditex.auth.get_auth_status",
        lambda **kwargs: {
            "azure_cli": {"status": "supported", "user_name": "reader@contoso.test"},
            "m365": {"status": "supported", "active_connection": "tenant-user"},
            "exchange": {"status": "supported", "module_version": "3.7.0"},
        },
    )

    report = bootstrap.build_doctor_report()

    assert report["system"]["package_manager"] == "brew"
    assert report["python"]["version"] == "Python 3.13.2"
    assert report["tools"]["az"]["version"] == "az-1.0"
    assert report["readiness"]["core_ready"] is True
    assert report["readiness"]["core_missing"] == []
    assert report["readiness"]["exchange_ready"] is False
    assert report["readiness"]["exchange_missing"] == ["pwsh"]
    assert report["readiness"]["pwsh_ready"] is False
    assert report["readiness"]["pwsh_missing"] == ["pwsh"]


def test_format_doctor_report_explains_missing_packs() -> None:
    report = {
        "system": {"os": "Darwin", "machine": "arm64", "package_manager": "manual"},
        "python": {"status": "blocked", "path": None, "version": None, "error": "missing"},
        "venv": {"status": "blocked", "path": "/tmp/.venv", "python_path": "/tmp/.venv/bin/python"},
        "tools": {
            "az": {"status": "blocked", "path": None, "version": None, "error": "command_not_found"},
            "node": {"status": "blocked", "path": None, "version": None, "error": "command_not_found"},
            "npm": {"status": "blocked", "path": None, "version": None, "error": "command_not_found"},
            "m365": {"status": "blocked", "path": None, "version": None, "error": "command_not_found"},
            "pwsh": {"status": "blocked", "path": None, "version": None, "error": "command_not_found"},
        },
        "auth": {
            "azure_cli": {"status": "blocked"},
            "m365": {"status": "blocked"},
            "exchange": {"status": "blocked"},
        },
        "readiness": {
            "core_missing": ["python", "venv", "az"],
            "exchange_missing": ["node", "npm", "m365", "pwsh", "exchange_online_module"],
            "pwsh_missing": ["pwsh"],
        },
    }

    text = bootstrap.format_doctor_report(report)

    assert "Core ready: no (need python, venv, az)" in text
    assert "Exchange module: blocked" in text
    assert "Exchange ready: no (need node, npm, m365, pwsh, exchange_online_module)" in text
    assert "Pwsh ready: no (need pwsh)" in text


def test_auditex_setup_dispatches_to_bootstrap(monkeypatch) -> None:
    called = {}

    def _fake_run_setup(*, with_exchange: bool = False, with_pwsh: bool = False, with_mcp: bool = False) -> int:
        called["with_exchange"] = with_exchange
        called["with_pwsh"] = with_pwsh
        called["with_mcp"] = with_mcp
        return 0

    monkeypatch.setattr("auditex.cli.run_setup", _fake_run_setup)

    rc = auditex_cli.main(["setup", "--exchange", "--pwsh", "--mcp"])

    assert rc == 0
    assert called == {"with_exchange": True, "with_pwsh": True, "with_mcp": True}


def test_auditex_doctor_prints_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.print_doctor_report",
        lambda json_output=False: print(json.dumps({"json": json_output})) or 0,
    )

    rc = auditex_cli.main(["doctor", "--json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["json"] is True


def test_auditex_guided_run_dispatches(monkeypatch) -> None:
    called = {}

    def _fake_run_guided(args) -> int:  # noqa: ANN001
        called["tenant_id"] = args.tenant_id
        return 0

    monkeypatch.setattr("auditex.cli.run_guided", _fake_run_guided)

    rc = auditex_cli.main(["guided-run", "--tenant-id", "contoso.onmicrosoft.com", "--non-interactive"])

    assert rc == 0
    assert called["tenant_id"] == "contoso.onmicrosoft.com"


def test_build_doctor_report_uses_short_m365_version(monkeypatch) -> None:
    monkeypatch.setattr(
        bootstrap,
        "_selected_python",
        lambda: {"status": "supported", "path": "/usr/bin/python3.13", "version": "Python 3.13.2"},
    )
    monkeypatch.setattr(
        bootstrap,
        "_venv_status",
        lambda: {"status": "supported", "path": "/tmp/.venv", "python_path": "/tmp/.venv/bin/python"},
    )
    monkeypatch.setattr(bootstrap, "detect_package_manager", lambda: "brew")

    def _fake_tool_status(name: str, **_: object) -> dict[str, object]:
        version = "CLI for Microsoft 365 v11.6.0" if name == "m365" else f"{name}-1.0"
        return {"name": name, "status": "supported", "path": f"/usr/bin/{name}", "version": version, "error": None}

    monkeypatch.setattr(bootstrap, "_tool_status", _fake_tool_status)
    monkeypatch.setattr(
        "auditex.auth.get_auth_status",
        lambda **kwargs: {
            "azure_cli": {"status": "supported", "user_name": "reader@contoso.test"},
            "m365": {"status": "supported", "active_connection": "tenant-user"},
            "exchange": {"status": "supported", "module_version": "3.7.0"},
        },
    )

    report = bootstrap.build_doctor_report()

    assert report["tools"]["m365"]["version"] == "CLI for Microsoft 365 v11.6.0"


def test_build_doctor_report_marks_exchange_not_ready_without_module(monkeypatch) -> None:
    monkeypatch.setattr(
        bootstrap,
        "_selected_python",
        lambda: {"status": "supported", "path": "/usr/bin/python3.13", "version": "Python 3.13.2"},
    )
    monkeypatch.setattr(
        bootstrap,
        "_venv_status",
        lambda: {"status": "supported", "path": "/tmp/.venv", "python_path": "/tmp/.venv/bin/python"},
    )
    monkeypatch.setattr(bootstrap, "detect_package_manager", lambda: "brew")
    monkeypatch.setattr(
        bootstrap,
        "_tool_status",
        lambda name, **_: {"name": name, "status": "supported", "path": f"/usr/bin/{name}", "version": f"{name}-1.0", "error": None},
    )
    monkeypatch.setattr(
        "auditex.auth.get_auth_status",
        lambda **kwargs: {
            "azure_cli": {"status": "supported", "user_name": "reader@contoso.test"},
            "m365": {"status": "supported", "active_connection": "tenant-user"},
            "exchange": {"status": "blocked", "error": "module_not_found"},
        },
    )

    report = bootstrap.build_doctor_report()

    assert report["readiness"]["exchange_ready"] is False
    assert report["readiness"]["exchange_missing"] == ["exchange_online_module"]


def test_build_doctor_report_app_mode_does_not_require_az(monkeypatch) -> None:
    monkeypatch.setattr(
        bootstrap,
        "_selected_python",
        lambda: {"status": "supported", "path": "/usr/bin/python3.13", "version": "Python 3.13.2"},
    )
    monkeypatch.setattr(
        bootstrap,
        "_venv_status",
        lambda: {"status": "supported", "path": "/tmp/.venv", "python_path": "/tmp/.venv/bin/python"},
    )
    monkeypatch.setattr(bootstrap, "detect_package_manager", lambda: "brew")

    def _fake_tool_status(name: str, **_: object) -> dict[str, object]:
        if name == "az":
            return {"name": name, "status": "blocked", "path": None, "version": None, "error": "command_not_found"}
        return {"name": name, "status": "supported", "path": f"/usr/bin/{name}", "version": f"{name}-1.0", "error": None}

    monkeypatch.setattr(bootstrap, "_tool_status", _fake_tool_status)
    monkeypatch.setattr(
        "auditex.auth.get_auth_status",
        lambda **kwargs: {
            "azure_cli": {"status": "skipped"},
            "m365": {"status": "skipped"},
            "exchange": {"status": "skipped"},
        },
    )

    report = bootstrap.build_doctor_report(auth_mode="app", include_exchange=False, include_auth_checks=False)

    assert report["readiness"]["core_ready"] is True
    assert report["readiness"]["core_missing"] == []
