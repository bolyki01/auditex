from __future__ import annotations

import json

from auditex import cli as auditex_cli
from auditex import guided
from auditex.guided import build_guided_parser


def test_root_help_lists_operator_commands(capsys) -> None:
    rc = auditex_cli.main(["--help"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "guided-run" in output
    assert "compare" in output
    assert "report" in output
    assert "run" in output


def test_setup_cli_accepts_optional_runtime_packs(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_run_setup(**kwargs):  # noqa: ANN003
        seen.update(kwargs)
        return 0

    monkeypatch.setattr("auditex.cli.run_setup", _fake_run_setup)

    rc = auditex_cli.main(["setup", "--mcp", "--exchange", "--pwsh"])

    assert rc == 0
    assert seen == {"with_mcp": True, "with_exchange": True, "with_pwsh": True}


def test_rules_inventory_cli_accepts_routing_filters(monkeypatch, capsys) -> None:
    seen: dict[str, object] = {}

    def _fake_list_rule_inventory(**kwargs):  # noqa: ANN003
        seen.update(kwargs)
        return [{"name": "alpha.rule", "path": "rules/alpha.json"}]

    monkeypatch.setattr("auditex.cli.list_rule_inventory", _fake_list_rule_inventory)

    rc = auditex_cli.main(
        [
            "rules",
            "inventory",
            "--product-family",
            "identity",
            "--license-tier",
            "p2",
            "--audit-level",
            "deep",
        ]
    )

    assert rc == 0
    assert seen["product_family"] == "identity"
    assert seen["license_tier"] == "p2"
    assert seen["audit_level"] == "deep"
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 1


def test_compare_cli_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.compare_runs",
        lambda run_dirs, allow_cross_tenant=False: {
            "runs": [{"path": path} for path in run_dirs],
            "same_tenant": not allow_cross_tenant,
        },
    )

    rc = auditex_cli.main(["compare", "--run-dir", "run-a", "--run-dir", "run-b"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert [row["path"] for row in payload["runs"]] == ["run-a", "run-b"]


def test_report_render_cli_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.render_report",
        lambda **kwargs: {
            "format": kwargs["format_name"],
            "include_sections": kwargs["include_sections"],
        },
    )

    rc = auditex_cli.main(
        [
            "report",
            "render",
            "run-a",
            "--format",
            "html",
            "--include-section",
            "summary",
            "--include-section",
            "findings",
        ]
    )

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["format"] == "html"
    assert payload["include_sections"] == ["summary", "findings"]


def test_export_list_cli_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.list_exporters",
        lambda: [{"name": "html", "formats": ["html"]}],
    )

    rc = auditex_cli.main(["export", "list"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exporters"][0]["name"] == "html"


def test_export_run_cli_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.run_exporter",
        lambda **kwargs: {"exporter": kwargs["name"], "run_dir": kwargs["run_dir"]},
    )

    rc = auditex_cli.main(["export", "run", "html", "run-a"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exporter"] == "html"
    assert payload["run_dir"] == "run-a"


def test_notify_send_cli_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.send_notification",
        lambda **kwargs: {"sink": kwargs["sink"], "dry_run": kwargs["dry_run"]},
    )

    rc = auditex_cli.main(["notify", "send", "run-a", "--sink", "teams"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sink"] == "teams"
    assert payload["dry_run"] is True


def test_guided_parser_accepts_local_mode_flags() -> None:
    args = build_guided_parser().parse_args(
        [
            "--tenant-id",
            "contoso.onmicrosoft.com",
            "--local-mode",
            "--skip-login-check",
            "--skip-tool-check",
            "--report-format",
            "csv",
        ]
    )

    assert args.local_mode is True
    assert args.skip_login_check is True
    assert args.skip_tool_check is True
    assert args.report_format == "csv"


def test_guided_run_requires_exchange_login_when_requested(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {"azure_cli": {"status": "supported"}},
            "readiness": {"core_ready": True, "exchange_ready": True},
        },
    )
    monkeypatch.setattr(guided, "_ensure_exchange_module", lambda **_: 0)
    monkeypatch.setattr(guided, "_ensure_m365_login", lambda tenant_id, browser_command: 5)
    monkeypatch.setattr("auditex.guided.tenant_cli.main", lambda *args, **kwargs: 0)

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--tenant-id",
                "contoso.onmicrosoft.com",
                "--tenant-name",
                "CONTOSO",
                "--out",
                str(tmp_path),
                "--include-exchange",
                "--non-interactive",
            ]
        )
    )

    assert rc == 5


def test_guided_run_exchange_setup_adds_pwsh(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {"azure_cli": {"status": "supported"}},
            "readiness": {"core_ready": True, "exchange_ready": False},
        },
    )
    monkeypatch.setattr(guided, "run_setup", lambda **kwargs: seen.update(kwargs) or 0)
    monkeypatch.setattr(guided, "_ensure_exchange_module", lambda **_: 0)
    monkeypatch.setattr(guided, "_ensure_m365_login", lambda tenant_id, browser_command: 0)
    monkeypatch.setattr("auditex.guided.tenant_cli.main", lambda *args, **kwargs: 0)

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--tenant-id",
                "contoso.onmicrosoft.com",
                "--tenant-name",
                "CONTOSO",
                "--out",
                str(tmp_path),
                "--include-exchange",
                "--non-interactive",
            ]
        )
    )

    assert rc == 0
    assert seen == {"with_mcp": False, "with_exchange": True, "with_pwsh": True}
