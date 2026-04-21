from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditex import cli as auditex_cli
from auditex.mcp_server import (
    build_cli_command,
    build_response_command,
    build_probe_command,
    compare_many_runs,
    list_adapters,
    list_collectors,
    list_available_exporters,
    preview_notification,
    preview_report,
    rules_inventory,
    list_response_actions,
    summarize_run,
    tool_specs,
)
from azure_tenant_audit.cli import build_parser, run_offline
from azure_tenant_audit.profiles import get_profile, profile_choices


def test_profile_choices_include_global_reader() -> None:
    assert "global-reader" in profile_choices()
    assert "reports-reader" in profile_choices()
    assert get_profile("global-reader").name == "global-reader"
    assert "inventory" in get_profile("global-reader").supported_planes
    assert "sharepoint_access" in get_profile("global-reader").default_collectors
    assert "app_consent" in get_profile("global-reader").default_collectors
    assert "licensing" in get_profile("global-reader").default_collectors
    assert "service_health" in get_profile("global-reader").default_collectors
    assert "reports_usage" in get_profile("global-reader").default_collectors
    assert "external_identity" in get_profile("global-reader").default_collectors
    assert "consent_policy" in get_profile("global-reader").default_collectors
    assert "domains_hybrid" in get_profile("global-reader").default_collectors
    assert "onedrive_posture" in get_profile("global-reader").default_collectors


def test_parser_accepts_auditor_profile() -> None:
    args = build_parser().parse_args(["--tenant-name", "acme", "--offline", "--auditor-profile", "global-reader"])
    assert args.auditor_profile == "global-reader"


def test_parser_accepts_plane_and_time_window() -> None:
    args = build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--offline",
            "--plane",
            "full",
            "--since",
            "2026-04-01T00:00:00Z",
            "--until",
            "2026-04-02T00:00:00Z",
        ]
    )
    assert args.plane == "full"
    assert args.since == "2026-04-01T00:00:00Z"
    assert args.until == "2026-04-02T00:00:00Z"


def test_parser_rejects_unimplemented_response_plane() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--tenant-name", "acme", "--offline", "--plane", "response"])


def test_offline_manifest_records_profile(tmp_path: Path) -> None:
    sample = {"identity": {"value": [{"id": "1"}]}}
    sample_path = tmp_path / "sample.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")

    rc = run_offline(
        sample_path,
        tmp_path,
        "contoso",
        "run1",
        auditor_profile="global-reader",
        plane="full",
        since="2026-04-01T00:00:00Z",
        until="2026-04-02T00:00:00Z",
    )
    assert rc == 0

    manifest = json.loads((tmp_path / "contoso-run1" / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["auditor_profile"] == "global-reader"
    assert manifest["plane"] == "full"
    assert manifest["time_window"]["since"] == "2026-04-01T00:00:00Z"
    assert manifest["time_window"]["until"] == "2026-04-02T00:00:00Z"


def test_mcp_tool_specs_present() -> None:
    names = {item["name"] for item in tool_specs()}
    assert "auditex_run_delegated_audit" in names
    assert "auditex_summarize_run" in names
    assert "auditex_diff_runs" in names
    assert "auditex_compare_runs" in names
    assert "auditex_probe_live" in names
    assert "auditex_probe_summarize" in names
    assert "auditex_list_collectors" in names
    assert "auditex_list_adapters" in names
    assert "auditex_list_blockers" in names
    assert "auditex_report_preview" in names
    assert "auditex_export_list" in names
    assert "auditex_notify_preview" in names
    assert "auditex_rules_inventory" in names
    assert "auditex_list_response_actions" in names
    assert "auditex_run_response_action" in names


def test_list_collectors_tool_shape_matches_definitions() -> None:
    result = list_collectors()
    assert result["path"].endswith("configs/collector-definitions.json")
    assert isinstance(result["collectors"], list)
    collector_names = {item["name"] for item in result["collectors"]}
    assert {
        "identity",
        "security",
        "conditional_access",
        "defender",
        "service_health",
        "reports_usage",
        "external_identity",
        "consent_policy",
        "domains_hybrid",
        "onedrive_posture",
        "sharepoint_access",
        "app_consent",
        "licensing",
        "identity_governance",
        "intune_depth",
        "teams_policy",
        "exchange_policy",
    }.issubset(collector_names)


def test_list_adapters_tool_shape() -> None:
    result = list_adapters()
    assert result["count"] >= 1
    assert isinstance(result["adapters"], list)
    adapter_names = {item["name"] for item in result["adapters"]}
    assert {"m365_cli", "m365dsc", "powershell_graph"}.issubset(adapter_names)


def test_build_cli_command_uses_profile_and_cli_token() -> None:
    command = build_cli_command(
        tenant_name="ACME",
        tenant_id="contoso.onmicrosoft.com",
        out_dir="outputs/live",
        auditor_profile="global-reader",
        plane="full",
        since="2026-04-01T00:00:00Z",
        until="2026-04-02T00:00:00Z",
    )
    assert "--use-azure-cli-token" in command
    assert command[0]
    assert "--auditor-profile" in command
    assert "global-reader" in command
    assert "--plane" in command
    assert "full" in command
    assert "--since" in command
    assert "--until" in command


def test_build_cli_command_rejects_unimplemented_response_plane() -> None:
    with pytest.raises(ValueError, match="response"):
        build_cli_command(
            tenant_name="ACME",
            out_dir="outputs/live",
            plane="response",
        )


def test_build_probe_command_uses_mode_surface_and_lab_guard() -> None:
    command = build_probe_command(
        tenant_name="ACME",
        out_dir="outputs/probes",
        tenant_id="contoso.onmicrosoft.com",
        auditor_profile="global-reader",
        mode="response",
        surface="exchange",
        allow_lab_response=True,
        since="2026-04-01T00:00:00Z",
        until="2026-04-02T00:00:00Z",
    )
    assert command[:3] == [command[0], "-m", "auditex"]
    assert "probe" in command
    assert "live" in command
    assert "--mode" in command
    assert "response" in command
    assert "--surface" in command
    assert "exchange" in command
    assert "--allow-lab-response" in command
    assert "--since" in command
    assert "--until" in command


def test_build_probe_command_includes_app_credentials() -> None:
    command = build_probe_command(
        tenant_name="ACME",
        out_dir="outputs/probes",
        tenant_id="contoso.onmicrosoft.com",
        mode="app",
        client_id="app-id",
        client_secret="app-secret",
    )
    assert "--client-id" in command
    assert "app-id" in command
    assert "--client-secret" in command
    assert "app-secret" in command


def test_build_cli_command_can_use_app_credentials() -> None:
    command = build_cli_command(
        tenant_name="ACME",
        tenant_id="contoso.onmicrosoft.com",
        out_dir="outputs/live",
        use_azure_cli_token=False,
        client_id="app-id",
        client_secret="app-secret",
    )
    assert "--use-azure-cli-token" not in command
    assert "--client-id" in command
    assert "app-id" in command
    assert "--client-secret" in command
    assert "app-secret" in command


def test_build_probe_command_supports_saved_auth_context() -> None:
    command = build_probe_command(
        tenant_name="ACME",
        out_dir="outputs/probes",
        auditor_profile="global-reader",
        mode="delegated",
        auth_context="customer-token",
    )
    assert "--auth-context" in command
    assert "customer-token" in command
    assert "--use-azure-cli-token" not in command


def test_probe_parser_accepts_saved_auth_context() -> None:
    from auditex.cli import _build_probe_parser

    args = _build_probe_parser().parse_args(
        [
            "live",
            "--tenant-name",
            "ACME",
            "--auth-context",
            "customer-token",
        ]
    )
    assert args.auth_context == "customer-token"


def test_list_response_actions_shape() -> None:
    result = list_response_actions()
    assert result["count"] >= 1
    assert "message_trace" in result["actions"]


def test_build_response_command_uses_guarded_namespace() -> None:
    command = build_response_command(
        tenant_name="ACME",
        out_dir="outputs/response",
        action="message_trace",
        tenant_id="contoso.onmicrosoft.com",
        auditor_profile="exchange-reader",
        target="user@contoso.com",
        intent="triage mail flow",
        auth_context="customer-token",
    )
    assert command[:3] == [command[0], "-m", "auditex"]
    assert "response" in command
    assert "run" in command
    assert "--action" in command
    assert "message_trace" in command
    assert "--intent" in command
    assert "triage mail flow" in command


def test_build_response_command_supports_saved_auth_context() -> None:
    command = build_response_command(
        tenant_name="ACME",
        out_dir="outputs/response",
        action="message_trace",
        tenant_id="contoso.onmicrosoft.com",
        auditor_profile="exchange-reader",
        target="user@contoso.com",
        intent="triage mail flow",
        auth_context="customer-token",
    )
    assert "--auth-context" in command
    assert "customer-token" in command


def test_response_parser_accepts_saved_auth_context() -> None:
    from auditex.cli import _build_response_parser

    args = _build_response_parser().parse_args(
        [
            "run",
            "--tenant-name",
            "ACME",
            "--action",
            "message_trace",
            "--intent",
            "triage mail flow",
            "--auth-context",
            "customer-token",
        ]
    )
    assert args.auth_context == "customer-token"
    assert "--auth-context" in command
    assert "customer-token" in command


def test_response_parser_accepts_saved_auth_context() -> None:
    from auditex.cli import _build_response_parser

    args = _build_response_parser().parse_args(
        [
            "run",
            "--tenant-name",
            "ACME",
            "--action",
            "message_trace",
            "--intent",
            "triage mail flow",
            "--auth-context",
            "customer-token",
        ]
    )
    assert args.auth_context == "customer-token"


def test_summarize_run_reads_manifest(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run-manifest.json").write_text(json.dumps({"tenant_name": "acme"}), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run_dir / "summary.md").write_text("# Audit Summary", encoding="utf-8")

    summary = summarize_run(str(run_dir))
    assert summary["manifest"]["tenant_name"] == "acme"
    assert summary["summary_md_path"].endswith("summary.md")
    assert summary["summary_md"] == "# Audit Summary"


def test_summarize_run_reads_probe_artifacts(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run-manifest.json").write_text(json.dumps({"tenant_name": "acme"}), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run_dir / "capability-matrix.json").write_text(json.dumps([{"surface": "identity"}]), encoding="utf-8")
    (run_dir / "toolchain-readiness.json").write_text(json.dumps({"m365_cli": {"status": "blocked"}}), encoding="utf-8")

    summary = summarize_run(str(run_dir))
    assert summary["capability_matrix"][0]["surface"] == "identity"
    assert summary["toolchain_readiness"]["m365_cli"]["status"] == "blocked"


def test_summarize_run_reads_probe_auth_context_artifact(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run-manifest.json").write_text(json.dumps({"tenant_name": "acme"}), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run_dir / "auth-context.json").write_text(json.dumps({"name": "customer-token"}), encoding="utf-8")

    summary = summarize_run(str(run_dir))
    assert summary["auth_context"]["name"] == "customer-token"


def test_summarize_run_reads_response_auth_context_artifact(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run-manifest.json").write_text(
        json.dumps({"tenant_name": "acme", "auth_context_path": "auth-context.json"}),
        encoding="utf-8",
    )
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run_dir / "session-context.json").write_text(json.dumps({"tenant_id": "tenant-saved"}), encoding="utf-8")
    (run_dir / "auth-context.json").write_text(
        json.dumps(
            {
                "name": "customer-token",
                "auth_type": "imported_token",
                "tenant_id": "tenant-saved",
                "token_claims": {"delegated_scopes": ["Directory.Read.All"]},
            }
        ),
        encoding="utf-8",
    )

    summary = summarize_run(str(run_dir))
    assert summary["auth_context_path"].endswith("auth-context.json")
    assert summary["auth_context"]["name"] == "customer-token"
    assert summary["auth_context"]["tenant_id"] == "tenant-saved"


def test_summarize_run_reads_report_pack_and_action_plan_artifacts(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run-manifest.json").write_text(json.dumps({"tenant_name": "acme"}), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run_dir / "reports").mkdir()
    (run_dir / "reports" / "report-pack.json").write_text(
        json.dumps({"summary": {"overall_status": "partial"}, "findings": [], "evidence_paths": []}),
        encoding="utf-8",
    )
    (run_dir / "reports" / "action-plan.json").write_text(
        json.dumps({"open_findings": [], "waived_findings": [], "blocked": []}),
        encoding="utf-8",
    )

    summary = summarize_run(str(run_dir))

    assert summary["report_pack_path"].endswith("reports/report-pack.json")
    assert summary["report_pack"]["summary"]["overall_status"] == "partial"
    assert summary["action_plan_path"].endswith("reports/action-plan.json")
    assert summary["action_plan"]["blocked"] == []


def test_compare_many_runs_uses_same_tenant_gate(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    for name, run_dir in (("run-a", run_a), ("run-b", run_b)):
        run_dir.mkdir()
        (run_dir / "run-manifest.json").write_text(
            json.dumps(
                {
                    "tenant_name": "acme",
                    "tenant_id": "tenant-1",
                    "run_id": name,
                    "created_utc": "2026-04-18T09:00:00Z",
                }
            ),
            encoding="utf-8",
        )
        (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")

    result = compare_many_runs([str(run_a), str(run_b)])

    assert result["compare_context"]["same_tenant"] is True
    assert len(result["runs"]) == 2


def test_preview_report_and_notification_are_read_only_helpers(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run-manifest.json").write_text(json.dumps({"tenant_name": "acme"}), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run_dir / "reports").mkdir()
    (run_dir / "findings").mkdir()
    (run_dir / "reports" / "report-pack.json").write_text(
        json.dumps(
            {
                "summary": {"tenant_name": "acme", "overall_status": "partial", "finding_count": 1},
                "findings": [{"id": "finding-1", "title": "Fix sharing", "severity": "high", "status": "open"}],
                "action_plan": [{"id": "finding-1", "title": "Fix sharing", "severity": "high"}],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "reports" / "action-plan.json").write_text(
        json.dumps([{"id": "finding-1", "title": "Fix sharing", "severity": "high"}]),
        encoding="utf-8",
    )
    (run_dir / "findings" / "findings.json").write_text(
        json.dumps([{"id": "finding-1", "title": "Fix sharing", "severity": "high", "status": "open"}]),
        encoding="utf-8",
    )

    report = preview_report(str(run_dir), format_name="json")
    notification = preview_notification(str(run_dir), sink="teams")

    assert report["format"] == "json"
    assert "\"tenant_name\": \"acme\"" in report["content"]
    assert notification["dry_run"] is True
    assert notification["payload"]["tenant_name"] == "acme"


def test_export_list_and_rules_inventory_helpers_return_rows() -> None:
    exporters = list_available_exporters()
    rules = rules_inventory(product_family="identity")

    assert "exporters" in exporters
    assert exporters["exporters"]
    assert rules["count"] >= 1


def test_rules_inventory_cli_exports_sorted_json(monkeypatch, capsys) -> None:
    seen: dict[str, object] = {}

    def _fake_list_rule_inventory(*, tag=None, path_prefix=None):  # noqa: ANN001
        seen["tag"] = tag
        seen["path_prefix"] = path_prefix
        return [
            {"name": "zeta", "path": "rules/zeta.json"},
            {"name": "alpha", "path": "rules/alpha.json"},
        ]

    monkeypatch.setattr("auditex.cli.list_rule_inventory", _fake_list_rule_inventory)

    rc = auditex_cli.main(["rules", "inventory", "--tag", "now", "--path-prefix", "rules/"])

    assert rc == 0
    assert seen == {"tag": "now", "path_prefix": "rules/"}
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 2
    assert [item["name"] for item in payload["rules"]] == ["alpha", "zeta"]
