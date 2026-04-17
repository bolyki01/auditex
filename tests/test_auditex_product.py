from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditex.mcp_server import (
    build_cli_command,
    build_response_command,
    build_probe_command,
    list_adapters,
    list_collectors,
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
    assert "auditex_probe_live" in names
    assert "auditex_probe_summarize" in names
    assert "auditex_list_collectors" in names
    assert "auditex_list_adapters" in names
    assert "auditex_list_blockers" in names
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

    summary = summarize_run(str(run_dir))
    assert summary["manifest"]["tenant_name"] == "acme"


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
