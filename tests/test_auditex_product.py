from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditex.mcp_server import build_cli_command, summarize_run, tool_specs
from azure_tenant_audit.cli import build_parser, run_offline
from azure_tenant_audit.profiles import get_profile, profile_choices


def test_profile_choices_include_global_reader() -> None:
    assert "global-reader" in profile_choices()
    assert get_profile("global-reader").name == "global-reader"
    assert "inventory" in get_profile("global-reader").supported_planes


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


def test_summarize_run_reads_manifest(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run-manifest.json").write_text(json.dumps({"tenant_name": "acme"}), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")

    summary = summarize_run(str(run_dir))
    assert summary["manifest"]["tenant_name"] == "acme"
