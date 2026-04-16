from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))
cli = importlib.import_module("azure_tenant_audit.cli")
output = importlib.import_module("azure_tenant_audit.output")


def test_build_parser_accepts_auditor_profile():
    parser = cli.build_parser()

    args = parser.parse_args(["--auditor-profile", cli.AUDITOR_PROFILE_GLOBAL_READER])

    assert args.auditor_profile == cli.AUDITOR_PROFILE_GLOBAL_READER


def test_invalid_auditor_profile_fails():
    parser = cli.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--auditor-profile", "viewer-only"])


def test_resolve_profile_from_auth_mode():
    assert (
        cli._resolve_audit_profile(cli.AUDITOR_PROFILE_AUTO, "app")
        == cli.AUDITOR_PROFILE_ENTERPRISE
    )
    assert (
        cli._resolve_audit_profile(cli.AUDITOR_PROFILE_AUTO, "azure_cli")
        == cli.AUDITOR_PROFILE_GLOBAL_READER
    )
    assert (
        cli._resolve_audit_profile(cli.AUDITOR_PROFILE_ENTERPRISE, "azure_cli")
        == cli.AUDITOR_PROFILE_ENTERPRISE
    )


def test_apply_profile_defaults_global_reader_only_when_not_explicit():
    available = ["identity", "security", "teams", "intune", "exchange"]

    with_explicit = cli._apply_profile_collector_defaults(
        ["identity", "security"], cli.AUDITOR_PROFILE_GLOBAL_READER, available
    )
    defaulted = cli._apply_profile_collector_defaults(
        None, cli.AUDITOR_PROFILE_GLOBAL_READER, available
    )

    assert with_explicit == ["identity", "security"]
    assert defaulted == ["identity", "security", "teams", "intune"]


def test_run_bundle_records_auditor_profile(tmp_path: Path):
    writer = output.AuditWriter(tmp_path, tenant_name="tenant", run_name="profile-test")
    writer.write_bundle(
        {
            "executed_by": "azure_tenant_audit",
            "collectors": ["identity"],
            "overall_status": "ok",
            "duration_seconds": 0.5,
            "mode": "live",
            "auditor_profile": cli.AUDITOR_PROFILE_GLOBAL_READER,
            "session_context": {},
            "command_line": ["python", "-m", "azure_tenant_audit"],
        }
    )

    manifest = json.loads((writer.run_dir / "run-manifest.json").read_text(encoding="utf-8"))

    assert manifest["auditor_profile"] == cli.AUDITOR_PROFILE_GLOBAL_READER


def test_audit_command_log_only_records_command_events(tmp_path: Path):
    logger = output.AuditLogger(tmp_path)
    logger.log("command.started", "command start")
    logger.log("graph.request.started", "graph request")
    logger.log("command.completed", "command complete")
    logger.log("collector.started", "collector start")
    logger.log("command.failed", "command failed")

    command_events = [
        json.loads(line)
        for line in (tmp_path / "audit-command-log.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    events = {entry["event"] for entry in command_events}

    assert events == {"command.started", "command.completed", "command.failed"}
