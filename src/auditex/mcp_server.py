from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import auth as auditex_auth
from azure_tenant_audit.diffing import diff_run_directories
from azure_tenant_audit.profiles import PROFILES

SUPPORTED_PLANES = ("inventory", "full")
SUPPORTED_PROBE_MODES = ("delegated", "app", "response")


def tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "auditex_list_profiles",
            "description": "List built-in delegated and app-readonly audit profiles.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_auth_status",
            "description": "Show local Auditex auth state, including Azure CLI and saved m365 connections.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_auth_list",
            "description": "List saved m365 connections for the local Auditex operator environment.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_auth_use",
            "description": "Switch the active saved m365 connection.",
            "readOnlyHint": False,
        },
        {
            "name": "auditex_run_offline_validation",
            "description": "Run the offline sample audit to validate local packaging without tenant access.",
            "readOnlyHint": False,
        },
        {
            "name": "auditex_run_delegated_audit",
            "description": "Run the Azure CLI token or supplied-token audit path against a tenant and return the run manifest path.",
            "readOnlyHint": False,
        },
        {
            "name": "auditex_summarize_run",
            "description": "Read a completed run directory and return summary, manifest, and diagnostics paths.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_diff_runs",
            "description": "Compare normalized snapshots between two completed run directories.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_probe_live",
            "description": "Run a live capability probe against a tenant and emit capability/toolchain/blocker artifacts.",
            "readOnlyHint": False,
        },
        {
            "name": "auditex_probe_summarize",
            "description": "Read a completed probe run and return capability, toolchain, and blocker artifact paths.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_list_blockers",
            "description": "Read blocker artifacts from a completed audit or probe run.",
            "readOnlyHint": True,
        },
    ]


def build_cli_command(
    *,
    tenant_name: str,
    out_dir: str,
    tenant_id: str | None = None,
    auditor_profile: str = "global-reader",
    plane: str = "inventory",
    use_azure_cli_token: bool = True,
    access_token: str | None = None,
    include_exchange: bool = False,
    collectors: str | None = None,
    since: str | None = None,
    until: str | None = None,
    offline: bool = False,
    sample_path: str = "examples/sample_audit_bundle/sample_result.json",
) -> list[str]:
    if plane not in SUPPORTED_PLANES:
        raise ValueError(f"Unsupported plane '{plane}'. Supported planes: {', '.join(SUPPORTED_PLANES)}")
    command = [sys.executable, "-m", "azure_tenant_audit", "--tenant-name", tenant_name, "--out", out_dir]
    if tenant_id:
        command.extend(["--tenant-id", tenant_id])
    command.extend(["--auditor-profile", auditor_profile])
    command.extend(["--plane", plane])
    if include_exchange:
        command.append("--include-exchange")
    if collectors:
        command.extend(["--collectors", collectors])
    if since:
        command.extend(["--since", since])
    if until:
        command.extend(["--until", until])
    if offline:
        command.extend(["--offline", "--sample", sample_path])
        return command
    if access_token:
        command.extend(["--access-token", access_token])
    elif use_azure_cli_token:
        command.append("--use-azure-cli-token")
    return command


def build_probe_command(
    *,
    tenant_name: str,
    out_dir: str,
    tenant_id: str | None = None,
    auditor_profile: str = "global-reader",
    mode: str = "delegated",
    surface: str = "all",
    since: str | None = None,
    until: str | None = None,
    allow_lab_response: bool = False,
    use_azure_cli_token: bool = True,
    access_token: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> list[str]:
    if mode not in SUPPORTED_PROBE_MODES:
        raise ValueError(f"Unsupported probe mode '{mode}'. Supported modes: {', '.join(SUPPORTED_PROBE_MODES)}")
    command = [sys.executable, "-m", "auditex", "probe", "live", "--tenant-name", tenant_name, "--out", out_dir]
    if tenant_id:
        command.extend(["--tenant-id", tenant_id])
    command.extend(["--auditor-profile", auditor_profile, "--mode", mode, "--surface", surface])
    if since:
        command.extend(["--since", since])
    if until:
        command.extend(["--until", until])
    if allow_lab_response:
        command.append("--allow-lab-response")
    if access_token:
        command.extend(["--access-token", access_token])
    elif use_azure_cli_token and mode == "delegated":
        command.append("--use-azure-cli-token")
    if client_id:
        command.extend(["--client-id", client_id])
    if client_secret:
        command.extend(["--client-secret", client_secret])
    return command


def run_cli_command(command: list[str], cwd: str | None = None) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def summarize_run(run_dir: str) -> dict[str, Any]:
    path = Path(run_dir)
    manifest_path = path / "run-manifest.json"
    summary_path = path / "summary.json"
    diagnostics_path = path / "diagnostics.json"
    result: dict[str, Any] = {
        "run_dir": str(path),
        "manifest_path": str(manifest_path),
        "summary_path": str(summary_path),
        "diagnostics_path": str(diagnostics_path),
    }
    if manifest_path.exists():
        result["manifest"] = json.loads(manifest_path.read_text(encoding="utf-8"))
    if summary_path.exists():
        result["summary"] = json.loads(summary_path.read_text(encoding="utf-8"))
    if diagnostics_path.exists():
        result["diagnostics"] = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    capability_matrix_path = path / "capability-matrix.json"
    toolchain_readiness_path = path / "toolchain-readiness.json"
    blockers_path = path / "blockers" / "blockers.json"
    if capability_matrix_path.exists():
        result["capability_matrix_path"] = str(capability_matrix_path)
        result["capability_matrix"] = json.loads(capability_matrix_path.read_text(encoding="utf-8"))
    if toolchain_readiness_path.exists():
        result["toolchain_readiness_path"] = str(toolchain_readiness_path)
        result["toolchain_readiness"] = json.loads(toolchain_readiness_path.read_text(encoding="utf-8"))
    if blockers_path.exists():
        result["blockers_path"] = str(blockers_path)
        result["blockers"] = json.loads(blockers_path.read_text(encoding="utf-8"))
    return result


def diff_runs(run_a: str, run_b: str) -> dict[str, Any]:
    return diff_run_directories(run_a, run_b)


def list_blockers(run_dir: str) -> dict[str, Any]:
    path = Path(run_dir) / "blockers" / "blockers.json"
    result = {"run_dir": run_dir, "blockers_path": str(path)}
    if path.exists():
        result["blockers"] = json.loads(path.read_text(encoding="utf-8"))
    return result


def main() -> int:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install Auditex with the MCP extra: pip install -e '.[mcp]'", file=sys.stderr)
        return 2

    server = FastMCP("auditex")

    @server.tool
    def auditex_list_profiles() -> dict[str, Any]:
        return {"profiles": [profile.__dict__ for profile in PROFILES.values()]}

    @server.tool
    def auditex_auth_status() -> dict[str, Any]:
        return auditex_auth.get_auth_status()

    @server.tool
    def auditex_auth_list() -> dict[str, Any]:
        return auditex_auth.list_connections()

    @server.tool
    def auditex_auth_use(connection_name: str) -> dict[str, Any]:
        return auditex_auth.use_connection(connection_name)

    @server.tool
    def auditex_run_offline_validation(
        tenant_name: str,
        out_dir: str = "outputs/offline",
        sample_path: str = "examples/sample_audit_bundle/sample_result.json",
    ) -> dict[str, Any]:
        command = build_cli_command(
            tenant_name=tenant_name,
            out_dir=out_dir,
            auditor_profile="auto",
            offline=True,
            sample_path=sample_path,
        )
        return run_cli_command(command)

    @server.tool
    def auditex_run_delegated_audit(
        tenant_name: str,
        tenant_id: str = "organizations",
        out_dir: str = "outputs/live",
        auditor_profile: str = "global-reader",
        plane: str = "inventory",
        include_exchange: bool = False,
        collectors: str = "",
        since: str = "",
        until: str = "",
    ) -> dict[str, Any]:
        command = build_cli_command(
            tenant_name=tenant_name,
            tenant_id=tenant_id,
            out_dir=out_dir,
            auditor_profile=auditor_profile,
            plane=plane,
            use_azure_cli_token=True,
            include_exchange=include_exchange,
            collectors=collectors or None,
            since=since or None,
            until=until or None,
        )
        return run_cli_command(command)

    @server.tool
    def auditex_summarize_run(run_dir: str) -> dict[str, Any]:
        return summarize_run(run_dir)

    @server.tool
    def auditex_diff_runs(run_a: str, run_b: str) -> dict[str, Any]:
        return diff_runs(run_a, run_b)

    @server.tool
    def auditex_probe_live(
        tenant_name: str,
        tenant_id: str = "organizations",
        out_dir: str = "outputs/probes",
        auditor_profile: str = "global-reader",
        mode: str = "delegated",
        surface: str = "all",
        since: str = "",
        until: str = "",
        allow_lab_response: bool = False,
        client_id: str = "",
        client_secret: str = "",
    ) -> dict[str, Any]:
        command = build_probe_command(
            tenant_name=tenant_name,
            tenant_id=tenant_id,
            out_dir=out_dir,
            auditor_profile=auditor_profile,
            mode=mode,
            surface=surface,
            since=since or None,
            until=until or None,
            allow_lab_response=allow_lab_response,
            client_id=client_id or None,
            client_secret=client_secret or None,
        )
        return run_cli_command(command)

    @server.tool
    def auditex_probe_summarize(run_dir: str) -> dict[str, Any]:
        return summarize_run(run_dir)

    @server.tool
    def auditex_list_blockers(run_dir: str) -> dict[str, Any]:
        return list_blockers(run_dir)

    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
