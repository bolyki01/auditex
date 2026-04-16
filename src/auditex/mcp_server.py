from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from azure_tenant_audit.profiles import PROFILES


def tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "auditex_list_profiles",
            "description": "List built-in delegated and app-readonly audit profiles.",
            "readOnlyHint": True,
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
    ]


def build_cli_command(
    *,
    tenant_name: str,
    out_dir: str,
    tenant_id: str | None = None,
    auditor_profile: str = "global-reader",
    use_azure_cli_token: bool = True,
    access_token: str | None = None,
    include_exchange: bool = False,
    collectors: str | None = None,
    offline: bool = False,
    sample_path: str = "examples/sample_audit_bundle/sample_result.json",
) -> list[str]:
    command = [sys.executable, "-m", "azure_tenant_audit", "--tenant-name", tenant_name, "--out", out_dir]
    if tenant_id:
        command.extend(["--tenant-id", tenant_id])
    command.extend(["--auditor-profile", auditor_profile])
    if include_exchange:
        command.append("--include-exchange")
    if collectors:
        command.extend(["--collectors", collectors])
    if offline:
        command.extend(["--offline", "--sample", sample_path])
        return command
    if access_token:
        command.extend(["--access-token", access_token])
    elif use_azure_cli_token:
        command.append("--use-azure-cli-token")
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
        include_exchange: bool = False,
        collectors: str = "",
    ) -> dict[str, Any]:
        command = build_cli_command(
            tenant_name=tenant_name,
            tenant_id=tenant_id,
            out_dir=out_dir,
            auditor_profile=auditor_profile,
            use_azure_cli_token=True,
            include_exchange=include_exchange,
            collectors=collectors or None,
        )
        return run_cli_command(command)

    @server.tool
    def auditex_summarize_run(run_dir: str) -> dict[str, Any]:
        return summarize_run(run_dir)

    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
