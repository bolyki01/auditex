from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from azure_tenant_audit.config import CollectorConfig

from . import auth as auditex_auth
from azure_tenant_audit.diffing import diff_run_directories
from azure_tenant_audit.profiles import PROFILES
from azure_tenant_audit.adapters import ADAPTERS, list_adapters as _list_adapters
from azure_tenant_audit.response import response_actions
from azure_tenant_audit.contracts import contract_schema_manifest
from .rules import list_rule_inventory
SUPPORTED_PLANES = ("inventory", "full", "export")
SUPPORTED_PROBE_MODES = ("delegated", "app", "response")


def list_collectors(config_path: str = "configs/collector-definitions.json") -> dict[str, Any]:
    path = Path(config_path)
    if not path.exists():
        return {"error": "collector definitions file not found", "path": str(path)}
    try:
        config = CollectorConfig.from_path(path)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "path": str(path)}

    collectors = [
        {
            "name": name,
            "description": definition.description,
            "enabled": definition.enabled,
            "required_permissions": list(definition.required_permissions),
            "query_plan": list(definition.query_plan),
            "command_collectors": list(definition.command_collectors or []),
            "position": position,
        }
        for position, (name, definition) in enumerate(config.collectors.items())
    ]
    return {
        "path": str(path),
        "collectors": collectors,
        "default_order": config.default_order,
    }


def list_adapters() -> dict[str, Any]:
    adapters = _list_adapters()
    return {
        "adapters": adapters,
        "count": len(adapters),
    }


def list_response_actions() -> dict[str, Any]:
    actions = response_actions()
    return {
        "actions": actions,
        "count": len(actions),
    }


def tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "auditex_list_collectors",
            "description": "List collector IDs, required permissions, and query plans from the active definitions file.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_list_adapters",
            "description": "List configured adapters and their dependency requirements.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_list_response_actions",
            "description": "List guarded response actions exposed by the response plane.",
            "readOnlyHint": True,
        },
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
            "name": "auditex_auth_import_token",
            "description": "Store a customer-provided Graph bearer token as a local auth context.",
            "readOnlyHint": False,
        },
        {
            "name": "auditex_auth_inspect_token",
            "description": "Decode a Graph bearer token locally and return its claims summary.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_auth_capability",
            "description": "Map a saved auth context to collector capability and missing read permissions.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_contract_schema_manifest",
            "description": "List versioned output contract schemas shipped with this Auditex build.",
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
        {
            "name": "auditex_diff_runs",
            "description": "Compare normalized snapshots between two completed run directories.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_compare_runs",
            "description": "Compare multiple completed runs with same-tenant gating and timeline output.",
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
        {
            "name": "auditex_report_preview",
            "description": "Build an in-memory report preview for a completed run without writing files.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_export_list",
            "description": "List available report exporters.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_notify_preview",
            "description": "Build the dry-run notification payload for a completed run.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_rules_inventory",
            "description": "List built-in rule inventory rows with optional routing filters.",
            "readOnlyHint": True,
        },
        {
            "name": "auditex_run_response_action",
            "description": "Run a guarded response action in a separate response bundle.",
            "readOnlyHint": False,
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
    client_id: str | None = None,
    client_secret: str | None = None,
    include_exchange: bool = False,
    collectors: str | list[str] | None = None,
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
        if isinstance(collectors, str):
            selected_collectors = collectors
        else:
            selected_collectors = ",".join(collectors)
        if selected_collectors:
            command.extend(["--collectors", selected_collectors])
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
    else:
        if client_id:
            command.extend(["--client-id", client_id])
        if client_secret:
            command.extend(["--client-secret", client_secret])
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
    auth_context: str | None = None,
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
    elif auth_context:
        command.extend(["--auth-context", auth_context])
    elif use_azure_cli_token and mode == "delegated":
        command.append("--use-azure-cli-token")
    if client_id:
        command.extend(["--client-id", client_id])
    if client_secret:
        command.extend(["--client-secret", client_secret])
    return command


def build_response_command(
    *,
    tenant_name: str,
    out_dir: str,
    action: str,
    tenant_id: str | None = None,
    auditor_profile: str = "exchange-reader",
    target: str | None = None,
    intent: str = "",
    since: str | None = None,
    until: str | None = None,
    run_name: str | None = None,
    execute: bool = False,
    allow_write: bool = False,
    allow_lab_response: bool = False,
    auth_context: str | None = None,
    adapter_override: str | None = None,
    command_override: str | None = None,
) -> list[str]:
    supported_actions = response_actions()
    if action not in supported_actions:
        raise ValueError(f"Unsupported response action '{action}'. Supported actions: {', '.join(supported_actions)}")
    command = [sys.executable, "-m", "auditex", "response", "run", "--tenant-name", tenant_name, "--out", out_dir, "--action", action, "--intent", intent]
    if tenant_id:
        command.extend(["--tenant-id", tenant_id])
    if auditor_profile:
        command.extend(["--auditor-profile", auditor_profile])
    if target:
        command.extend(["--target", target])
    if since:
        command.extend(["--since", since])
    if until:
        command.extend(["--until", until])
    if run_name:
        command.extend(["--run-name", run_name])
    if execute:
        command.append("--execute")
    if allow_write:
        command.append("--allow-write")
    if allow_lab_response:
        command.append("--allow-lab-response")
    if auth_context:
        command.extend(["--auth-context", auth_context])
    if adapter_override:
        command.extend(["--adapter-override", adapter_override])
    if command_override:
        command.extend(["--command-override", command_override])
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
    summary_md_path = path / "summary.md"
    diagnostics_path = path / "diagnostics.json"
    result: dict[str, Any] = {
        "run_dir": str(path),
        "manifest_path": str(manifest_path),
        "summary_path": str(summary_path),
        "summary_md_path": str(summary_md_path),
        "diagnostics_path": str(diagnostics_path),
    }
    if manifest_path.exists():
        result["manifest"] = json.loads(manifest_path.read_text(encoding="utf-8"))
    if summary_path.exists():
        result["summary"] = json.loads(summary_path.read_text(encoding="utf-8"))
    if summary_md_path.exists():
        result["summary_md"] = summary_md_path.read_text(encoding="utf-8")
    if diagnostics_path.exists():
        result["diagnostics"] = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    capability_matrix_path = path / "capability-matrix.json"
    toolchain_readiness_path = path / "toolchain-readiness.json"
    probe_auth_context_path = path / "auth-context.json"
    normalized_capability_path = path / "normalized" / "capability_matrix.json"
    normalized_auth_context_path = path / "normalized" / "auth_context.json"
    normalized_coverage_ledger_path = path / "normalized" / "coverage_ledger.json"
    ai_context_path = path / "ai_context.json"
    validation_path = path / "validation.json"
    blockers_path = path / "blockers" / "blockers.json"
    findings_path = path / "findings" / "findings.json"
    report_pack_path = path / "reports" / "report-pack.json"
    action_plan_path = path / "reports" / "action-plan.json"
    evidence_db_path = path / "index" / "evidence.sqlite"
    if capability_matrix_path.exists():
        result["capability_matrix_path"] = str(capability_matrix_path)
        result["capability_matrix"] = json.loads(capability_matrix_path.read_text(encoding="utf-8"))
    elif normalized_capability_path.exists():
        result["capability_matrix_path"] = str(normalized_capability_path)
        result["capability_matrix"] = json.loads(normalized_capability_path.read_text(encoding="utf-8"))
    if toolchain_readiness_path.exists():
        result["toolchain_readiness_path"] = str(toolchain_readiness_path)
        result["toolchain_readiness"] = json.loads(toolchain_readiness_path.read_text(encoding="utf-8"))
    if probe_auth_context_path.exists():
        result["auth_context_path"] = str(probe_auth_context_path)
        result["auth_context"] = json.loads(probe_auth_context_path.read_text(encoding="utf-8"))
    elif normalized_auth_context_path.exists():
        result["auth_context_path"] = str(normalized_auth_context_path)
        result["auth_context"] = json.loads(normalized_auth_context_path.read_text(encoding="utf-8"))
    if normalized_coverage_ledger_path.exists():
        result["coverage_ledger_path"] = str(normalized_coverage_ledger_path)
        result["coverage_ledger"] = json.loads(normalized_coverage_ledger_path.read_text(encoding="utf-8"))
    if ai_context_path.exists():
        result["ai_context_path"] = str(ai_context_path)
        result["ai_context"] = json.loads(ai_context_path.read_text(encoding="utf-8"))
    if validation_path.exists():
        result["validation_path"] = str(validation_path)
        result["validation"] = json.loads(validation_path.read_text(encoding="utf-8"))
        result["contract_validation"] = {
            "valid": result["validation"].get("valid"),
            "issue_count": result["validation"].get("issue_count", 0),
            "contract_version": result["validation"].get("contract_version"),
        }
    if evidence_db_path.exists():
        result["evidence_db_path"] = str(evidence_db_path)
    if blockers_path.exists():
        result["blockers_path"] = str(blockers_path)
        result["blockers"] = json.loads(blockers_path.read_text(encoding="utf-8"))
    if findings_path.exists():
        result["findings_path"] = str(findings_path)
        result["findings"] = json.loads(findings_path.read_text(encoding="utf-8"))
    if report_pack_path.exists():
        result["report_pack_path"] = str(report_pack_path)
        result["report_pack"] = json.loads(report_pack_path.read_text(encoding="utf-8"))
    if action_plan_path.exists():
        result["action_plan_path"] = str(action_plan_path)
        result["action_plan"] = json.loads(action_plan_path.read_text(encoding="utf-8"))
    return result


def diff_runs(run_a: str, run_b: str) -> dict[str, Any]:
    return diff_run_directories(run_a, run_b)


def list_blockers(run_dir: str) -> dict[str, Any]:
    path = Path(run_dir) / "blockers" / "blockers.json"
    result = {"run_dir": run_dir, "blockers_path": str(path)}
    if path.exists():
        result["blockers"] = json.loads(path.read_text(encoding="utf-8"))
    return result


def compare_many_runs(run_dirs: list[str], allow_cross_tenant: bool = False) -> dict[str, Any]:
    from .compare import compare_runs

    return compare_runs(run_dirs, allow_cross_tenant=allow_cross_tenant)


def preview_report(
    run_dir: str,
    format_name: str = "json",
    include_sections: str = "",
    exclude_sections: str = "",
) -> dict[str, Any]:
    from .reporting import preview_report as _preview_report

    include = [item.strip() for item in include_sections.split(",") if item.strip()]
    exclude = [item.strip() for item in exclude_sections.split(",") if item.strip()]
    return _preview_report(
        run_dir=run_dir,
        format_name=format_name,
        include_sections=include or None,
        exclude_sections=exclude or None,
    )


def list_available_exporters() -> dict[str, Any]:
    from .exporters import list_exporters

    return {"exporters": list_exporters()}


def preview_notification(run_dir: str, sink: str = "teams") -> dict[str, Any]:
    from .notify import send_notification

    return send_notification(run_dir=run_dir, sink=sink, dry_run=True)


def rules_inventory(
    tag: str = "",
    path_prefix: str = "",
    product_family: str = "",
    license_tier: str = "",
    audit_level: str = "",
) -> dict[str, Any]:
    rows = list_rule_inventory(
        tag=tag or None,
        path_prefix=path_prefix or None,
        product_family=product_family or None,
        license_tier=license_tier or None,
        audit_level=audit_level or None,
    )
    return {"count": len(rows), "rules": rows}


def main() -> int:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install Auditex with the MCP extra: pip install -e '.[mcp]'", file=sys.stderr)
        return 2

    server = FastMCP("auditex")

    @server.tool()
    def auditex_list_profiles() -> dict[str, Any]:
        return {"profiles": [profile.__dict__ for profile in PROFILES.values()]}

    @server.tool()
    def auditex_list_collectors(config_path: str = "configs/collector-definitions.json") -> dict[str, Any]:
        return list_collectors(config_path=config_path)

    @server.tool()
    def auditex_list_adapters() -> dict[str, Any]:
        return list_adapters()

    @server.tool()
    def auditex_list_response_actions() -> dict[str, Any]:
        return list_response_actions()

    @server.tool()
    def auditex_auth_status() -> dict[str, Any]:
        return auditex_auth.get_auth_status()

    @server.tool()
    def auditex_auth_list() -> dict[str, Any]:
        return auditex_auth.list_connections()

    @server.tool()
    def auditex_auth_use(connection_name: str) -> dict[str, Any]:
        return auditex_auth.use_connection(connection_name)

    @server.tool()
    def auditex_auth_import_token(name: str, token: str, tenant_id: str = "") -> dict[str, Any]:
        return auditex_auth.import_token_context(name=name, token=token, tenant_id=tenant_id or None)

    @server.tool()
    def auditex_auth_inspect_token(token: str) -> dict[str, Any]:
        return auditex_auth.inspect_token_claims(token)

    @server.tool()
    def auditex_auth_capability(name: str = "", collectors: str = "", auditor_profile: str = "auto") -> dict[str, Any]:
        selected_collectors = [item.strip() for item in collectors.split(",") if item.strip()]
        return auditex_auth.capability_for_context(
            name=name or None,
            collectors=selected_collectors,
            auditor_profile=auditor_profile,
        )

    @server.tool()
    def auditex_contract_schema_manifest(schema_dir: str = "schemas") -> dict[str, Any]:
        return contract_schema_manifest(schema_dir=schema_dir)

    @server.tool()
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

    @server.tool()
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

    @server.tool()
    def auditex_summarize_run(run_dir: str) -> dict[str, Any]:
        return summarize_run(run_dir)

    @server.tool()
    def auditex_diff_runs(run_a: str, run_b: str) -> dict[str, Any]:
        return diff_runs(run_a, run_b)

    @server.tool()
    def auditex_compare_runs(run_dirs: list[str], allow_cross_tenant: bool = False) -> dict[str, Any]:
        return compare_many_runs(run_dirs, allow_cross_tenant=allow_cross_tenant)

    @server.tool()
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
        auth_context: str = "",
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
            auth_context=auth_context or None,
            client_id=client_id or None,
            client_secret=client_secret or None,
        )
        return run_cli_command(command)

    @server.tool()
    def auditex_probe_summarize(run_dir: str) -> dict[str, Any]:
        return summarize_run(run_dir)

    @server.tool()
    def auditex_list_blockers(run_dir: str) -> dict[str, Any]:
        return list_blockers(run_dir)

    @server.tool()
    def auditex_report_preview(
        run_dir: str,
        format_name: str = "json",
        include_sections: str = "",
        exclude_sections: str = "",
    ) -> dict[str, Any]:
        return preview_report(
            run_dir=run_dir,
            format_name=format_name,
            include_sections=include_sections,
            exclude_sections=exclude_sections,
        )

    @server.tool()
    def auditex_export_list() -> dict[str, Any]:
        return list_available_exporters()

    @server.tool()
    def auditex_notify_preview(run_dir: str, sink: str = "teams") -> dict[str, Any]:
        return preview_notification(run_dir=run_dir, sink=sink)

    @server.tool()
    def auditex_rules_inventory(
        tag: str = "",
        path_prefix: str = "",
        product_family: str = "",
        license_tier: str = "",
        audit_level: str = "",
    ) -> dict[str, Any]:
        return rules_inventory(
            tag=tag,
            path_prefix=path_prefix,
            product_family=product_family,
            license_tier=license_tier,
            audit_level=audit_level,
        )

    @server.tool()
    def auditex_run_response_action(
        tenant_name: str,
        action: str,
        tenant_id: str = "organizations",
        out_dir: str = "outputs/response",
        auditor_profile: str = "exchange-reader",
        target: str = "",
        intent: str = "",
        since: str = "",
        until: str = "",
        run_name: str = "",
        execute: bool = False,
        allow_write: bool = False,
        allow_lab_response: bool = False,
        auth_context: str = "",
        adapter_override: str = "",
        command_override: str = "",
    ) -> dict[str, Any]:
        command = build_response_command(
            tenant_name=tenant_name,
            out_dir=out_dir,
            action=action,
            tenant_id=tenant_id,
            auditor_profile=auditor_profile,
            target=target or None,
            intent=intent,
            since=since or None,
            until=until or None,
            run_name=run_name or None,
            execute=execute,
            allow_write=allow_write,
            allow_lab_response=allow_lab_response,
            auth_context=auth_context or None,
            adapter_override=adapter_override or None,
            command_override=command_override or None,
        )
        return run_cli_command(command)

    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
