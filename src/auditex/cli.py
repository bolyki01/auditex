from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import auth as auditex_auth
from .bootstrap import print_doctor_report, run_setup
from .guided import build_guided_parser, run_guided
from .rules import list_rule_inventory
from azure_tenant_audit.cli import main as tenant_audit_main
from azure_tenant_audit.diffing import diff_run_directories
from azure_tenant_audit.probe import ProbeConfig, probe_mode_choices, run_live_probe
from azure_tenant_audit.response import ResponseConfig, response_actions, run_response

from .mcp_server import list_blockers, summarize_run
from .sentry_runtime import init_sentry


def _build_root_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditex",
        description="Auditex operator CLI.",
        epilog="Use `auditex run ...` for explicit raw audit runs. Legacy raw flags like `auditex --tenant-name ...` still work.",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("setup", help="Bootstrap local runtime dependencies.")
    subparsers.add_parser("doctor", help="Show local runtime and auth readiness.")
    subparsers.add_parser("guided-run", help="Run the guided operator flow.")
    subparsers.add_parser("run", help="Run a raw tenant audit.")
    subparsers.add_parser("probe", help="Run or summarize capability probes.")
    subparsers.add_parser("response", help="Run guarded response actions.")
    subparsers.add_parser("compare", help="Compare completed runs.")
    subparsers.add_parser("report", help="Preview or render reports from a run.")
    subparsers.add_parser("export", help="List and run exporters.")
    subparsers.add_parser("notify", help="Build or send post-run notifications.")
    subparsers.add_parser("rules", help="Inspect built-in rule packs.")
    subparsers.add_parser("auth", help="Inspect and manage local auth state.")
    return parser


def compare_runs(run_dirs: list[str], *, allow_cross_tenant: bool = False) -> dict[str, object]:
    from .compare import compare_runs as _compare_runs

    return _compare_runs(run_dirs, allow_cross_tenant=allow_cross_tenant)


def render_report(
    *,
    run_dir: str,
    format_name: str,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
    output_path: str | None = None,
) -> dict[str, object]:
    from .reporting import render_report as _render_report

    return _render_report(
        run_dir=run_dir,
        format_name=format_name,
        include_sections=include_sections,
        exclude_sections=exclude_sections,
        output_path=output_path,
    )


def list_exporters() -> list[dict[str, object]]:
    from .exporters import list_exporters as _list_exporters

    return _list_exporters()


def run_exporter(
    *,
    name: str,
    run_dir: str,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
    output_path: str | None = None,
) -> dict[str, object]:
    from .exporters import run_exporter as _run_exporter

    return _run_exporter(
        name=name,
        run_dir=run_dir,
        include_sections=include_sections,
        exclude_sections=exclude_sections,
        output_path=output_path,
    )


def send_notification(*, run_dir: str, sink: str, dry_run: bool = True) -> dict[str, object]:
    from .notify import send_notification as _send_notification

    return _send_notification(run_dir=run_dir, sink=sink, dry_run=dry_run)


def _build_probe_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditex probe", description="Run live capability probes against a tenant.")
    subparsers = parser.add_subparsers(dest="probe_command", required=True)

    live = subparsers.add_parser("live", help="Run a live capability probe.")
    live.add_argument("--tenant-name", required=True, help="Label for the probe output folder.")
    live.add_argument("--tenant-id", default=None, help="Entra tenant ID.")
    live.add_argument("--auditor-profile", default="global-reader", help="Audit profile for escalation guidance.")
    live.add_argument("--mode", default="delegated", choices=probe_mode_choices(), help="Probe auth and execution mode.")
    live.add_argument("--surface", default="all", help="Surface family to probe, or comma-separated list.")
    live.add_argument("--out", default="outputs/probes", help="Base output directory.")
    live.add_argument("--run-name", default=None, help="Optional probe run name.")
    live.add_argument("--since", default=None, help="Optional ISO8601 lower bound for time-windowed surfaces.")
    live.add_argument("--until", default=None, help="Optional ISO8601 upper bound for time-windowed surfaces.")
    live.add_argument("--top", type=int, default=5, help="Per-surface result limit for probe requests.")
    live.add_argument("--page-size", type=int, default=5, help="Per-request page size for probe requests.")
    live.add_argument("--access-token", default=None, help="Optional preissued Graph access token.")
    live.add_argument("--auth-context", default=None, help="Saved local auth context name to use for probe execution.")
    live.add_argument("--use-azure-cli-token", action="store_true", help="Use Azure CLI Graph token for delegated probes.")
    live.add_argument("--client-id", default=None, help="App registration ID for app probe mode.")
    live.add_argument("--client-secret", default=None, help="App secret for app probe mode.")
    live.add_argument("--authority", default="https://login.microsoftonline.com/", help="Identity authority URL.")
    live.add_argument("--graph-scope", default="https://graph.microsoft.com/.default", help="Graph scope.")
    live.add_argument("--allow-lab-response", action="store_true", help="Allow response readiness probes against configured lab tenants only.")
    live.add_argument(
        "--permission-hints",
        default="configs/collector-permissions.json",
        help="Collector permission matrix used to classify probe blockers.",
    )

    summarize = subparsers.add_parser("summarize", help="Summarize an existing probe run.")
    summarize.add_argument("run_dir", help="Probe run directory.")
    return parser


def _build_auth_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditex auth", description="Inspect and manage local Auditex auth state.")
    subparsers = parser.add_subparsers(dest="auth_command", required=True)

    subparsers.add_parser("status", help="Show Azure CLI, local auth env, and active m365 connection state.")
    subparsers.add_parser("list", help="List saved m365 connections.")
    use = subparsers.add_parser("use", help="Switch the active m365 connection.")
    use.add_argument("connection_name", help="Saved m365 connection name.")

    export_env = subparsers.add_parser("export-env", help="Show the effective local auth env values.")
    export_env.add_argument("--format", choices=("json", "shell"), default="json")

    login = subparsers.add_parser("login", help="Run delegated or app m365 login.")
    login.add_argument("--mode", choices=("delegated", "app"), default="delegated")
    login.add_argument("--tenant-id", default=None)
    login.add_argument("--connection-name", default=None)
    login.add_argument("--auth-type", default=None)
    login.add_argument("--app-id", default=None)
    login.add_argument("--client-secret", default=None)

    import_token = subparsers.add_parser("import-token", help="Save a customer-provided Graph bearer token as a local auth context.")
    import_token.add_argument("--name", required=True, help="Saved auth context name.")
    import_token.add_argument("--token", required=True, help="Bearer token or JWT access token.")
    import_token.add_argument("--tenant-id", default=None)

    inspect_token = subparsers.add_parser("inspect-token", help="Decode a Graph bearer token locally without sending it anywhere.")
    inspect_token.add_argument("--token", required=True, help="Bearer token or JWT access token.")

    capability = subparsers.add_parser("capability", help="Show collector capability for a saved auth context.")
    capability.add_argument("--name", default=None, help="Saved auth context name. Defaults to active context.")
    capability.add_argument("--collectors", required=True, help="Comma-separated collector IDs to evaluate.")
    capability.add_argument("--auditor-profile", default="auto")
    return parser


def _build_response_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditex response", description="Run guarded response actions.")
    subparsers = parser.add_subparsers(dest="response_command", required=True)

    run = subparsers.add_parser("run", help="Plan or execute a guarded response action.")
    run.add_argument("--tenant-name", required=True, help="Label for the response output folder.")
    run.add_argument("--tenant-id", default=None, help="Entra tenant ID.")
    run.add_argument(
        "--auditor-profile",
        default="exchange-reader",
        choices=("exchange-reader", "app-readonly-full", "global-reader", "security-reader", "auto"),
        help="Response profile gate.",
    )
    run.add_argument("--action", choices=response_actions(), required=True, help="Response action to plan or execute.")
    run.add_argument("--target", default=None, help="Target recipient, user, or object depending on action.")
    run.add_argument("--intent", required=True, help="Explicit intent text for the response action.")
    run.add_argument("--since", default=None, help="Optional ISO8601 lower bound for time-windowed actions.")
    run.add_argument("--until", default=None, help="Optional ISO8601 upper bound for time-windowed actions.")
    run.add_argument("--out", default="outputs/response", help="Base output directory.")
    run.add_argument("--run-name", default=None, help="Optional run name.")
    run.add_argument("--execute", action="store_true", help="Execute the command plan instead of dry-running it.")
    run.add_argument("--allow-write", action="store_true", help="Allow destructive actions when a response action is classified as write-capable.")
    run.add_argument("--allow-lab-response", action="store_true", help="Allow the response plane for configured lab tenants only.")
    run.add_argument("--auth-context", default=None, help="Saved local auth context name to use for response execution.")
    run.add_argument("--adapter-override", default=None, help="Override the adapter used for the response action.")
    run.add_argument("--command-override", default=None, help="Override the command template used for the response action.")

    subparsers.add_parser("list-actions", help="List available guarded response actions.")
    return parser


def _build_rules_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditex rules", description="Inspect built-in Auditex rule packs.")
    subparsers = parser.add_subparsers(dest="rules_command", required=True)
    inventory = subparsers.add_parser("inventory", help="List rule inventory rows.")
    inventory.add_argument("--tag", default=None, help="Optional rule tag filter.")
    inventory.add_argument("--path-prefix", default=None, help="Optional path prefix filter.")
    inventory.add_argument("--product-family", default=None, help="Optional product family filter.")
    inventory.add_argument("--license-tier", default=None, help="Optional license tier filter.")
    inventory.add_argument("--audit-level", default=None, help="Optional audit level filter.")
    return parser


def _build_compare_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditex compare", description="Compare multiple completed run directories.")
    parser.add_argument("--run-dir", action="append", required=True, dest="run_dirs", help="Run directory to compare.")
    parser.add_argument("--allow-cross-tenant", action="store_true", help="Allow comparing runs from different tenants.")
    return parser


def _build_report_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditex report", description="Render reports from a completed run.")
    subparsers = parser.add_subparsers(dest="report_command", required=True)
    render = subparsers.add_parser("render", help="Render a report bundle in one format.")
    render.add_argument("run_dir", help="Completed run directory.")
    render.add_argument("--format", required=True, choices=("json", "md", "csv", "html"))
    render.add_argument("--include-section", action="append", default=None)
    render.add_argument("--exclude-section", action="append", default=None)
    render.add_argument("--output", default=None)
    return parser


def _build_export_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditex export", description="List and run offline exporters.")
    subparsers = parser.add_subparsers(dest="export_command", required=True)
    subparsers.add_parser("list", help="List available exporters.")
    run = subparsers.add_parser("run", help="Run one exporter.")
    run.add_argument("exporter_name")
    run.add_argument("run_dir")
    run.add_argument("--include-section", action="append", default=None)
    run.add_argument("--exclude-section", action="append", default=None)
    run.add_argument("--output", default=None)
    return parser


def _build_notify_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditex notify", description="Create or send post-run notifications.")
    subparsers = parser.add_subparsers(dest="notify_command", required=True)
    send = subparsers.add_parser("send", help="Build or send a notification from a run bundle.")
    send.add_argument("run_dir")
    send.add_argument("--sink", required=True, choices=("teams", "slack", "smtp"))
    send.add_argument("--execute", action="store_true", help="Send instead of dry-run.")
    return parser


def main(argv: list[str] | None = None) -> int:
    init_sentry()

    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv:
        _build_root_parser().print_help()
        return 0
    if argv[0] in {"-h", "--help", "help"}:
        _build_root_parser().print_help()
        return 0
    if argv[0].startswith("-"):
        return tenant_audit_main(argv)
    if argv[0] == "setup":
        parser = argparse.ArgumentParser(prog="auditex setup", description="Bootstrap local Auditex prerequisites.")
        parser.add_argument("--mcp", action="store_true", help="Install optional MCP extras during bootstrap.")
        parser.add_argument("--exchange", action="store_true", help="Install optional Exchange adapter tooling.")
        parser.add_argument("--pwsh", action="store_true", help="Install optional PowerShell runtime.")
        args = parser.parse_args(argv[1:])
        setup_kwargs: dict[str, object] = {"with_mcp": args.mcp}
        if args.exchange:
            setup_kwargs["with_exchange"] = True
        if args.pwsh:
            setup_kwargs["with_pwsh"] = True
        return run_setup(**setup_kwargs)
    if argv[0] == "doctor":
        parser = argparse.ArgumentParser(prog="auditex doctor", description="Inspect local tool and auth readiness.")
        parser.add_argument("--json", action="store_true", help="Print JSON report.")
        args = parser.parse_args(argv[1:])
        return print_doctor_report(json_output=args.json)
    if argv[0] == "guided-run":
        parser = build_guided_parser()
        args = parser.parse_args(argv[1:])
        return run_guided(args)
    if argv[0] == "rules":
        parser = _build_rules_parser()
        args = parser.parse_args(argv[1:])
        if args.rules_command == "inventory":
            filters: dict[str, object] = {}
            if args.tag is not None:
                filters["tag"] = args.tag
            if args.path_prefix is not None:
                filters["path_prefix"] = args.path_prefix
            if args.product_family is not None:
                filters["product_family"] = args.product_family
            if args.license_tier is not None:
                filters["license_tier"] = args.license_tier
            if args.audit_level is not None:
                filters["audit_level"] = args.audit_level
            rows = sorted(
                list_rule_inventory(**filters),
                key=lambda item: item.get("name", ""),
            )
            print(json.dumps({"count": len(rows), "rules": rows}, indent=2))
            return 0
        return 2
    if argv[0] == "compare":
        parser = _build_compare_parser()
        args = parser.parse_args(argv[1:])
        print(json.dumps(compare_runs(args.run_dirs, allow_cross_tenant=args.allow_cross_tenant), indent=2))
        return 0
    if argv[0] == "report":
        parser = _build_report_parser()
        args = parser.parse_args(argv[1:])
        if args.report_command != "render":
            return 2
        print(
            json.dumps(
                render_report(
                    run_dir=args.run_dir,
                    format_name=args.format,
                    include_sections=args.include_section,
                    exclude_sections=args.exclude_section,
                    output_path=args.output,
                ),
                indent=2,
            )
        )
        return 0
    if argv[0] == "export":
        parser = _build_export_parser()
        args = parser.parse_args(argv[1:])
        if args.export_command == "list":
            print(json.dumps({"exporters": list_exporters()}, indent=2))
            return 0
        if args.export_command == "run":
            print(
                json.dumps(
                    run_exporter(
                        name=args.exporter_name,
                        run_dir=args.run_dir,
                        include_sections=args.include_section,
                        exclude_sections=args.exclude_section,
                        output_path=args.output,
                    ),
                    indent=2,
                )
            )
            return 0
        return 2
    if argv[0] == "notify":
        parser = _build_notify_parser()
        args = parser.parse_args(argv[1:])
        if args.notify_command != "send":
            return 2
        print(json.dumps(send_notification(run_dir=args.run_dir, sink=args.sink, dry_run=not args.execute), indent=2))
        return 0
    if argv[0] == "auth":
        parser = _build_auth_parser()
        args = parser.parse_args(argv[1:])
        if args.auth_command == "status":
            print(json.dumps(auditex_auth.get_auth_status(), indent=2))
            return 0
        if args.auth_command == "list":
            print(json.dumps(auditex_auth.list_connections(), indent=2))
            return 0
        if args.auth_command == "use":
            print(json.dumps(auditex_auth.use_connection(args.connection_name), indent=2))
            return 0
        if args.auth_command == "export-env":
            payload = auditex_auth.export_env()
            if args.format == "shell":
                for key, value in (payload.get("values") or {}).items():
                    print(f"{key}={value}")
            else:
                print(json.dumps(payload, indent=2))
            return 0
        if args.auth_command == "login":
            return auditex_auth.login_connection(
                mode=args.mode,
                tenant_id=args.tenant_id,
                connection_name=args.connection_name,
                auth_type=args.auth_type,
                app_id=args.app_id,
                client_secret=args.client_secret,
            )
        if args.auth_command == "import-token":
            print(
                json.dumps(
                    auditex_auth.import_token_context(
                        name=args.name,
                        token=args.token,
                        tenant_id=args.tenant_id,
                    ),
                    indent=2,
                )
            )
            return 0
        if args.auth_command == "inspect-token":
            print(json.dumps(auditex_auth.inspect_token_claims(args.token), indent=2))
            return 0
        if args.auth_command == "capability":
            print(
                json.dumps(
                    auditex_auth.capability_for_context(
                        name=args.name,
                        collectors=[item.strip() for item in args.collectors.split(",") if item.strip()],
                        auditor_profile=args.auditor_profile,
                    ),
                    indent=2,
                )
            )
            return 0
        return 2
    if argv[0] == "run":
        return tenant_audit_main(argv[1:])
    if argv[0] == "summarize":
        if len(argv) != 2:
            print("usage: auditex summarize <run-dir>", file=sys.stderr)
            return 2
        print(json.dumps(summarize_run(argv[1]), indent=2))
        return 0
    if argv[0] == "blockers":
        if len(argv) != 2:
            print("usage: auditex blockers <run-dir>", file=sys.stderr)
            return 2
        print(json.dumps(list_blockers(argv[1]), indent=2))
        return 0
    if argv[0] == "diff":
        if len(argv) != 3:
            print("usage: auditex diff <run-a> <run-b>", file=sys.stderr)
            return 2
        print(json.dumps(diff_run_directories(argv[1], argv[2]), indent=2))
        return 0
    if argv[0] == "probe":
        parser = _build_probe_parser()
        args = parser.parse_args(argv[1:])
        if args.probe_command == "summarize":
            print(json.dumps(summarize_run(args.run_dir), indent=2))
            return 0
        if args.probe_command != "live":
            return 2
        cfg = ProbeConfig(
            tenant_name=args.tenant_name,
            output_dir=Path(args.out),
            tenant_id=args.tenant_id,
            auditor_profile=args.auditor_profile,
            mode=args.mode,
            surface=args.surface,
            run_name=args.run_name,
            since=args.since,
            until=args.until,
            top=args.top,
            page_size=args.page_size,
            access_token=args.access_token,
            auth_context=args.auth_context,
            use_azure_cli_token=args.use_azure_cli_token,
            client_id=args.client_id,
            client_secret=args.client_secret,
            authority=args.authority,
            graph_scope=args.graph_scope,
            allow_lab_response=args.allow_lab_response,
            permission_hints_path=Path(args.permission_hints),
        )
        return run_live_probe(cfg)
    if argv[0] == "response":
        parser = _build_response_parser()
        args = parser.parse_args(argv[1:])
        if args.response_command == "list-actions":
            print(json.dumps({"actions": response_actions()}, indent=2))
            return 0
        if args.response_command != "run":
            return 2
        cfg = ResponseConfig(
            tenant_name=args.tenant_name,
            out_dir=Path(args.out),
            action=args.action,
            tenant_id=args.tenant_id,
            target=args.target,
            intent=args.intent,
            since=args.since,
            until=args.until,
            auditor_profile=args.auditor_profile,
            run_name=args.run_name,
            execute=args.execute,
            allow_write=args.allow_write,
            allow_lab_response=args.allow_lab_response,
            auth_context=args.auth_context,
            adapter_override=args.adapter_override,
            command_override=args.command_override,
        )
        return run_response(cfg, command_line=argv)
    return tenant_audit_main(argv)
