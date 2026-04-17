from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import auth as auditex_auth
from azure_tenant_audit.cli import main as tenant_audit_main
from azure_tenant_audit.diffing import diff_run_directories
from azure_tenant_audit.probe import ProbeConfig, probe_mode_choices, run_live_probe

from .mcp_server import list_blockers, summarize_run


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
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv or argv[0].startswith("-"):
        return tenant_audit_main(argv)
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
            use_azure_cli_token=args.use_azure_cli_token,
            client_id=args.client_id,
            client_secret=args.client_secret,
            authority=args.authority,
            graph_scope=args.graph_scope,
            allow_lab_response=args.allow_lab_response,
            permission_hints_path=Path(args.permission_hints),
        )
        return run_live_probe(cfg)
    return tenant_audit_main(argv)
