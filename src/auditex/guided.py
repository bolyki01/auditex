from __future__ import annotations

import argparse
import os
import platform
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from azure_tenant_audit import cli as tenant_cli
from azure_tenant_audit.profiles import profile_choices

from . import auth as auditex_auth
from .bootstrap import build_doctor_report, run_setup


def _default_browser_command() -> str:
    if platform.system() == "Darwin":
        return "safari"
    return os.environ.get("BROWSER") or "firefox"


def _prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value or (default or "")


def _confirm(label: str, default: bool = True) -> bool:
    default_hint = "Y/n" if default else "y/N"
    value = input(f"{label} [{default_hint}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes"}


class ProgressRenderer:
    def __init__(self) -> None:
        self.collector_total = 0
        self.collector_done = 0

    def __call__(self, payload: dict[str, Any]) -> None:
        event = payload.get("event")
        details = payload.get("details") or {}
        if event == "preflight.started":
            print("Preflight: checking collector access")
            return
        if event == "preflight.collector.started":
            print(f"Preflight: {details.get('collector')}")
            return
        if event == "preflight.completed":
            print(
                "Preflight: "
                f"run {details.get('run_count', 0)}, "
                f"skip {details.get('skip_count', 0)}"
            )
            return
        if event == "run.started":
            self.collector_total = len(details.get("collectors") or [])
            self.collector_done = 0
            print(f"Run start: {self.collector_total} collectors")
            return
        if event == "collector.started":
            print(f"[{self.collector_done + 1}/{self.collector_total}] {details.get('collector')}")
            return
        if event == "collector.finished":
            self.collector_done += 1
            print(
                f"  {details.get('collector')}: "
                f"{details.get('status')} "
                f"items={details.get('item_count', 0)}"
            )
            return
        if event == "collector.failed":
            self.collector_done += 1
            print(f"  {details.get('collector')}: failed")
            return
        if event == "graph.request.retry":
            print(
                "  wait: "
                f"{details.get('reason') or 'retry'} "
                f"{details.get('backoff_seconds', details.get('retry_after_sec', 0))}s"
            )
            return
        if event == "run.diagnostics.generated":
            print(f"Diagnostics: {details.get('count', 0)}")
            return
        if event == "run.completed":
            print("Run complete")


def _run_azure_login(tenant_id: str, browser_command: str) -> int:
    env = os.environ.copy()
    env["BROWSER"] = browser_command
    return subprocess.run(
        ["az", "login", "--tenant", tenant_id, "--allow-no-subscriptions"],
        env=env,
        check=False,
    ).returncode


def _offer_m365_setup(tenant_id: str) -> int:
    print("Exchange needs m365 app setup")
    if not _confirm("Run one-time m365 setup now?", default=False):
        return 0
    setup_rc = subprocess.run(["m365", "setup", "--scripting"], check=False).returncode
    if setup_rc != 0:
        return setup_rc
    app_id = _prompt("m365 app id", default=os.environ.get("M365_CLI_APP_ID") or "")
    if app_id:
        auth_env = auditex_auth.default_local_auth_env_path()
        auth_env.parent.mkdir(parents=True, exist_ok=True)
        existing = auth_env.read_text(encoding="utf-8") if auth_env.exists() else ""
        lines = [line for line in existing.splitlines() if not line.startswith("M365_CLI_APP_ID=")]
        lines.append(f"M365_CLI_APP_ID={app_id}")
        auth_env.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
        os.environ["M365_CLI_APP_ID"] = app_id
    return 0


def _tenant_matches(observed: str | None, expected: str) -> bool:
    if not observed or expected == "organizations":
        return True
    left = observed.strip().lower()
    right = expected.strip().lower()
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")


def _ensure_exchange_module(*, non_interactive: bool) -> int:
    exchange = auditex_auth.get_auth_status().get("exchange") or {}
    if exchange.get("status") == "supported":
        return 0
    print("Exchange PowerShell module missing")
    if not non_interactive and not _confirm("Install ExchangeOnlineManagement now?", default=True):
        return 2
    return auditex_auth.ensure_exchange_online_module()


def _ensure_m365_login(tenant_id: str, browser_command: str) -> int:
    status = auditex_auth.get_auth_status().get("m365") or {}
    if (
        status.get("status") == "supported"
        and status.get("active_connection")
        and status.get("authenticated")
        and _tenant_matches(str(status.get("tenant_id") or ""), tenant_id)
    ):
        return 0
    app_id = os.environ.get("M365_CLI_APP_ID") or os.environ.get("M365_CLI_CLIENT_ID")
    if not app_id:
        setup_rc = _offer_m365_setup(tenant_id)
        if setup_rc != 0:
            return setup_rc
        app_id = os.environ.get("M365_CLI_APP_ID") or os.environ.get("M365_CLI_CLIENT_ID")
    command = [
        "m365",
        "login",
        "--authType",
        "browser",
        "--tenant",
        tenant_id,
    ]
    if app_id:
        command.extend(["--appId", app_id])
    env = os.environ.copy()
    env["BROWSER"] = browser_command
    rc = subprocess.run(command, env=env, check=False).returncode
    if rc != 0:
        return rc
    refreshed = auditex_auth.get_auth_status().get("m365") or {}
    if (
        refreshed.get("status") != "supported"
        or not refreshed.get("active_connection")
        or not refreshed.get("authenticated")
        or not _tenant_matches(str(refreshed.get("tenant_id") or ""), tenant_id)
    ):
        return 5
    return 0


def build_guided_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditex guided-run", description="Interactive guided tenant audit.")
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--tenant-name", default=None)
    parser.add_argument("--auditor-profile", default="global-reader", choices=profile_choices())
    parser.add_argument("--out", default="outputs/guided")
    parser.add_argument("--run-name", default=None)
    parser.add_argument("--top", type=int, default=500)
    parser.add_argument("--page-size", type=int, default=50)
    parser.add_argument("--browser-command", default=None)
    parser.add_argument("--collectors", default=None)
    parser.add_argument("--include-exchange", action="store_true")
    parser.add_argument("--throttle-mode", choices=("fast", "safe", "ultra-safe"), default="safe")
    parser.add_argument("--include-blocked", action="store_true")
    parser.add_argument("--with-mcp", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--local-mode", action="store_true")
    parser.add_argument("--skip-login-check", action="store_true")
    parser.add_argument("--skip-tool-check", action="store_true")
    parser.add_argument("--report-format", choices=("json", "md", "csv", "html"), default=None)
    parser.add_argument("--probe-first", dest="probe_first", action="store_true", default=True)
    parser.add_argument("--no-probe-first", dest="probe_first", action="store_false")
    return parser


def run_guided(args: argparse.Namespace) -> int:
    doctor = build_doctor_report()
    print("Auditex guided run")
    print(f"Machine: {doctor['system']['os']} {doctor['system']['machine']}")

    tenant_id = args.tenant_id
    tenant_name = args.tenant_name
    browser_command = args.browser_command or _default_browser_command()
    include_exchange = args.include_exchange

    if not args.non_interactive:
        tenant_id = tenant_id or _prompt("Tenant id or domain", default="organizations")
        tenant_name = tenant_name or _prompt("Tenant label", default=(tenant_id or "tenant").split(".")[0].upper())
        if not args.include_exchange:
            include_exchange = _confirm("Include Exchange checks?", default=False)
    else:
        tenant_id = tenant_id or "organizations"
        tenant_name = tenant_name or (tenant_id.split(".")[0].upper() if tenant_id != "organizations" else "TENANT")

    needs_setup = not args.skip_tool_check and not doctor.get("readiness", {}).get("core_ready")
    if include_exchange and not doctor.get("readiness", {}).get("exchange_ready"):
        needs_setup = not args.skip_tool_check
    if needs_setup:
        print("Local tools missing")
        if args.non_interactive or _confirm("Run setup now?", default=True):
            setup_kwargs: dict[str, bool] = {"with_mcp": args.with_mcp}
            if include_exchange:
                setup_kwargs["with_exchange"] = True
                setup_kwargs["with_pwsh"] = True
            setup_rc = run_setup(**setup_kwargs)
            if setup_rc != 0:
                return setup_rc
            doctor = build_doctor_report()
        else:
            return 2

    azure_state = (doctor.get("auth") or {}).get("azure_cli") or {}
    if not args.local_mode and not args.skip_login_check and azure_state.get("status") != "supported":
        print("Azure login needed")
        login_rc = _run_azure_login(tenant_id, browser_command)
        if login_rc != 0:
            return login_rc

    if include_exchange and not args.local_mode and not args.skip_login_check:
        module_rc = _ensure_exchange_module(non_interactive=args.non_interactive)
        if module_rc != 0:
            return module_rc
        m365_rc = _ensure_m365_login(tenant_id, browser_command)
        if m365_rc != 0:
            print("Exchange login failed")
            return m365_rc

    argv = [
        "--tenant-name",
        tenant_name,
        "--tenant-id",
        tenant_id,
        "--use-azure-cli-token",
        "--auditor-profile",
        args.auditor_profile,
        "--out",
        args.out,
        "--top",
        str(args.top),
        "--page-size",
        str(args.page_size),
        "--throttle-mode",
        args.throttle_mode,
    ]
    if args.run_name:
        argv.extend(["--run-name", args.run_name])
    if args.collectors:
        argv.extend(["--collectors", args.collectors])
    if include_exchange:
        argv.append("--include-exchange")
    if args.probe_first:
        argv.append("--probe-first")
    else:
        argv.append("--no-probe-first")
    if args.include_blocked:
        argv.append("--include-blocked")

    renderer = ProgressRenderer()
    started = time.time()
    rc = tenant_cli.main(argv, event_listener=renderer)
    duration = round(time.time() - started, 2)
    print(f"Done in {duration}s")
    if args.report_format:
        from .reporting import render_report

        latest = sorted(Path(args.out).expanduser().resolve().glob(f"{tenant_name}-*"))
        if latest:
            render_report(run_dir=str(latest[-1]), format_name=args.report_format)
    return rc
