from __future__ import annotations

import argparse
import subprocess
import json
import importlib
import logging
import os
from collections import defaultdict
from typing import Any, Callable, Optional
import sys
import time
from pathlib import Path

from .collectors import REGISTRY
from .collectors.base import CollectorResult
from .config import AuthConfig, CollectorConfig, RunConfig
from .findings import build_findings, build_report_pack
from .graph import GraphClient
from .normalize import build_ai_safe_summary, build_normalized_snapshot
from .output import AuditWriter
from .presets import load_collector_presets, resolve_collector_selection
from .profiles import get_profile, profile_choices
from .utils import load_env_file, parse_csv_list
from auditex.evidence_db import build_run_evidence_index

LOG = logging.getLogger("azure_tenant_audit")

SENSITIVE_CLI_ARGS = {"--client-secret", "--access-token"}
PLANE_CHOICES = ("inventory", "full", "export")


def _scrub_command_line(command_line: list[str]) -> list[str]:
    """Remove token values from command history before writing into logs/manifest."""
    scrubbed: list[str] = []
    skip_next = False
    for item in command_line:
        if skip_next:
            scrubbed.append("***redacted***")
            skip_next = False
            continue
        if item in SENSITIVE_CLI_ARGS:
            scrubbed.append(item)
            skip_next = True
            continue
        if item.startswith("--client-secret="):
            scrubbed.append("--client-secret=***redacted***")
            continue
        if item.startswith("--access-token="):
            scrubbed.append("--access-token=***redacted***")
            continue
        scrubbed.append(item)
    if skip_next:
        scrubbed.append("***redacted***")
    return scrubbed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Microsoft tenant audit collection.")
    parser.add_argument("--tenant-name", default="tenant", help="Label for the output folder.")
    parser.add_argument("--tenant-id", default=None, help="Entra tenant ID.")
    parser.add_argument("--client-id", default=None, help="App registration ID.")
    parser.add_argument("--client-secret", default=None, help="App secret.")
    parser.add_argument("--access-token", default=None, help="Optional preissued Graph access token.")
    parser.add_argument("--auth-context", default=None, help="Optional saved Auditex auth context name.")
    parser.add_argument(
        "--use-azure-cli-token",
        action="store_true",
        help="Use an existing Azure CLI Graph token if available (no app credentials required).",
    )
    parser.add_argument("--authority", default="https://login.microsoftonline.com/", help="Identity authority URL.")
    parser.add_argument("--graph-scope", default="https://graph.microsoft.com/.default", help="Graph scope.")
    parser.add_argument("--interactive", action="store_true", help="Use delegated browser login.")
    parser.add_argument("--scopes", default=None, help="Comma-separated delegated Graph scopes for interactive login.")
    parser.add_argument("--browser-command", default="firefox", help="Browser command used by interactive auth.")
    parser.add_argument("--out", default="audit-output", help="Base output directory.")
    parser.add_argument("--config", default="configs/collector-definitions.json", help="Collector configuration file.")
    parser.add_argument(
        "--collector-preset",
        default=None,
        help="Optional named collector preset from configs/collector-presets.json.",
    )
    parser.add_argument(
        "--waiver-file",
        default=None,
        help="Optional JSON waiver file for accepted findings.",
    )
    parser.add_argument("--collectors", default=None, help="Comma-separated collectors to run.")
    parser.add_argument("--exclude", default=None, help="Comma-separated collectors to skip.")
    parser.add_argument("--include-exchange", action="store_true", help="Enable optional exchange collectors.")
    parser.add_argument("--top", type=int, default=500, help="Per-endpoint result limit.")
    parser.add_argument("--page-size", type=int, default=100, help="Per-request page size for paged Graph endpoints.")
    parser.add_argument(
        "--throttle-mode",
        choices=("fast", "safe", "ultra-safe"),
        default="safe",
        help="Graph pacing mode used to reduce bursts and retry more carefully.",
    )
    parser.add_argument("--probe-first", dest="probe_first", action="store_true", default=False, help="Run a low-volume preflight before full collection.")
    parser.add_argument("--no-probe-first", dest="probe_first", action="store_false", help="Skip the low-volume preflight step.")
    parser.add_argument("--include-blocked", action="store_true", help="Run collectors even if preflight marks them as known blocked.")
    parser.add_argument("--run-name", default=None, help="Optional run subfolder identifier.")
    parser.add_argument(
        "--resume-from",
        default=None,
        help="Resume into an existing run directory and skip already completed collectors.",
    )
    parser.add_argument(
        "--plane",
        default="inventory",
        choices=PLANE_CHOICES,
        help="Run plane: inventory (default), full, or export. Full and export both run export collectors.",
    )
    parser.add_argument("--since", default=None, help="Optional ISO8601 lower bound for time-windowed collectors.")
    parser.add_argument("--until", default=None, help="Optional ISO8601 upper bound for time-windowed collectors.")
    parser.add_argument(
        "--auditor-profile",
        default="auto",
        choices=profile_choices(),
        help="Named audit profile for expected permission shape and escalation guidance.",
    )
    parser.add_argument("--offline", action="store_true", help="Use offline sample bundle.")
    parser.add_argument("--sample", default="examples/sample_audit_bundle/sample_result.json", help="Sample bundle path when offline.")
    parser.add_argument(
        "--permission-hints",
        default="configs/collector-permissions.json",
        help="Optional collector-permission matrix file for diagnostics.",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logs.")
    parser.add_argument("--env", default=None, help="Optional .env-like file to load.")
    return parser


def _acquire_azure_cli_access_token(
    tenant_id: str | None, log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None
) -> str:
    """Load a Microsoft Graph token from Azure CLI for environments without app registration."""

    command = [
        "az",
        "account",
        "get-access-token",
        "--resource",
        "https://graph.microsoft.com",
        "--output",
        "json",
    ]
    if tenant_id:
        command.extend(["--tenant", tenant_id])

    start = time.time()
    if log_event:
        log_event(
            "auth.cli.token.requested",
            "Requesting Microsoft Graph token from Azure CLI",
            {"tenant_id": tenant_id or "organizations", "resource": "https://graph.microsoft.com"},
        )
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=120,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Azure CLI is not available. Install azure-cli and sign in with 'az login'.") from exc

    duration_ms = round((time.time() - start) * 1000, 2)

    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "").strip() or "Azure CLI token command failed."
        if "Please run 'az login'" in message or "Please run: az login" in message:
            if log_event:
                log_event(
                    "auth.cli.token.failed",
                    "Azure CLI token acquisition failed because login is required.",
                    {"tenant_id": tenant_id or "organizations", "duration_ms": duration_ms},
                )
            raise RuntimeError("Azure CLI is not signed in. Run 'az login' in a browser first, then retry.") from None
        if log_event:
            log_event(
                "auth.cli.token.failed",
                "Azure CLI token acquisition failed.",
                {
                    "tenant_id": tenant_id or "organizations",
                    "duration_ms": duration_ms,
                    "error": message,
                },
            )
        raise RuntimeError(f"Azure CLI token fetch failed: {message}")

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        if log_event:
            log_event(
                "auth.cli.token.failed",
                "Azure CLI token response was not valid JSON.",
                {
                    "tenant_id": tenant_id or "organizations",
                    "duration_ms": duration_ms,
                },
            )
        raise RuntimeError("Azure CLI returned non-JSON token response.") from exc

    token = payload.get("accessToken") or payload.get("access_token")
    if not token:
        if log_event:
            log_event(
                "auth.cli.token.failed",
                "Azure CLI token response missing access token field.",
                {"tenant_id": tenant_id or "organizations", "duration_ms": duration_ms},
            )
        raise RuntimeError("Azure CLI token response was missing accessToken.")

    if log_event:
        log_event(
            "auth.cli.token.acquired",
            "Azure CLI token acquired.",
            {
                "tenant_id": tenant_id or "organizations",
                "duration_ms": duration_ms,
            },
        )
    return token


def _capture_signed_in_context(
    client: GraphClient, log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None
) -> dict[str, Any]:
    """Best-effort capture of the current delegated identity and directory roles."""

    try:
        me = client.get_json("/me")
        roles = client.get_all(
            "/me/memberOf/microsoft.graph.directoryRole",
            params={"$select": "id,displayName,roleTemplateId"},
        )
    except Exception as exc:  # noqa: BLE001
        if log_event:
            log_event(
                "auth.session.unavailable",
                "Unable to capture signed-in identity and directory roles.",
                {"error": str(exc)},
            )
        return {}

    role_names = sorted(
        {
            role.get("displayName")
            for role in roles
            if isinstance(role, dict) and role.get("displayName")
        }
    )
    context = {
        "display_name": me.get("displayName"),
        "user_principal_name": me.get("userPrincipalName"),
        "object_id": me.get("id"),
        "roles": role_names,
    }
    if log_event:
        log_event(
            "auth.session.context",
            "Captured signed-in identity and directory roles.",
            context,
        )
    return context


def _inspect_access_token(token: str) -> dict[str, Any]:
    return importlib.import_module("auditex.auth").inspect_token_claims(token)


def _build_auth_context_payload(
    *,
    auth_mode: str,
    tenant_id: str,
    token_claims: dict[str, Any] | None = None,
    session_context: dict[str, Any] | None = None,
    saved_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "auth_mode": auth_mode,
        "tenant_id": tenant_id,
        "token_claims": token_claims or {},
        "session_context": session_context or {},
    }
    if saved_context:
        payload["saved_auth_context"] = {
            "name": saved_context.get("name"),
            "auth_type": saved_context.get("auth_type"),
            "tenant_id": saved_context.get("tenant_id"),
        }
        delegated_roles = saved_context.get("delegated_roles") or []
    else:
        delegated_roles = []
    session_roles = (session_context or {}).get("roles") or []
    payload["delegated_roles"] = list(dict.fromkeys([*delegated_roles, *session_roles]))
    return payload


def _build_capability_matrix_rows(
    *,
    auth_context: dict[str, Any],
    selected_collectors: list[str],
    auditor_profile: str,
    collector_config: CollectorConfig,
    permission_hints: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    token_claims = auth_context.get("token_claims") or {}
    available = {
        *[str(item) for item in token_claims.get("delegated_scopes") or [] if item],
        *[str(item) for item in token_claims.get("app_roles") or [] if item],
    }
    delegated_roles = {str(item) for item in auth_context.get("delegated_roles") or [] if item}
    has_global_reader = any(role.lower() == "global reader" for role in delegated_roles)
    profile = get_profile(auditor_profile)
    rows: list[dict[str, Any]] = []
    for collector_name in selected_collectors:
        definition = collector_config.collectors.get(collector_name)
        hints = permission_hints.get(collector_name, {})
        required = list(definition.required_permissions) if definition else list(hints.get("graph_scopes") or [])
        missing = [perm for perm in required if perm not in available]
        status = "supported"
        reason = "required_permissions_present"
        if missing:
            status = "blocked_by_scope"
            reason = "missing_required_permissions"
        if collector_name in {"purview", "ediscovery"} and has_global_reader:
            status = "blocked_by_role"
            reason = "global_reader_limit"
        elif collector_name == "reports_usage" and has_global_reader and "Reports.Read.All" not in available:
            status = "partial"
            reason = "global_reader_tenant_level_reports_only"
        rows.append(
            {
                "collector": collector_name,
                "status": status,
                "reason": reason,
                "required_permissions": required,
                "missing_permissions": missing,
                "observed_permissions": sorted(available),
                "delegated_roles": sorted(delegated_roles),
                "minimum_role_hints": list(hints.get("minimum_role_hints") or profile.delegated_role_hints),
                "notes": hints.get("notes") or profile.notes,
            }
        )
    return rows


def _build_coverage_ledger(
    *,
    capability_rows: list[dict[str, Any]],
    result_rows: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results_by_collector = {str(row.get("name")): row for row in result_rows}
    diagnostics_by_collector: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in diagnostics:
        collector = str(item.get("collector") or "")
        if collector:
            diagnostics_by_collector[collector].append(item)
    ledger: list[dict[str, Any]] = []
    for capability in capability_rows:
        collector = str(capability.get("collector") or "")
        result = results_by_collector.get(collector, {})
        ledger.append(
            {
                "collector": collector,
                "expected_status": capability.get("status"),
                "expected_reason": capability.get("reason"),
                "actual_status": result.get("status"),
                "item_count": result.get("item_count", 0),
                "message": result.get("message"),
                "diagnostic_count": len(diagnostics_by_collector.get(collector, [])),
                "diagnostics": diagnostics_by_collector.get(collector, []),
            }
        )
    return ledger


def run_offline(
    sample_path: Path,
    out: Path,
    tenant_name: str,
    run_name: str | None,
    *,
    auditor_profile: str = "auto",
    plane: str = "inventory",
    since: str | None = None,
    until: str | None = None,
) -> int:
    if not sample_path.exists():
        LOG.error("Sample file not found: %s", sample_path)
        return 2
    try:
        sample = json.loads(sample_path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        LOG.error("Unable to load sample bundle: %s", exc)
        return 2

    writer = AuditWriter(out, tenant_name=tenant_name, run_name=run_name)
    writer.log_event(
        "run.started",
        "Offline run started",
        {
            "mode": "offline",
            "sample": str(sample_path),
            "auditor_profile": auditor_profile,
            "plane": plane,
            "since": since,
            "until": until,
        },
    )

    (writer.raw_dir / "sample_input.json").write_text(
        json.dumps(sample, indent=2),
        encoding="utf-8",
    )
    for key, value in sample.items():
        row = {
            "name": key,
            "status": "ok",
            "item_count": len(value.get("value", [])) if isinstance(value, dict) else 0,
            "message": "offline simulation",
        }
        writer.write_summary(row)
        writer.log_event("collector.synthetic", "Offline collector simulated", {"name": key, "item_count": row["item_count"]})
    writer.write_bundle(
        {
            "executed_by": "azure_tenant_audit",
            "collectors": list(sample.keys()),
            "overall_status": "ok",
            "duration_seconds": 0,
            "mode": "offline",
            "auditor_profile": auditor_profile,
            "plane": plane,
            "since": since,
            "until": until,
            "command_line": [],
        }
    )
    LOG.info("Offline sample written to %s", writer.run_dir)
    return 0


def _load_permission_hints(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        LOG.warning("Permission hints file not found: %s", path)
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        LOG.warning("Failed to load permission hints file %s: %s", path, exc)
        return {}
    raw = payload.get("collector_permissions") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(name): dict(value) if isinstance(value, dict) else {} for name, value in raw.items()}


def _build_diagnostics(
    result_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    permission_hints: dict[str, dict[str, Any]],
    auditor_profile: str,
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    by_collector = defaultdict(list)
    profile = get_profile(auditor_profile)
    for row in coverage_rows:
        collector_name = row.get("collector")
        if isinstance(collector_name, str):
            by_collector[collector_name].append(row)

    for row in result_rows:
        collector_name = row["name"]
        if row["status"] in {"ok", "skipped"}:
            continue
        hints = permission_hints.get(collector_name, {})
        recommended_scopes = hints.get("graph_scopes", [])
        minimum_roles = hints.get("minimum_role_hints", [])
        command_tools = hints.get("command_tools", [])
        optional_commands = hints.get("optional_commands", [])
        notes = hints.get("notes")
        notes_detail = notes if isinstance(notes, str) else None
        issue_rows = by_collector.get(collector_name, [])
        if not issue_rows:
            failures.append(
                {
                    "collector": collector_name,
                    "status": row["status"],
                    "error": row.get("error"),
                    "error_class": "unknown",
                    "evidence": {
                        "message": row.get("message"),
                    },
                    "recommendations": {
                        "required_graph_scopes": sorted(set(recommended_scopes)),
                        "recommended_roles": sorted(set(minimum_roles)),
                        "command_tools": sorted(set(command_tools)),
                        "optional_commands": sorted(set(optional_commands)),
                        "notes": notes_detail,
                        "auditor_profile": auditor_profile,
                        "profile_role_hints": list(profile.delegated_role_hints),
                        "optional_app_escalation_permissions": list(profile.app_escalation_permissions),
                    },
                }
            )
            continue

        for item in issue_rows:
            status = item.get("status")
            if status == "ok":
                continue
            failure: dict[str, Any] = {
                "collector": collector_name,
                "item": item.get("name"),
                "status": status,
                "endpoint": item.get("endpoint"),
                "error_class": item.get("error_class"),
                "error": item.get("error"),
                "top": item.get("top"),
                "command_type": item.get("type"),
            }
            if item.get("type") == "command":
                failure["commands_required"] = optional_commands or [str(item.get("command"))] if item.get("command") else []
                failure["recommendations"] = {
                    "required_tools": sorted(set(command_tools)),
                    "notes": notes_detail,
                    "auditor_profile": auditor_profile,
                    "profile_role_hints": list(profile.delegated_role_hints),
                }
            elif item.get("type") == "graph":
                failure["recommendations"] = {
                    "required_graph_scopes": sorted(set(recommended_scopes)),
                    "recommended_roles": sorted(set(minimum_roles)),
                    "notes": notes_detail,
                    "auditor_profile": auditor_profile,
                    "profile_role_hints": list(profile.delegated_role_hints),
                    "optional_app_escalation_permissions": list(profile.app_escalation_permissions),
                }
            else:
                failure["recommendations"] = {
                    "notes": notes_detail,
                    "auditor_profile": auditor_profile,
                }
            failures.append(failure)

    return failures


def _collector_pause_seconds(throttle_mode: str) -> float:
    if throttle_mode == "ultra-safe":
        return 1.5
    if throttle_mode == "safe":
        return 0.5
    return 0.0


def _run_preflight_probe(
    *,
    selected_collectors: list[str],
    completed_collectors: set[str],
    client: GraphClient,
    run_cfg: RunConfig,
    writer: AuditWriter,
    include_blocked: bool,
) -> tuple[list[str], list[dict[str, Any]], str]:
    rows: list[dict[str, Any]] = []
    runnable: list[str] = []
    preflight_top = max(1, min(5, run_cfg.top_items))
    preflight_page_size = max(1, min(5, run_cfg.page_size))
    writer.log_event(
        "preflight.started",
        "Collector preflight started",
        {
            "collector_count": len(selected_collectors),
            "top": preflight_top,
            "page_size": preflight_page_size,
            "include_blocked": include_blocked,
        },
    )
    for name in selected_collectors:
        if name in completed_collectors:
            runnable.append(name)
            rows.append(
                {
                    "collector": name,
                    "decision": "run",
                    "reason": "already_completed",
                    "status": "ok",
                    "item_count": 0,
                }
            )
            continue
        collector = REGISTRY.get(name)
        if collector is None:
            rows.append(
                {
                    "collector": name,
                    "decision": "skip",
                    "reason": "unknown_collector",
                    "status": "failed",
                    "item_count": 0,
                    "error": "unknown collector",
                }
            )
            continue

        writer.log_event("preflight.collector.started", "Preflight collector started", {"collector": name})
        try:
            result = collector.run(
                {
                    "client": client,
                    "top": preflight_top,
                    "page_size": preflight_page_size,
                    "plane": "inventory",
                    "since": run_cfg.since,
                    "until": run_cfg.until,
                    "collector_checkpoint_state": {},
                    "operation_checkpoint_state": {},
                    "chunk_writer": None,
                    "audit_logger": writer.log_event,
                }
            )
            coverage = result.coverage or []
            has_ok = any(item.get("status") == "ok" for item in coverage)
            decision = "run" if include_blocked or result.item_count > 0 or has_ok else "skip"
            reason = "supported" if decision == "run" else "known_blocked"
            rows.append(
                {
                    "collector": name,
                    "decision": decision,
                    "reason": reason,
                    "status": result.status,
                    "item_count": result.item_count,
                    "coverage_rows": len(coverage),
                    "message": result.message,
                }
            )
            if decision == "run":
                runnable.append(name)
            writer.log_event(
                "preflight.collector.finished",
                "Preflight collector finished",
                {
                    "collector": name,
                    "decision": decision,
                    "status": result.status,
                    "item_count": result.item_count,
                },
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(
                {
                    "collector": name,
                    "decision": "skip" if not include_blocked else "run",
                    "reason": "preflight_exception",
                    "status": "failed",
                    "item_count": 0,
                    "error": str(exc),
                }
            )
            if include_blocked:
                runnable.append(name)
            writer.log_event(
                "preflight.collector.finished",
                "Preflight collector failed",
                {
                    "collector": name,
                    "decision": "run" if include_blocked else "skip",
                    "status": "failed",
                    "error": str(exc),
                },
            )

    artifact = writer.write_json_artifact(
        "preflight-plan.json",
        {
            "collectors": rows,
            "runnable_collectors": runnable,
            "skipped_collectors": [row["collector"] for row in rows if row.get("decision") == "skip"],
        },
    )
    writer.log_event(
        "preflight.completed",
        "Collector preflight completed",
        {
            "run_count": len(runnable),
            "skip_count": len([row for row in rows if row.get("decision") == "skip"]),
        },
    )
    return runnable, rows, str(artifact.relative_to(writer.run_dir))


def run_live(args: argparse.Namespace, event_listener: Callable[[dict[str, Any]], None] | None = None) -> int:
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    saved_auth_context: dict[str, Any] | None = None
    if args.auth_context:
        saved_auth_context = importlib.import_module("auditex.auth").resolve_auth_context(args.auth_context)
        args.access_token = args.access_token or saved_auth_context.get("token")
        args.tenant_id = args.tenant_id or saved_auth_context.get("tenant_id")

    config = CollectorConfig.from_path(Path(args.config))
    permission_hints = _load_permission_hints(Path(args.permission_hints))
    profile = get_profile(args.auditor_profile)
    selected_collector_names = parse_csv_list(args.collectors)
    exclude_collector_names = parse_csv_list(args.exclude)
    if args.include_exchange:
        merged_collectors = list(selected_collector_names or profile.default_collectors)
        if "exchange" not in merged_collectors:
            merged_collectors.append("exchange")
        selected_collector_names = merged_collectors

    run_cfg = RunConfig(
        tenant_name=args.tenant_name,
        output_dir=out,
        collectors=selected_collector_names,
        excluded_collectors=exclude_collector_names,
        include_exchange=args.include_exchange,
        offline=args.offline,
        sample_path=Path(args.sample),
        run_name=args.run_name,
        top_items=args.top,
        page_size=args.page_size,
        auditor_profile=args.auditor_profile,
        default_collectors=profile.default_collectors,
        plane=args.plane,
        since=args.since,
        until=args.until,
    )

    available = [name for name in config.default_order if name in config.collectors]
    try:
        selected = resolve_collector_selection(
            available=available,
            profile_default_collectors=profile.default_collectors,
            preset_name=args.collector_preset,
            presets=load_collector_presets(),
            explicit_collectors=selected_collector_names,
            excluded_collectors=exclude_collector_names,
        )
    except ValueError as exc:
        LOG.error("%s", exc)
        return 2
    if run_cfg.plane not in profile.supported_planes:
        LOG.error("Audit profile '%s' does not support plane '%s'.", run_cfg.auditor_profile, run_cfg.plane)
        return 2
    execution_plane = "export" if run_cfg.plane in {"full", "export"} else "inventory"

    auth_scopes = parse_csv_list(args.scopes)
    if args.interactive and not auth_scopes:
        auth_scopes = sorted({perm for name in selected for perm in config.collectors[name].required_permissions})
    if args.interactive and not auth_scopes:
        auth_scopes = ["User.Read"]

    resume_from = Path(args.resume_from).expanduser().resolve() if args.resume_from else None
    writer = AuditWriter(
        run_cfg.output_dir,
        run_cfg.tenant_name,
        run_name=run_cfg.run_name,
        run_dir=resume_from,
        event_listener=event_listener,
    )
    completed_state = writer.load_checkpoint_state() if resume_from else {}
    completed_collectors = {
        name
        for name, state in completed_state.get("collectors", {}).items()
        if state.get("status") in {"ok", "partial", "skipped"}
    }
    collector_checkpoint_state = writer.load_collector_checkpoint_state() if resume_from else {}
    operation_checkpoint_state = writer.load_operation_checkpoint_state() if resume_from else {}
    if resume_from:
        writer.log_event(
            "run.resume",
            "Resuming from existing run state",
            {
                "resume_from": str(resume_from),
                "checkpoint_entries": len(completed_state.get("collectors", {})),
                "completed_collectors": sorted(completed_collectors),
            },
        )

    if args.use_azure_cli_token:
        if not args.access_token:
            try:
                args.access_token = _acquire_azure_cli_access_token(args.tenant_id, log_event=writer.log_event)
                writer.log_event(
                    "auth.cli.token.selected",
                    "Using Azure CLI cached token for Graph authentication.",
                    {"tenant_id": args.tenant_id or "organizations"},
                )
                LOG.info("Using Azure CLI cached Graph token.")
            except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
                writer.log_event(
                    "auth.cli.token.rejected",
                    "Azure CLI token could not be used.",
                    {"tenant_id": args.tenant_id or "organizations", "error": str(exc)},
                )
                LOG.error("Unable to use Azure CLI token: %s", exc)
                return 2

    has_token_source = bool(args.access_token or args.use_azure_cli_token)
    if args.interactive and not args.client_id and not has_token_source:
        LOG.warning(
            "Interactive mode requested without --client-id. Falling back to Azure CLI token mode. "
            "Run `az login` first; this avoids creating an app registration."
        )
        args.interactive = False
        args.use_azure_cli_token = True
        has_token_source = True
    if not args.interactive and not has_token_source:
        if not args.client_id:
            LOG.error("client-id is required for app authentication.")
            return 2
        if not args.client_secret:
            LOG.error("client-id and client-secret are required for app auth. Use --interactive or --use-azure-cli-token.")
            return 2
        if not args.tenant_id:
            LOG.error("tenant-id is required for app authentication.")
            return 2
    if args.interactive and not args.tenant_id:
        args.tenant_id = "organizations"

    tenant_id = args.tenant_id or "organizations"

    auth_mode = "interactive" if args.interactive else "azure_cli" if args.use_azure_cli_token else "access_token" if args.access_token else "app"

    auth = AuthConfig(
        tenant_id=tenant_id,
        client_id=args.client_id,
        auth_mode=auth_mode,
        client_secret=args.client_secret,
        access_token=args.access_token,
        authority=args.authority,
        graph_scope=args.graph_scope,
        interactive_scopes=auth_scopes,
        throttle_mode=args.throttle_mode,
    )
    client = GraphClient(auth, audit_event=writer.log_event)
    session_context: dict[str, Any] = {}
    if auth_mode in {"azure_cli", "interactive"}:
        session_context = _capture_signed_in_context(client, log_event=writer.log_event)
    token_claims: dict[str, Any] = {}
    if args.access_token:
        try:
            token_claims = _inspect_access_token(args.access_token)
        except Exception as exc:  # noqa: BLE001
            writer.log_event(
                "auth.token.inspect_failed",
                "Access token could not be decoded locally.",
                {"error": str(exc)},
            )
            token_claims = {}
    auth_context_payload = _build_auth_context_payload(
        auth_mode=auth_mode,
        tenant_id=tenant_id,
        token_claims=token_claims,
        session_context=session_context,
        saved_context=saved_auth_context,
    )
    capability_rows = _build_capability_matrix_rows(
        auth_context=auth_context_payload,
        selected_collectors=selected,
        auditor_profile=run_cfg.auditor_profile,
        collector_config=config,
        permission_hints=permission_hints,
    )
    selected_before_preflight = list(selected)
    preflight_rows: list[dict[str, Any]] = []
    preflight_path: str | None = None
    if args.probe_first:
        selected, preflight_rows, preflight_path = _run_preflight_probe(
            selected_collectors=selected_before_preflight,
            completed_collectors=completed_collectors,
            client=client,
            run_cfg=run_cfg,
            writer=writer,
            include_blocked=args.include_blocked,
        )
        if not selected:
            writer.log_event(
                "run.aborted",
                "No runnable collectors remained after preflight.",
                {"preflight_path": preflight_path},
            )
            writer.write_bundle(
                {
                    "executed_by": "azure_tenant_audit",
                    "collectors": [],
                    "overall_status": "partial",
                    "duration_seconds": 0,
                    "mode": auth_mode,
                    "auditor_profile": run_cfg.auditor_profile,
                    "plane": run_cfg.plane,
                    "since": run_cfg.since,
                    "until": run_cfg.until,
                    "session_context": session_context,
                    "command_line": _scrub_command_line(list(getattr(args, "_command_line", sys.argv))),
                    "coverage_count": 0,
                    "throttle_mode": args.throttle_mode,
                    "preflight_path": preflight_path,
                }
            )
            return 1
    command_line = _scrub_command_line(list(getattr(args, "_command_line", sys.argv)))
    writer.log_event(
        "run.started",
        "Live run started",
        {
            "tenant_id": args.tenant_id,
            "collectors": selected,
            "top": run_cfg.top_items,
            "page_size": run_cfg.page_size,
            "include_exchange": args.include_exchange,
            "mode": auth_mode,
            "auditor_profile": run_cfg.auditor_profile,
            "plane": run_cfg.plane,
            "since": run_cfg.since,
            "until": run_cfg.until,
            "session_context": session_context,
            "auth_context": auth_context_payload,
            "command_line": command_line,
            "throttle_mode": args.throttle_mode,
            "preflight_path": preflight_path,
        },
    )
    start = time.time()
    result_rows: list[dict[str, object]] = []
    failures = 0
    summary_rows: list[dict[str, object]] = []
    coverage_rows: list[dict[str, Any]] = list(writer.coverage) if resume_from else []
    collector_payloads: dict[str, dict[str, Any]] = {}
    preflight_skipped = {
        row["collector"]: row
        for row in preflight_rows
        if row.get("decision") == "skip" and row.get("collector")
    }
    collector_pause_seconds = _collector_pause_seconds(args.throttle_mode)

    for name, skip in preflight_skipped.items():
        skip_row: dict[str, object] = {
            "name": name,
            "status": "skipped",
            "item_count": 0,
            "message": "Collector skipped after preflight marked it as known blocked.",
            "error": skip.get("error"),
            "coverage_rows": 0,
        }
        result_rows.append(skip_row)
        summary_rows.append(skip_row)
        writer.write_checkpoint(name, skip_row)
        writer.log_event(
            "collector.skipped",
            "Collector skipped after preflight",
            {
                "collector": name,
                "reason": skip.get("reason"),
            },
        )

    for name in selected:
        collector = REGISTRY.get(name)
        if collector is None:
            LOG.warning("Unknown collector requested: %s", name)
            continue

        if resume_from and name in completed_collectors:
            previous_state = collector_checkpoint_state.get(name, {})
            skipped_row: dict[str, object] = {
                "name": name,
                "status": "skipped",
                "item_count": previous_state.get("item_count", 0),
                "message": "Collector skipped due to checkpoint resume.",
                "error": None,
                "coverage_rows": 0,
            }
            result_rows.append(skipped_row)
            existing_payload = writer._safe_load_json(writer.raw_dir / f"{name}.json")
            if isinstance(existing_payload, dict):
                collector_payloads[name] = existing_payload
            writer.log_event(
                "collector.skipped",
                "Collector skipped",
                {
                    "collector": name,
                    "resume_from": str(resume_from),
                    "previous_status": previous_state.get("status"),
                    "item_count": previous_state.get("item_count", 0),
                },
            )
            continue

        try:
            writer.log_event("collector.started", "Collector started", {"collector": name})
            result: CollectorResult = collector.run(
                {
                    "client": client,
                    "top": run_cfg.top_items,
                    "page_size": run_cfg.page_size,
                    "plane": execution_plane,
                    "since": run_cfg.since,
                    "until": run_cfg.until,
                    "collector_checkpoint_state": collector_checkpoint_state.get(name, {}),
                    "operation_checkpoint_state": operation_checkpoint_state.get(name, {}),
                    "write_export_checkpoint": writer.write_export_checkpoint,
                    "write_export_records": lambda collector_name, operation_name, page_number, records, metadata=None: str(
                        writer.write_export_records(
                            collector_name,
                            operation_name,
                            page_number,
                            records,
                            metadata,
                        ).relative_to(writer.run_dir)
                    ),
                    "write_export_summary": lambda collector_name, operation_name, payload: str(
                        writer.write_export_summary(collector_name, operation_name, payload).relative_to(writer.run_dir)
                    ),
                    "chunk_writer": lambda collector_name, endpoint_name, page_number, records, metadata=None: str(
                        writer.write_chunk_records(collector_name, endpoint_name, page_number, records, metadata).relative_to(
                            writer.run_dir
                        )
                    ),
                    "audit_logger": writer.log_event,
                }
            )
            collector_coverage = result.coverage or []
            if collector_coverage:
                writer.write_index_records(collector_coverage)
                coverage_rows.extend(collector_coverage)
            writer.log_event(
                "collector.finished",
                "Collector finished",
                {
                    "collector": name,
                    "status": result.status,
                    "item_count": result.item_count,
                    "coverage_rows": len(collector_coverage),
                    "error": result.error,
                },
            )
            writer.write_raw(name, result.payload)
            status = result.status
            if result.status != "ok":
                failures += 1
            if result.error:
                LOG.warning("%s collector error: %s", name, result.error)
            collector_payloads[name] = result.payload
            result_rows.append(
                {
                    "name": result.name,
                    "status": status,
                    "item_count": result.item_count,
                    "message": result.message or ("ok" if status == "ok" else "partial"),
                    "error": result.error,
                    "coverage_rows": len(collector_coverage),
                }
            )
            summary_rows.append(result_rows[-1])
            writer.write_checkpoint(name, result_rows[-1])
        except Exception as exc:  # noqa: BLE001
            failures += 1
            LOG.exception("Collector failed: %s", name)
            writer.log_event(
                "collector.failed",
                "Collector crashed",
                {"collector": name, "error": str(exc)},
            )
            result_rows.append(
                {
                    "name": name,
                    "status": "failed",
                    "item_count": 0,
                    "message": "collector crashed",
                    "error": str(exc),
                    "coverage_rows": 0,
                }
            )
            summary_rows.append(result_rows[-1])
            writer.write_checkpoint(name, result_rows[-1])

        if collector_pause_seconds > 0:
            writer.log_event(
                "run.collector.pause",
                "Pausing before next collector",
                {"collector": name, "delay_seconds": collector_pause_seconds},
            )
            time.sleep(collector_pause_seconds)

    duration = round(time.time() - start, 2)
    for row in summary_rows:
        writer.write_summary(row)
    diagnostics = _build_diagnostics(
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        permission_hints=permission_hints,
        auditor_profile=run_cfg.auditor_profile,
    )
    if diagnostics:
        writer.write_diagnostics(diagnostics)
        writer.write_blockers(diagnostics)
        writer.log_event(
            "run.diagnostics.generated",
            "Failure diagnostics generated",
            {"count": len(diagnostics)},
        )
    coverage_ledger = _build_coverage_ledger(
        capability_rows=capability_rows,
        result_rows=result_rows,
        diagnostics=diagnostics,
    )
    normalized_snapshot = build_normalized_snapshot(
        tenant_name=run_cfg.tenant_name,
        run_id=writer.run_id,
        collector_payloads=collector_payloads,
        diagnostics=diagnostics,
        result_rows=result_rows,
        coverage_rows=coverage_rows,
    )
    findings = build_findings(
        diagnostics,
        normalized_snapshot=normalized_snapshot,
        waiver_file=args.waiver_file,
    )
    writer.write_normalized("auth_context", auth_context_payload)
    writer.write_normalized("capability_matrix", {"kind": "capability_matrix", "records": capability_rows})
    writer.write_normalized("coverage_ledger", {"kind": "coverage_ledger", "records": coverage_ledger})
    if findings:
        writer.write_findings(findings)
    for name, payload in normalized_snapshot.items():
        writer.write_normalized(name, payload)
    writer.write_ai_safe("run_summary", build_ai_safe_summary(normalized_snapshot, findings=findings))
    evidence_paths = ["run-manifest.json", "summary.json"]
    if coverage_rows:
        evidence_paths.append("coverage.json")
    if diagnostics:
        evidence_paths.append("blockers/blockers.json")
    if findings:
        evidence_paths.append("findings/findings.json")
    evidence_paths.extend(f"normalized/{name}.json" for name in normalized_snapshot)
    writer.write_report_pack(
        build_report_pack(
            tenant_name=run_cfg.tenant_name,
            overall_status="partial" if failures or preflight_skipped else "ok",
            findings=findings,
            evidence_paths=evidence_paths,
            blocker_count=len(diagnostics),
        )
    )
    writer.log_event(
        "run.complete",
        "Live run completed",
        {"failures": failures, "collectors": len(result_rows), "coverage_rows": len(coverage_rows)},
    )
    evidence_db_path = build_run_evidence_index(writer.run_dir)
    writer._record_artifact(evidence_db_path)
    writer.write_bundle(
        {
            "executed_by": "azure_tenant_audit",
            "collectors": selected,
            "overall_status": "partial" if failures or preflight_skipped else "ok",
            "duration_seconds": duration,
            "mode": auth_mode,
            "auditor_profile": run_cfg.auditor_profile,
            "plane": run_cfg.plane,
            "collector_preset": args.collector_preset,
            "waiver_path": args.waiver_file,
            "since": run_cfg.since,
            "until": run_cfg.until,
            "session_context": session_context,
            "auth_context_path": "normalized/auth_context.json",
            "capability_matrix_path": "normalized/capability_matrix.json",
            "coverage_ledger_path": "normalized/coverage_ledger.json",
            "command_line": command_line,
            "coverage_count": len(coverage_rows),
            "throttle_mode": args.throttle_mode,
            "preflight_path": preflight_path,
            "evidence_db_path": str(evidence_db_path.relative_to(writer.run_dir)),
        }
    )
    LOG.info("Completed in %.2fs. Output in %s", duration, writer.run_dir)
    return 1 if failures or preflight_skipped else 0


def main(argv: list[str] | None = None, event_listener: Callable[[dict[str, Any]], None] | None = None) -> int:
    parser = build_parser()
    parsed_argv = list(argv if argv is not None else sys.argv[1:])
    args = parser.parse_args(parsed_argv)
    args._command_line = ["azure-tenant-audit", *parsed_argv]
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")

    if args.env:
        load_env_file(Path(args.env))

    args.tenant_id = args.tenant_id or None
    args.client_id = args.client_id or None
    args.client_secret = args.client_secret or None
    args.access_token = args.access_token or None

    if args.tenant_id is None:
        args.tenant_id = __import__("os").environ.get("AZURE_TENANT_ID")
    if args.client_id is None:
        args.client_id = __import__("os").environ.get("AZURE_CLIENT_ID")
    if args.client_secret is None:
        args.client_secret = __import__("os").environ.get("AZURE_CLIENT_SECRET")
    if args.access_token is None:
        args.access_token = __import__("os").environ.get("AZURE_ACCESS_TOKEN")
    if args.authority is None:
        args.authority = __import__("os").environ.get("AZURE_AUTHORITY", args.authority)
    if args.graph_scope is None:
        args.graph_scope = __import__("os").environ.get("AZURE_GRAPH_SCOPE", args.graph_scope)
    if args.interactive and args.browser_command:
        os.environ["BROWSER"] = args.browser_command
    if args.scopes:
        args.scopes = args.scopes.strip()
    if args.offline:
        return run_offline(
            Path(args.sample),
            Path(args.out),
            args.tenant_name,
            args.run_name,
            auditor_profile=args.auditor_profile,
            plane=args.plane,
            since=args.since,
            until=args.until,
        )
    return run_live(args, event_listener=event_listener)


if __name__ == "__main__":
    raise SystemExit(main())
