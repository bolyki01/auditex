from __future__ import annotations

import json
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import requests

from .run_bundle import RunBundle


WEBHOOK_ENV = {
    "teams": "AUDITEX_TEAMS_WEBHOOK_URL",
    "slack": "AUDITEX_SLACK_WEBHOOK_URL",
}


def _build_payload(run_dir: str | Path) -> dict[str, Any]:
    bundle = RunBundle(run_dir)
    report_summary = bundle.report_summary()
    action_plan = bundle.action_plan_rows()
    manifest = bundle.manifest()
    findings_rows = bundle.finding_rows()
    report_pack_path, _ = bundle.report_pack()
    action_plan_path, _ = bundle.action_plan()
    open_count = sum(1 for item in findings_rows if isinstance(item, dict) and item.get("status") == "open")
    accepted_count = sum(1 for item in findings_rows if isinstance(item, dict) and item.get("status") == "accepted_risk")
    return {
        "run_dir": str(run_dir),
        "tenant_name": report_summary.get("tenant_name") or manifest.get("tenant_name"),
        "overall_status": report_summary.get("overall_status") or manifest.get("overall_status"),
        "finding_count": report_summary.get("finding_count", manifest.get("findings_count", len(findings_rows))),
        "blocker_count": report_summary.get("blocker_count", manifest.get("blocker_count", 0)),
        "open_count": report_summary.get("open_count", open_count),
        "accepted_count": report_summary.get("accepted_count", accepted_count),
        "action_plan": action_plan,
        "report_pack_path": str(report_pack_path) if report_pack_path is not None else None,
        "action_plan_path": str(action_plan_path) if action_plan_path is not None else None,
    }


def _payload_text(payload: dict[str, Any], sink: str) -> str:
    lines = [
        f"Auditex {sink} notification",
        f"Tenant: {payload.get('tenant_name') or 'unknown'}",
        f"Status: {payload.get('overall_status') or 'unknown'}",
        f"Findings: {payload.get('finding_count', 0)}",
        f"Open: {payload.get('open_count', 0)}",
        f"Blockers: {payload.get('blocker_count', 0)}",
    ]
    action_plan = payload.get("action_plan") or []
    if action_plan:
        lines.append(f"Top action: {action_plan[0].get('title') or action_plan[0].get('id')}")
    return "\n".join(lines)


def _send_webhook(sink: str, payload: dict[str, Any]) -> dict[str, Any]:
    env_name = WEBHOOK_ENV[sink]
    url = os.environ.get(env_name)
    if not url:
        return {"status": "blocked", "reason": f"{env_name} is not set", "payload": payload}
    body = {
        "text": _payload_text(payload, sink),
        "auditex": payload,
    }
    response = requests.post(url, json=body, timeout=15)
    return {
        "status": "sent" if response.status_code < 400 else "failed",
        "sink": sink,
        "payload": payload,
        "http_status": response.status_code,
        "response_text": response.text,
    }


def _send_smtp(payload: dict[str, Any]) -> dict[str, Any]:
    host = os.environ.get("AUDITEX_SMTP_HOST")
    to_addr = os.environ.get("AUDITEX_SMTP_TO")
    from_addr = os.environ.get("AUDITEX_SMTP_FROM", "auditex@localhost")
    if not host or not to_addr:
        return {
            "status": "blocked",
            "reason": "AUDITEX_SMTP_HOST and AUDITEX_SMTP_TO are required",
            "payload": payload,
        }
    port = int(os.environ.get("AUDITEX_SMTP_PORT", "25"))
    message = EmailMessage()
    message["Subject"] = f"Auditex report for {payload.get('tenant_name') or 'tenant'}"
    message["From"] = from_addr
    message["To"] = to_addr
    message.set_content(_payload_text(payload, "smtp") + "\n\n" + json.dumps(payload, indent=2))
    with smtplib.SMTP(host, port, timeout=15) as client:
        client.send_message(message)
    return {"status": "sent", "sink": "smtp", "payload": payload}


def send_notification(*, run_dir: str, sink: str, dry_run: bool = True) -> dict[str, Any]:
    payload = _build_payload(run_dir)
    if dry_run:
        return {"status": "planned", "sink": sink, "dry_run": True, "payload": payload}
    if sink in WEBHOOK_ENV:
        result = _send_webhook(sink, payload)
        result["dry_run"] = False
        return result
    if sink == "smtp":
        result = _send_smtp(payload)
        result["dry_run"] = False
        return result
    return {"status": "blocked", "sink": sink, "dry_run": False, "reason": "unsupported sink", "payload": payload}
