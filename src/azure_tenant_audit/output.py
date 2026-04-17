from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import time

LOG = logging.getLogger("azure_tenant_audit.output")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AuditLogger:
    """Persistent event logger for a run."""

    _command_events = frozenset({"command.started", "command.completed", "command.failed"})

    def __init__(self, run_dir: Path) -> None:
        self.jsonl_path = run_dir / "audit-log.jsonl"
        self.command_log_path = run_dir / "audit-command-log.jsonl"
        self.debug_path = run_dir / "audit-debug.log"
        self.jsonl_path.touch(exist_ok=True)
        self.command_log_path.touch(exist_ok=True)
        self.debug_path.touch(exist_ok=True)

    def log(self, event: str, message: str, details: Optional[dict[str, Any]] = None) -> None:
        payload = {
            "ts_utc": _now_iso(),
            "event": event,
            "message": message,
            "details": details or {},
        }
        line = json.dumps(payload, default=str, ensure_ascii=False)
        with self.jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if event in self._command_events:
            with self.command_log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        with self.debug_path.open("a", encoding="utf-8") as handle:
            handle.write(f"[{payload['ts_utc']}] {payload['event']}: {payload['message']} {payload['details']}\n")
        LOG.debug("%s: %s", payload["event"], payload["message"])


class AuditWriter:
    def __init__(self, base_dir: Path, tenant_name: str, run_name: Optional[str] = None):
        self.base_dir = base_dir
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        self.run_id = run_name or f"run_{ts}"
        self.run_dir = base_dir / f"{tenant_name}-{self.run_id}"
        self.raw_dir = self.run_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.chunks_dir = self.run_dir / "chunks"
        self.chunks_dir.mkdir(parents=True, exist_ok=True)
        self.index_dir = self.run_dir / "index"
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir = self.run_dir / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.blockers_dir = self.run_dir / "blockers"
        self.blockers_dir.mkdir(parents=True, exist_ok=True)
        self.normalized_dir = self.run_dir / "normalized"
        self.normalized_dir.mkdir(parents=True, exist_ok=True)
        self.ai_safe_dir = self.run_dir / "ai_safe"
        self.ai_safe_dir.mkdir(parents=True, exist_ok=True)
        self.findings_dir = self.run_dir / "findings"
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir = self.run_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoints_dir = self.run_dir / "checkpoints"
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)
        self.coverage_index_path = self.index_dir / "coverage.jsonl"
        self.summary: dict[str, Any] = {"collectors": []}
        self.coverage: list[dict[str, Any]] = []
        self.audit = AuditLogger(self.run_dir)
        self._manifest = {
            "tenant_name": tenant_name,
            "run_id": self.run_id,
            "created_utc": ts,
            "collectors": [],
            "artifacts": [
                "raw/",
                "chunks/",
                "blockers/",
                "normalized/",
                "ai_safe/",
                "findings/",
                "reports/",
                "checkpoints/",
                "audit-log.jsonl",
                "audit-command-log.jsonl",
                "audit-debug.log",
            ],
        }

    def _record_artifact(self, target: Path) -> None:
        relative = str(target.relative_to(self.run_dir))
        if relative not in self._manifest["artifacts"]:
            self._manifest["artifacts"].append(relative)

    def write_raw(self, name: str, payload: dict[str, Any]) -> Path:
        target = self.raw_dir / f"{name}.json"
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self._record_artifact(target)
        return target

    def write_chunk_records(
        self,
        collector: str,
        name: str,
        page_number: int,
        records: list[dict[str, Any]],
        metadata: Optional[dict[str, Any]] = None,
    ) -> Path:
        collector_dir = self.chunks_dir / collector
        collector_dir.mkdir(parents=True, exist_ok=True)
        target = collector_dir / f"{name}-{page_number:05d}.jsonl"
        with target.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, default=str) + "\n")
        if metadata:
            meta_path = collector_dir / f"{name}-{page_number:05d}.meta.json"
            meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
            self._record_artifact(meta_path)
        self._record_artifact(target)
        return target

    def write_index_records(self, records: list[dict[str, Any]], filename: str = "coverage.jsonl") -> None:
        if not records:
            return
        index_path = self.index_dir / filename
        with index_path.open("a", encoding="utf-8") as handle:
            for record in records:
                self.coverage.append(record)
                handle.write(json.dumps(record, default=str) + "\n")
        self._record_artifact(index_path)

    def log_event(self, event: str, message: str, details: Optional[dict[str, Any]] = None) -> None:
        self.audit.log(event, message, details=details)

    def write_diagnostics(self, diagnostics: list[dict[str, Any]]) -> Path:
        path = self.run_dir / "diagnostics.json"
        path.write_text(json.dumps(diagnostics, indent=2), encoding="utf-8")
        self._record_artifact(path)
        self._manifest["diagnostics_path"] = "diagnostics.json"
        self._manifest["diagnostics_count"] = len(diagnostics)
        return path

    def write_blockers(self, blockers: list[dict[str, Any]]) -> Path:
        path = self.blockers_dir / "blockers.json"
        path.write_text(json.dumps(blockers, indent=2), encoding="utf-8")
        self._record_artifact(path)
        self._manifest["blocker_count"] = len(blockers)
        self._manifest["blockers_path"] = str(path.relative_to(self.run_dir))
        return path

    def write_normalized(self, name: str, payload: dict[str, Any]) -> Path:
        path = self.normalized_dir / f"{name}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self._record_artifact(path)
        return path

    def write_ai_safe(self, name: str, payload: dict[str, Any]) -> Path:
        path = self.ai_safe_dir / f"{name}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self._record_artifact(path)
        return path

    def write_findings(self, findings: list[dict[str, Any]]) -> Path:
        path = self.findings_dir / "findings.json"
        path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        self._record_artifact(path)
        self._manifest["findings_count"] = len(findings)
        self._manifest["findings_path"] = str(path.relative_to(self.run_dir))
        return path

    def write_report_pack(self, payload: dict[str, Any]) -> Path:
        path = self.reports_dir / "report-pack.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self._record_artifact(path)
        self._manifest["report_pack_path"] = str(path.relative_to(self.run_dir))
        return path

    def write_summary(self, item: dict[str, Any]) -> None:
        self.summary["collectors"].append(item)

    def write_bundle(self, metadata: dict[str, Any]) -> None:
        self._manifest["executed_by"] = metadata.get("executed_by")
        self._manifest["selected_collectors"] = metadata.get("collectors", [])
        self._manifest["overall_status"] = metadata.get("overall_status", "partial")
        self._manifest["duration_seconds"] = metadata.get("duration_seconds", 0)
        self._manifest["mode"] = metadata.get("mode", "live")
        self._manifest["auditor_profile"] = metadata.get("auditor_profile", "auto")
        self._manifest["plane"] = metadata.get("plane", "inventory")
        self._manifest["session_context"] = metadata.get("session_context", {})
        self._manifest["command_line"] = metadata.get("command_line", [])
        self._manifest["time_window"] = {
            "since": metadata.get("since"),
            "until": metadata.get("until"),
        }
        self._manifest["run_dir"] = str(self.run_dir)
        self._manifest["audit_log_path"] = "audit-log.jsonl"
        self._manifest["audit_command_log_path"] = "audit-command-log.jsonl"
        self._manifest["debug_log_path"] = "audit-debug.log"
        if self._manifest.get("session_context"):
            auth_context_path = self.run_dir / "auth-context.json"
            auth_context_path.write_text(json.dumps(self._manifest["session_context"], indent=2), encoding="utf-8")
            self._manifest["session_context_path"] = str(auth_context_path.relative_to(self.run_dir))
            self._record_artifact(auth_context_path)

        if self.coverage:
            coverage_path = self.run_dir / "coverage.json"
            coverage_path.write_text(json.dumps(self.coverage, indent=2), encoding="utf-8")
            self._manifest["coverage_path"] = str(coverage_path.relative_to(self.run_dir))
            self._record_artifact(coverage_path)
            self._manifest["coverage_count"] = len(self.coverage)

        manifest_path = self.run_dir / "run-manifest.json"
        manifest_path.write_text(json.dumps(self._manifest, indent=2), encoding="utf-8")

        summary_json_path = self.run_dir / "summary.json"
        summary_md_path = self.run_dir / "summary.md"
        summary_json_path.write_text(json.dumps(self.summary, indent=2), encoding="utf-8")

        lines = [
            "# Audit Summary",
            f"- Run ID: {self.run_id}",
            f"- Tenant: {self._manifest['tenant_name']}",
            f"- Mode: {self._manifest['mode']}",
            "",
            "| Collector | Status | Items | Details |",
            "| --- | --- | --- | --- |",
        ]
        for row in self.summary.get("collectors", []):
            lines.append(
                f"| {row.get('name')} | {row.get('status')} | {row.get('item_count', 0)} | {row.get('message', '')} |"
            )
        summary_md_path.write_text("\n".join(lines), encoding="utf-8")

        self.log_event(
            "run.completed",
            "Run complete",
            {
                "overall_status": self._manifest["overall_status"],
                "collector_count": len(self.summary.get("collectors", [])),
                "duration_seconds": self._manifest["duration_seconds"],
            },
        )
