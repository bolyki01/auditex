from __future__ import annotations

import csv
import html
import json
from io import StringIO
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SECTION_REGISTRY_PATH = REPO_ROOT / "configs" / "report-sections.json"
FORMAT_EXTENSIONS = {"json": ".json", "md": ".md", "csv": ".csv", "html": ".html"}


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default
    return payload if payload is not None else default


def load_section_registry(path: Path | None = None) -> list[dict[str, Any]]:
    payload = _load_json(path or DEFAULT_SECTION_REGISTRY_PATH, default={})
    rows = payload.get("sections", []) if isinstance(payload, dict) else []
    if not isinstance(rows, list):
        return []
    registry: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("id"):
            continue
        registry.append(
            {
                "id": str(row["id"]),
                "title": row.get("title") or row["id"],
                "description": row.get("description") or "",
            }
        )
    return registry


def _load_normalized_sections(run_path: Path) -> dict[str, Any]:
    normalized_dir = run_path / "normalized"
    if not normalized_dir.exists():
        return {}
    sections: dict[str, Any] = {}
    for path in sorted(normalized_dir.glob("*.json")):
        payload = _load_json(path, default={})
        if payload:
            sections[path.stem] = payload
    return sections


def load_report_bundle(run_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    report_pack = _load_json(run_path / "reports" / "report-pack.json", default={})
    summary_json = _load_json(run_path / "summary.json", default={})
    findings_json = _load_json(run_path / "findings" / "findings.json", default=[])
    action_plan_json = _load_json(run_path / "reports" / "action-plan.json", default=[])
    blockers_json = _load_json(run_path / "blockers" / "blockers.json", default=[])
    manifest_json = _load_json(run_path / "run-manifest.json", default={})
    summary = report_pack.get("summary") if isinstance(report_pack, dict) else None
    findings = report_pack.get("findings") if isinstance(report_pack, dict) else None
    action_plan = report_pack.get("action_plan") if isinstance(report_pack, dict) else None
    return {
        "run_dir": str(run_path),
        "manifest": manifest_json,
        "summary_json": summary_json,
        "sections": {
            "summary": summary if isinstance(summary, dict) else {},
            "findings": findings if isinstance(findings, list) else findings_json,
            "action_plan": action_plan if isinstance(action_plan, list) else action_plan_json,
            "normalized": _load_normalized_sections(run_path),
            "blockers": blockers_json if isinstance(blockers_json, list) else [],
            "manifest": manifest_json if isinstance(manifest_json, dict) else {},
        },
    }


def _select_sections(
    bundle: dict[str, Any],
    *,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
) -> dict[str, Any]:
    sections = dict(bundle.get("sections") or {})
    include = set(include_sections or sections.keys())
    exclude = set(exclude_sections or [])
    return {section_id: payload for section_id, payload in sections.items() if section_id in include and section_id not in exclude}


def _default_output_path(run_path: Path, format_name: str) -> Path:
    ext = FORMAT_EXTENSIONS[format_name]
    return run_path / "reports" / f"rendered-report{ext}"


def _render_json(selected_sections: dict[str, Any]) -> str:
    return json.dumps({"sections": selected_sections}, indent=2)


def _render_markdown(selected_sections: dict[str, Any]) -> str:
    summary = selected_sections.get("summary") or {}
    findings = selected_sections.get("findings") or []
    lines = [
        "# Auditex Report",
        "",
        f"- Tenant: {summary.get('tenant_name') or 'unknown'}",
        f"- Status: {summary.get('overall_status') or 'unknown'}",
        f"- Findings: {summary.get('finding_count', len(findings))}",
        f"- Open: {summary.get('open_count', 0)}",
        "",
        "## Findings",
        "",
        "| ID | Severity | Status | Title |",
        "| --- | --- | --- | --- |",
    ]
    for finding in findings:
        lines.append(
            f"| {finding.get('id')} | {finding.get('severity')} | {finding.get('status')} | {finding.get('title')} |"
        )
    return "\n".join(lines)


def _render_csv(selected_sections: dict[str, Any]) -> str:
    rows = selected_sections.get("findings") or selected_sections.get("action_plan") or []
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["id", "title", "severity", "status"])
    writer.writeheader()
    for row in rows:
        if not isinstance(row, dict):
            continue
        writer.writerow(
            {
                "id": row.get("id"),
                "title": row.get("title"),
                "severity": row.get("severity"),
                "status": row.get("status"),
            }
        )
    return buffer.getvalue()


def _render_html(selected_sections: dict[str, Any]) -> str:
    summary = selected_sections.get("summary") or {}
    findings = selected_sections.get("findings") or []
    items = "".join(
        f"<tr><td>{html.escape(str(item.get('id')))}</td><td>{html.escape(str(item.get('severity')))}</td>"
        f"<td>{html.escape(str(item.get('status')))}</td><td>{html.escape(str(item.get('title')))}</td></tr>"
        for item in findings
        if isinstance(item, dict)
    )
    return (
        "<html><head><title>Auditex Report</title></head><body>"
        f"<h1>Auditex Report</h1><p>Tenant: {html.escape(str(summary.get('tenant_name') or 'unknown'))}</p>"
        f"<p>Status: {html.escape(str(summary.get('overall_status') or 'unknown'))}</p>"
        "<table><thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Title</th></tr></thead>"
        f"<tbody>{items}</tbody></table></body></html>"
    )


def render_report(
    *,
    run_dir: str,
    format_name: str,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    preview = preview_report(
        run_dir=run_dir,
        format_name=format_name,
        include_sections=include_sections,
        exclude_sections=exclude_sections,
    )
    content = preview["content"]
    selected_sections = preview["sections"]
    run_path = Path(run_dir)
    target = Path(output_path) if output_path else _default_output_path(run_path, format_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {
        "format": format_name,
        "output_path": str(target),
        "sections": selected_sections,
    }


def preview_report(
    *,
    run_dir: str,
    format_name: str,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
) -> dict[str, Any]:
    if format_name not in FORMAT_EXTENSIONS:
        raise ValueError(f"Unsupported report format: {format_name}")
    run_path = Path(run_dir)
    bundle = load_report_bundle(run_path)
    selected_sections = _select_sections(
        bundle,
        include_sections=include_sections,
        exclude_sections=exclude_sections,
    )
    if format_name == "json":
        content = _render_json(selected_sections)
    elif format_name == "md":
        content = _render_markdown(selected_sections)
    elif format_name == "csv":
        content = _render_csv(selected_sections)
    else:
        content = _render_html(selected_sections)
    return {
        "format": format_name,
        "content": content,
        "sections": list(selected_sections.keys()),
    }
