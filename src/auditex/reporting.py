from __future__ import annotations

import csv
import html
import json
from collections.abc import Iterable, Mapping
from io import StringIO
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SECTION_REGISTRY_PATH = REPO_ROOT / "configs" / "report-sections.json"
FORMAT_EXTENSIONS = {"json": ".json", "md": ".md", "csv": ".csv", "html": ".html"}

_SECTION_ORDER = ("summary", "findings", "action_plan", "normalized", "blockers", "manifest")
_CSV_COLUMNS = ("id", "title", "severity", "status")


def _read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return fallback


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _dict_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def _relative_source(path: Path, run_path: Path) -> str:
    try:
        return str(path.relative_to(run_path))
    except ValueError:
        return str(path)


def load_section_registry(path: Path | None = None) -> list[dict[str, Any]]:
    payload = _mapping(_read_json(path or DEFAULT_SECTION_REGISTRY_PATH, {}))
    rows = payload.get("sections")
    if not isinstance(rows, list):
        return []

    registry: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in rows:
        if not isinstance(item, Mapping):
            continue
        section_id = _text(item.get("id")).strip()
        if not section_id or section_id in seen:
            continue
        seen.add(section_id)
        registry.append(
            {
                "id": section_id,
                "title": _text(item.get("title"), section_id).strip() or section_id,
                "description": _text(item.get("description")).strip(),
            }
        )
    return registry


def _load_normalized_sections(run_path: Path) -> dict[str, Any]:
    normalized_dir = run_path / "normalized"
    if not normalized_dir.is_dir():
        return {}

    sections: dict[str, Any] = {}
    for path in sorted(normalized_dir.glob("*.json"), key=lambda item: item.name):
        payload = _read_json(path, {})
        if payload not in ({}, [], None):
            sections[path.stem] = payload
    return sections


def load_report_bundle(run_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    report_pack = _mapping(_read_json(run_path / "reports" / "report-pack.json", {}))
    manifest = _mapping(_read_json(run_path / "run-manifest.json", {}))

    fallback_summary = _mapping(_read_json(run_path / "summary.json", {}))
    summary = _mapping(report_pack.get("summary")) or fallback_summary

    findings = _dict_rows(report_pack.get("findings"))
    if not findings:
        findings = _dict_rows(_read_json(run_path / "findings" / "findings.json", []))

    action_plan = _dict_rows(report_pack.get("action_plan"))
    if not action_plan:
        action_plan = _dict_rows(_read_json(run_path / "reports" / "action-plan.json", []))

    blockers = _dict_rows(_read_json(run_path / "blockers" / "blockers.json", []))

    sections = {
        "summary": summary,
        "findings": findings,
        "action_plan": action_plan,
        "normalized": _load_normalized_sections(run_path),
        "blockers": blockers,
        "manifest": manifest,
    }
    return {"run_dir": str(run_path), "manifest": manifest, "summary_json": fallback_summary, "sections": sections}


def _select_sections(
    bundle: dict[str, Any],
    *,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
) -> dict[str, Any]:
    sections = _mapping(bundle.get("sections"))
    if include_sections is None:
        include = [key for key in _SECTION_ORDER if key in sections]
        include.extend(key for key in sections if key not in include)
    else:
        include = list(include_sections)
    blocked = set(exclude_sections or [])

    selected: dict[str, Any] = {}
    for key in include:
        if key in sections and key not in blocked:
            selected[key] = sections[key]
    return selected


def _default_output_path(run_path: Path, format_name: str) -> Path:
    return run_path / "reports" / f"rendered-report{FORMAT_EXTENSIONS[format_name]}"


def _render_json(selected_sections: dict[str, Any]) -> str:
    return _json({"sections": selected_sections})


def _markdown_cell(value: Any) -> str:
    return _text(value, "").replace("|", "\\|").replace("\n", " ").strip()


def _render_markdown(selected_sections: dict[str, Any]) -> str:
    summary = _mapping(selected_sections.get("summary"))
    findings = _dict_rows(selected_sections.get("findings"))

    lines = [
        "# Auditex Report",
        "",
        f"- Tenant: {_text(summary.get('tenant_name'), 'unknown')}",
        f"- Status: {_text(summary.get('overall_status'), 'unknown')}",
        f"- Findings: {_text(summary.get('finding_count'), str(len(findings)))}",
        f"- Open: {_text(summary.get('open_count'), '0')}",
        "",
        "## Findings",
        "",
        "| ID | Severity | Status | Title |",
        "| --- | --- | --- | --- |",
    ]

    if findings:
        for row in findings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_cell(row.get("id")),
                        _markdown_cell(row.get("severity")),
                        _markdown_cell(row.get("status")),
                        _markdown_cell(row.get("title")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("|  |  |  | No findings in the selected report sections. |")

    if "blockers" in selected_sections and _dict_rows(selected_sections.get("blockers")):
        lines.extend(["", "## Blockers", ""])
        for blocker in _dict_rows(selected_sections.get("blockers")):
            lines.append(f"- {_markdown_cell(blocker.get('collector') or blocker.get('id') or 'blocker')}: {_markdown_cell(blocker.get('message') or blocker.get('error'))}")

    return "\n".join(lines) + "\n"


def _render_csv(selected_sections: dict[str, Any]) -> str:
    rows = _dict_rows(selected_sections.get("findings")) or _dict_rows(selected_sections.get("action_plan"))
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(_CSV_COLUMNS), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: row.get(column, "") for column in _CSV_COLUMNS})
    return buffer.getvalue()


def _html(value: Any) -> str:
    return html.escape(_text(value, ""), quote=True)


def _render_key_values(title: str, values: Mapping[str, Any]) -> str:
    rows = []
    for key in sorted(values):
        value = values[key]
        if isinstance(value, (dict, list)):
            value = _json(value)
        rows.append(f"<tr><th scope=\"row\">{_html(key)}</th><td>{_html(value)}</td></tr>")
    if not rows:
        rows.append("<tr><td colspan=\"2\">No data</td></tr>")
    return f"<section><h2>{_html(title)}</h2><table><tbody>{''.join(rows)}</tbody></table></section>"


def _render_findings_table(title: str, rows: Iterable[Mapping[str, Any]]) -> str:
    body = []
    for item in rows:
        body.append(
            "<tr>"
            f"<td>{_html(item.get('id'))}</td>"
            f"<td>{_html(item.get('severity'))}</td>"
            f"<td>{_html(item.get('status'))}</td>"
            f"<td>{_html(item.get('title'))}</td>"
            "</tr>"
        )
    if not body:
        body.append("<tr><td colspan=\"4\">No rows</td></tr>")
    return (
        f"<section><h2>{_html(title)}</h2>"
        "<table><thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Title</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table></section>"
    )


def _render_json_section(title: str, payload: Any) -> str:
    return f"<section><h2>{_html(title)}</h2><pre>{_html(_json(payload))}</pre></section>"


def _render_html(selected_sections: dict[str, Any]) -> str:
    summary = _mapping(selected_sections.get("summary"))
    sections = [
        "<!doctype html>",
        "<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Auditex Report</title>",
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;line-height:1.4}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ccc;padding:.45rem;text-align:left;vertical-align:top}pre{white-space:pre-wrap;background:#f6f6f6;padding:1rem;overflow:auto}</style>",
        "</head><body>",
        "<h1>Auditex Report</h1>",
        f"<p><strong>Tenant:</strong> {_html(summary.get('tenant_name') or 'unknown')}</p>",
        f"<p><strong>Status:</strong> {_html(summary.get('overall_status') or 'unknown')}</p>",
    ]

    if "summary" in selected_sections:
        sections.append(_render_key_values("Summary", summary))
    if "findings" in selected_sections:
        sections.append(_render_findings_table("Findings", _dict_rows(selected_sections.get("findings"))))
    if "action_plan" in selected_sections:
        sections.append(_render_findings_table("Action Plan", _dict_rows(selected_sections.get("action_plan"))))
    if "blockers" in selected_sections:
        sections.append(_render_json_section("Blockers", selected_sections.get("blockers")))
    if "normalized" in selected_sections:
        sections.append(_render_json_section("Normalized Evidence", selected_sections.get("normalized")))
    if "manifest" in selected_sections:
        sections.append(_render_json_section("Manifest", selected_sections.get("manifest")))

    sections.append("</body></html>\n")
    return "".join(sections)


def preview_report(
    *,
    run_dir: str,
    format_name: str,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
) -> dict[str, Any]:
    if format_name not in FORMAT_EXTENSIONS:
        raise ValueError(f"Unsupported report format: {format_name}")

    bundle = load_report_bundle(run_dir)
    selected = _select_sections(bundle, include_sections=include_sections, exclude_sections=exclude_sections)
    renderers = {
        "json": _render_json,
        "md": _render_markdown,
        "csv": _render_csv,
        "html": _render_html,
    }
    return {"format": format_name, "content": renderers[format_name](selected), "sections": list(selected.keys())}


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
    target = Path(output_path) if output_path else _default_output_path(Path(run_dir), format_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(preview["content"], encoding="utf-8")
    return {"format": format_name, "output_path": str(target), "sections": preview["sections"]}
