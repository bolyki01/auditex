from __future__ import annotations

import csv
import hashlib
import html
import json
from collections.abc import Iterable, Mapping
from io import StringIO
from pathlib import Path
from typing import Any

from azure_tenant_audit.resources import resolve_resource_path

from .run_bundle import RunBundle

DEFAULT_SECTION_REGISTRY_PATH = Path("configs/report-sections.json")
FORMAT_EXTENSIONS = {
    "json": ".json",
    "md": ".md",
    "csv": ".csv",
    "html": ".html",
    "sarif": ".sarif.json",
    "oscal": ".oscal.json",
}

_SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
    "informational": "none",
}
AUDITEX_SARIF_TOOL_URI = "https://github.com/magrathean-uk/auditex"
AUDITEX_OSCAL_NS = "https://magrathean.uk/auditex/oscal"

_SECTION_ORDER = ("summary", "findings", "action_plan", "normalized", "blockers", "manifest")
_CSV_COLUMNS = ("id", "title", "severity", "status")
# Severity ordering used for deterministic CSV row sort (highest first).
# Anything outside this set sorts after ``info`` to keep the order stable.
_SEVERITY_RANK: Mapping[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}


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
    payload = _mapping(_read_json(resolve_resource_path(path or DEFAULT_SECTION_REGISTRY_PATH), {}))
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
    bundle = RunBundle(run_path)
    manifest = bundle.manifest()
    fallback_summary = bundle.summary()

    sections = {
        "summary": bundle.report_summary(),
        "findings": bundle.finding_rows(),
        "action_plan": bundle.action_plan_rows(),
        "normalized": _load_normalized_sections(run_path),
        "blockers": bundle.blocker_rows(),
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


def _csv_sort_key(row: Mapping[str, Any]) -> tuple:
    """Deterministic sort key for CSV rows.

    Severity desc (critical → high → medium → low → info → unknown), then
    rule_id, then record_key (from the first evidence_ref), then id. This
    keeps the CSV byte-stable across runs of the same input — D4
    contract.
    """
    severity = str(row.get("severity") or "").strip().lower()
    severity_rank = _SEVERITY_RANK.get(severity, 99)
    rule_id = str(row.get("rule_id") or "")
    record_key = ""
    refs = row.get("evidence_refs")
    if isinstance(refs, list) and refs:
        first = refs[0]
        if isinstance(first, Mapping):
            record_key = str(first.get("record_key") or "")
    finding_id = str(row.get("id") or "")
    return (severity_rank, rule_id, record_key, finding_id)


def _render_csv(selected_sections: dict[str, Any]) -> str:
    rows = _dict_rows(selected_sections.get("findings")) or _dict_rows(selected_sections.get("action_plan"))
    rows = sorted(rows, key=_csv_sort_key)
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


def _sarif_rule_help_markdown(finding: Mapping[str, Any]) -> str:
    """Build a Markdown help block for a SARIF rule.

    GitHub Code Scanning surfaces ``help.markdown`` in the Security UI;
    a structured block (description / impact / remediation / mapped controls /
    references) makes findings actionable inline rather than forcing operators
    to open the auditex bundle to figure out what a rule means.
    """
    parts: list[str] = []
    title = _text(finding.get("title")) or _text(finding.get("rule_id")) or "Auditex finding"
    parts.append(f"## {title}")
    description = _text(finding.get("description"))
    if description:
        parts.append(f"**Description:** {description}")
    impact = _text(finding.get("impact"))
    if impact:
        parts.append(f"**Impact:** {impact}")
    remediation = _text(finding.get("remediation"))
    if remediation:
        parts.append(f"**Remediation:** {remediation}")
    severity = _text(finding.get("severity"))
    if severity:
        parts.append(f"**Severity:** {severity}")
    framework_mappings = (
        finding.get("framework_mappings")
        if isinstance(finding.get("framework_mappings"), Mapping)
        else {}
    )
    if framework_mappings:
        rows: list[str] = []
        for framework, controls in sorted(framework_mappings.items()):
            if isinstance(controls, list) and controls:
                control_text = ", ".join(_text(c) for c in controls if _text(c))
                if control_text:
                    rows.append(f"- **{framework}**: {control_text}")
        if rows:
            parts.append("**Mapped controls:**\n\n" + "\n".join(rows))
    references = finding.get("references")
    if isinstance(references, list) and references:
        ref_lines = "\n".join(f"- {_text(ref)}" for ref in references if _text(ref))
        if ref_lines:
            parts.append("**References:**\n\n" + ref_lines)
    return "\n\n".join(parts)


def _sarif_help_uri(rule_id: str) -> str:
    """Per-rule help URI surfaced by GitHub Code Scanning.

    Until per-rule docs pages exist on a stable site, point at the canonical
    finding-templates.json — operators can navigate to the rule_id entry
    there. URL is deterministic per rule_id so dedup is stable.
    """
    return f"{AUDITEX_SARIF_TOOL_URI}/blob/main/configs/finding-templates.json#{rule_id}"


def _sarif_finding_fingerprint(finding: Mapping[str, Any]) -> str:
    """Stable, content-derived SHA-256 hex digest for SARIF dedup.

    Includes ``rule_id``, the finding ``id``, and the first evidence_ref's
    ``record_key`` (when present). All three are stable across runs of the
    same tenant — re-running auditex against the same posture should
    produce the same fingerprints, which is what GitHub Code Scanning's
    dedup contract requires for its alert tracking.

    Excludes wall-clock and run-derived fields so a re-run against a
    static bundle yields byte-identical fingerprints.
    """
    rule_id = _text(finding.get("rule_id"))
    finding_id = _text(finding.get("id"))
    record_key = ""
    refs = finding.get("evidence_refs")
    if isinstance(refs, list) and refs:
        first = refs[0]
        if isinstance(first, Mapping):
            record_key = _text(first.get("record_key"))
    payload = f"{rule_id}|{finding_id}|{record_key}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def render_sarif(
    *,
    findings: list[dict[str, Any]] | None,
    summary: Mapping[str, Any] | None,
    manifest: Mapping[str, Any] | None,
) -> dict[str, Any]:
    findings_rows = [dict(item) for item in (findings or []) if isinstance(item, Mapping)]
    summary_dict = _mapping(summary)
    manifest_dict = _mapping(manifest)

    rule_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    for finding in findings_rows:
        rule_id = _text(finding.get("rule_id") or finding.get("id"))
        if not rule_id or rule_id in rule_index:
            continue
        rule_index[rule_id] = len(rules)
        framework_mappings = finding.get("framework_mappings") if isinstance(finding.get("framework_mappings"), Mapping) else {}
        tags: list[str] = []
        for framework, controls in framework_mappings.items():
            if not isinstance(controls, list):
                continue
            for control in controls:
                control_text = _text(control).strip()
                if control_text:
                    tags.append(f"{framework}:{control_text}")
        category = _text(finding.get("category"))
        if category:
            tags.append(f"category:{category}")
        help_text = (
            _text(finding.get("remediation"))
            or _text(finding.get("description"))
            or "See Auditex finding for remediation guidance."
        )
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace(".", "_"),
                "shortDescription": {"text": _text(finding.get("title")) or rule_id},
                "fullDescription": {"text": _text(finding.get("description")) or _text(finding.get("title")) or rule_id},
                "help": {
                    "text": help_text,
                    "markdown": _sarif_rule_help_markdown(finding),
                },
                "helpUri": _sarif_help_uri(rule_id),
                "defaultConfiguration": {"level": _SARIF_LEVELS.get(_text(finding.get("severity")).lower(), "warning")},
                "properties": {"tags": sorted(set(tags))} if tags else {"tags": []},
            }
        )

    results: list[dict[str, Any]] = []
    for finding in findings_rows:
        rule_id = _text(finding.get("rule_id") or finding.get("id"))
        if not rule_id:
            continue
        affected = finding.get("affected_objects")
        if isinstance(affected, list) and affected:
            partial_fingerprints = {"affected": ",".join(_text(item) for item in affected)}
        else:
            partial_fingerprints = {}
        result_entry = {
            "ruleId": rule_id,
            "ruleIndex": rule_index.get(rule_id, 0),
            "level": _SARIF_LEVELS.get(_text(finding.get("severity")).lower(), "warning"),
            "message": {
                "text": _text(finding.get("title")) or _text(finding.get("description")) or rule_id,
            },
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": _text(target),
                            "kind": _text(finding.get("category"), "cloud-resource"),
                        }
                        for target in (affected if isinstance(affected, list) else [])
                    ]
                    or [
                        {
                            "name": _text(finding.get("collector"), "auditex"),
                            "kind": _text(finding.get("category"), "cloud-resource"),
                        }
                    ],
                }
            ],
            # Stable per-finding fingerprint for GitHub Code Scanning dedup
            # across runs. Content-derived (rule_id + id + record_key); the
            # ``auditex/v1`` key is the version sentinel — bumping the
            # algorithm in a future release means a new key.
            "fingerprints": {"auditex/v1": _sarif_finding_fingerprint(finding)},
            "properties": {
                "auditex.finding_id": _text(finding.get("id")),
                "auditex.severity": _text(finding.get("severity")),
                "auditex.collector": _text(finding.get("collector")),
                "auditex.category": _text(finding.get("category")),
            },
        }
        if partial_fingerprints:
            result_entry["partialFingerprints"] = partial_fingerprints
        results.append(result_entry)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "auditex",
                        "informationUri": AUDITEX_SARIF_TOOL_URI,
                        "version": _text(manifest_dict.get("schema_contract_version") or summary_dict.get("schema_version")),
                        "rules": rules,
                    }
                },
                "automationDetails": {
                    "id": _text(manifest_dict.get("run_id") or summary_dict.get("run_id") or "auditex-run"),
                    "description": {
                        "text": f"Auditex Microsoft 365 audit run for tenant {_text(summary_dict.get('tenant_name'), 'unknown')}",
                    },
                },
                "results": results,
            }
        ],
    }


def render_oscal(
    *,
    findings: list[dict[str, Any]] | None,
    summary: Mapping[str, Any] | None,
    manifest: Mapping[str, Any] | None,
) -> dict[str, Any]:
    import uuid as _uuid
    from datetime import datetime, timezone

    findings_rows = [dict(item) for item in (findings or []) if isinstance(item, Mapping)]
    summary_dict = _mapping(summary)
    manifest_dict = _mapping(manifest)

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assessment_uuid = _text(manifest_dict.get("run_id") or summary_dict.get("run_id"))
    if not assessment_uuid:
        assessment_uuid = str(_uuid.uuid4())

    observations: list[dict[str, Any]] = []
    findings_oscal: list[dict[str, Any]] = []
    for finding in findings_rows:
        observation_uuid = str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/observation/{_text(finding.get('id'))}"))
        finding_uuid = str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/finding/{_text(finding.get('id'))}"))
        framework_mappings = finding.get("framework_mappings") if isinstance(finding.get("framework_mappings"), Mapping) else {}
        target_ids: list[str] = []
        for framework in ("nist_800_53", "iso_27001", "soc2", "cis_m365_v3", "nis2", "dora", "mitre_attack"):
            controls = framework_mappings.get(framework)
            if not isinstance(controls, list):
                continue
            for control in controls:
                control_text = _text(control).strip()
                if not control_text:
                    continue
                target_ids.append(control_text)
                target_ids.append(f"{framework}:{control_text}")
        observations.append(
            {
                "uuid": observation_uuid,
                "title": _text(finding.get("title")) or _text(finding.get("rule_id")) or _text(finding.get("id")),
                "description": _text(finding.get("description")) or _text(finding.get("title")) or "",
                "methods": ["EXAMINE"],
                "collected": now,
                "subjects": [
                    {"uuid-ref": str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/subject/{_text(item)}")), "title": _text(item)}
                    for item in (finding.get("affected_objects") or [])
                ],
                "props": [
                    {"name": "auditex.finding_id", "value": _text(finding.get("id"))},
                    {"name": "auditex.severity", "value": _text(finding.get("severity"))},
                    {"name": "auditex.collector", "value": _text(finding.get("collector"))},
                ],
            }
        )
        findings_oscal.append(
            {
                "uuid": finding_uuid,
                "title": _text(finding.get("title")) or _text(finding.get("rule_id")) or _text(finding.get("id")),
                "description": _text(finding.get("description")) or _text(finding.get("title")) or "",
                "target-ids": sorted(set(target_ids)),
                "remediation": _text(finding.get("remediation")) or "",
                "related-observations": [{"observation-uuid": observation_uuid}],
                "props": [
                    {"name": "auditex.finding_id", "value": _text(finding.get("id"))},
                    {"name": "auditex.severity", "value": _text(finding.get("severity"))},
                    {"name": "auditex.rule_id", "value": _text(finding.get("rule_id"))},
                ],
            }
        )

    return {
        "assessment-results": {
            "uuid": str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/assessment/{assessment_uuid}")),
            "metadata": {
                "title": f"Auditex Assessment Results for {_text(summary_dict.get('tenant_name'), 'unknown tenant')}",
                "version": _text(manifest_dict.get("schema_contract_version") or summary_dict.get("schema_version") or "0"),
                "oscal-version": "1.1.2",
                "last-modified": now,
            },
            "import-ap": {"href": "#auditex-assessment-plan"},
            "results": [
                {
                    "uuid": str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/result/{assessment_uuid}")),
                    "title": "Auditex audit findings",
                    "description": "Findings produced by Auditex collectors and rules.",
                    "start": now,
                    "end": now,
                    # OSCAL Assessment Results 1.1.2 requires ``reviewed-controls``
                    # on each result. ``include-all: {}`` is the canonical "all
                    # controls in scope" selector — auditex's findings are not
                    # scoped per-control at the result level, the framework
                    # mappings on each finding handle that.
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "description": "Controls reviewed by Auditex collectors and rules",
                                "include-all": {},
                            }
                        ]
                    },
                    "observations": observations,
                    "findings": findings_oscal,
                }
            ],
        }
    }


def _render_sarif(selected_sections: dict[str, Any]) -> str:
    findings = _dict_rows(selected_sections.get("findings"))
    summary = _mapping(selected_sections.get("summary"))
    manifest = _mapping(selected_sections.get("manifest"))
    return _json(render_sarif(findings=findings, summary=summary, manifest=manifest))


def _render_oscal(selected_sections: dict[str, Any]) -> str:
    findings = _dict_rows(selected_sections.get("findings"))
    summary = _mapping(selected_sections.get("summary"))
    manifest = _mapping(selected_sections.get("manifest"))
    return _json(render_oscal(findings=findings, summary=summary, manifest=manifest))


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
        "sarif": _render_sarif,
        "oscal": _render_oscal,
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
