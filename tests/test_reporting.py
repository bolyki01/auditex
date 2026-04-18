from __future__ import annotations

import json
from pathlib import Path

from auditex.exporters import list_exporters, run_exporter
from auditex.reporting import load_section_registry, preview_report, render_report


def _write_run(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run-manifest.json").write_text(
        json.dumps({"tenant_name": "acme", "run_id": "run-1", "overall_status": "partial"}),
        encoding="utf-8",
    )
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run_dir / "reports").mkdir(exist_ok=True)
    (run_dir / "findings").mkdir(exist_ok=True)
    (run_dir / "normalized").mkdir(exist_ok=True)
    (run_dir / "reports" / "report-pack.json").write_text(
        json.dumps(
            {
                "summary": {
                    "tenant_name": "acme",
                    "overall_status": "partial",
                    "finding_count": 2,
                    "blocker_count": 1,
                    "open_count": 1,
                    "accepted_count": 1,
                },
                "findings": [
                    {"id": "finding-1", "title": "Fix sharing", "severity": "high", "status": "open"},
                    {"id": "finding-2", "title": "Accepted", "severity": "medium", "status": "accepted_risk"},
                ],
                "action_plan": [{"id": "finding-1", "title": "Fix sharing", "severity": "high"}],
                "evidence_paths": ["findings/findings.json", "normalized/users.json"],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "reports" / "action-plan.json").write_text(
        json.dumps([{"id": "finding-1", "title": "Fix sharing", "severity": "high"}]),
        encoding="utf-8",
    )
    (run_dir / "findings" / "findings.json").write_text(
        json.dumps(
            [
                {"id": "finding-1", "title": "Fix sharing", "severity": "high", "status": "open"},
                {"id": "finding-2", "title": "Accepted", "severity": "medium", "status": "accepted_risk"},
            ]
        ),
        encoding="utf-8",
    )
    (run_dir / "normalized" / "users.json").write_text(
        json.dumps({"kind": "users", "records": [{"key": "user:1", "display_name": "Alice"}]}),
        encoding="utf-8",
    )


def test_load_section_registry_includes_core_sections() -> None:
    rows = load_section_registry()
    ids = {row["id"] for row in rows}
    assert {"summary", "findings", "action_plan", "normalized"}.issubset(ids)


def test_render_report_respects_section_filters(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)

    result = render_report(
        run_dir=str(run_dir),
        format_name="json",
        include_sections=["summary", "action_plan"],
    )

    payload = json.loads(Path(result["output_path"]).read_text(encoding="utf-8"))
    assert payload["sections"]["summary"]["tenant_name"] == "acme"
    assert "action_plan" in payload["sections"]
    assert "findings" not in payload["sections"]


def test_render_report_supports_md_csv_and_html(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)

    md_result = render_report(run_dir=str(run_dir), format_name="md")
    csv_result = render_report(run_dir=str(run_dir), format_name="csv")
    html_result = render_report(run_dir=str(run_dir), format_name="html")

    assert Path(md_result["output_path"]).read_text(encoding="utf-8").startswith("# Auditex Report")
    assert "finding-1" in Path(csv_result["output_path"]).read_text(encoding="utf-8")
    assert "<html" in Path(html_result["output_path"]).read_text(encoding="utf-8").lower()


def test_preview_report_returns_content_without_writing(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)

    result = preview_report(run_dir=str(run_dir), format_name="json", include_sections=["summary"])

    payload = json.loads(result["content"])
    assert result["format"] == "json"
    assert result["sections"] == ["summary"]
    assert payload["sections"]["summary"]["tenant_name"] == "acme"


def test_list_exporters_includes_builtin_formats() -> None:
    rows = list_exporters()
    names = {row["name"] for row in rows}
    assert {"json", "md", "csv", "html"}.issubset(names)


def test_run_exporter_uses_builtin_renderer(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)

    result = run_exporter(name="html", run_dir=str(run_dir))

    assert result["name"] == "html"
    assert result["artifacts"][0]["path"].endswith(".html")
