from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditex.reporting import preview_report
from auditex.exporters import run_exporter, list_exporters

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def offline_run_dir(tmp_path: Path) -> Path:
    from azure_tenant_audit.cli import run_offline

    rc = run_offline(
        REPO_ROOT / "examples" / "sample_audit_bundle" / "sample_result.json",
        tmp_path,
        "contoso",
        "sarif-test",
        auditor_profile="global-reader",
        plane="inventory",
    )
    assert rc == 0
    return tmp_path / "contoso-sarif-test"


def test_list_exporters_includes_sarif_and_oscal() -> None:
    names = {row["name"] for row in list_exporters()}
    assert "sarif" in names
    assert "oscal" in names


def test_preview_report_supports_sarif_format(offline_run_dir: Path) -> None:
    preview = preview_report(run_dir=str(offline_run_dir), format_name="sarif")

    document = json.loads(preview["content"])
    assert document["version"] == "2.1.0"
    assert document["$schema"].startswith("https://json.schemastore.org/sarif")
    assert document["runs"][0]["tool"]["driver"]["name"] == "auditex"
    assert isinstance(document["runs"][0]["results"], list)


def test_sarif_severity_maps_to_levels() -> None:
    from auditex.reporting import render_sarif

    findings = [
        {"id": "f1", "rule_id": "rule.crit", "severity": "critical", "title": "Crit", "category": "x"},
        {"id": "f2", "rule_id": "rule.high", "severity": "high", "title": "High", "category": "x"},
        {"id": "f3", "rule_id": "rule.med", "severity": "medium", "title": "Med", "category": "x"},
        {"id": "f4", "rule_id": "rule.low", "severity": "low", "title": "Low", "category": "x"},
    ]
    summary = {"tenant_name": "acme", "schema_version": "2026-04-21"}

    document = render_sarif(findings=findings, summary=summary, manifest={})

    levels = {result["ruleId"]: result["level"] for result in document["runs"][0]["results"]}
    assert levels["rule.crit"] == "error"
    assert levels["rule.high"] == "error"
    assert levels["rule.med"] == "warning"
    assert levels["rule.low"] == "note"


def test_sarif_rule_index_aligns_results_to_rules() -> None:
    from auditex.reporting import render_sarif

    findings = [
        {"id": "f1", "rule_id": "rule.alpha", "severity": "high", "title": "Alpha", "category": "x"},
        {"id": "f2", "rule_id": "rule.beta", "severity": "medium", "title": "Beta", "category": "x"},
        {"id": "f3", "rule_id": "rule.alpha", "severity": "high", "title": "Alpha 2", "category": "x"},
    ]
    document = render_sarif(findings=findings, summary={}, manifest={})

    rules = document["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [rule["id"] for rule in rules]
    assert rule_ids == ["rule.alpha", "rule.beta"]
    indexes = {result["ruleId"]: result["ruleIndex"] for result in document["runs"][0]["results"]}
    assert indexes["rule.alpha"] == 0
    assert indexes["rule.beta"] == 1


def test_sarif_includes_framework_mappings_in_properties() -> None:
    from auditex.reporting import render_sarif

    findings = [
        {
            "id": "f1",
            "rule_id": "rule.alpha",
            "severity": "high",
            "title": "Alpha",
            "category": "x",
            "framework_mappings": {
                "cis_m365_v3": ["1.1.1"],
                "mitre_attack": ["T1078"],
            },
        }
    ]
    document = render_sarif(findings=findings, summary={}, manifest={})

    rule_props = document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
    assert "tags" in rule_props
    assert "cis_m365_v3:1.1.1" in rule_props["tags"]
    assert "mitre_attack:T1078" in rule_props["tags"]


def test_sarif_rule_help_markdown_contains_template_sections() -> None:
    """D1: every SARIF rule must carry help.text + help.markdown + helpUri so
    GitHub Code Scanning's UI surfaces actionable rule docs inline."""
    from auditex.reporting import render_sarif

    findings = [
        {
            "id": "f1",
            "rule_id": "rule.alpha",
            "severity": "high",
            "title": "Alpha finding",
            "description": "Alpha desc",
            "impact": "Alpha impact",
            "remediation": "Alpha remediation",
            "category": "test",
            "framework_mappings": {
                "cis_m365_v3": ["1.1.1"],
                "mitre_attack": ["T1078"],
            },
            "references": ["RFC 1234", "Microsoft Learn page"],
        }
    ]
    document = render_sarif(findings=findings, summary={}, manifest={})
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]

    assert rule["help"]["text"] == "Alpha remediation"
    md = rule["help"]["markdown"]
    assert "## Alpha finding" in md
    assert "**Description:** Alpha desc" in md
    assert "**Impact:** Alpha impact" in md
    assert "**Remediation:** Alpha remediation" in md
    assert "**Severity:** high" in md
    assert "cis_m365_v3" in md and "1.1.1" in md
    assert "mitre_attack" in md and "T1078" in md
    assert "RFC 1234" in md
    assert rule["helpUri"].endswith("configs/finding-templates.json#rule.alpha")
    assert rule["helpUri"].startswith("https://")


def test_sarif_rule_help_markdown_minimal_when_template_missing() -> None:
    """A finding with only a rule_id and severity must still produce a
    valid help.markdown — no KeyError, no empty string."""
    from auditex.reporting import render_sarif

    findings = [
        {"id": "f1", "rule_id": "rule.bare", "severity": "low"},
    ]
    document = render_sarif(findings=findings, summary={}, manifest={})
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["help"]["markdown"]  # not empty
    assert rule["helpUri"].endswith("configs/finding-templates.json#rule.bare")


def test_sarif_help_fields_populated_for_every_rule_under_diverse_input() -> None:
    """Regression guard: every rule emitted by render_sarif must have the
    three help fields populated regardless of how complete the source
    finding is. Synthetic batch covers the realistic spread of finding
    shapes (full template, partial, minimal)."""
    from auditex.reporting import render_sarif

    findings = [
        {
            "id": "f1",
            "rule_id": "rule.full",
            "severity": "high",
            "title": "Full",
            "description": "d",
            "impact": "i",
            "remediation": "r",
            "category": "x",
            "framework_mappings": {"cis_m365_v3": ["1.1"]},
            "references": ["doc"],
        },
        {
            "id": "f2",
            "rule_id": "rule.no_template",
            "severity": "medium",
            "title": "No template",
            "category": "x",
        },
        {
            "id": "f3",
            "rule_id": "rule.bare",
            "severity": "low",
        },
    ]
    document = render_sarif(findings=findings, summary={}, manifest={})
    rules = document["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 3
    for rule in rules:
        rule_id = rule["id"]
        assert rule.get("help", {}).get("text"), f"rule={rule_id} missing help.text"
        assert rule.get("help", {}).get("markdown"), f"rule={rule_id} missing help.markdown"
        assert rule.get("helpUri"), f"rule={rule_id} missing helpUri"
        assert rule_id in rule["helpUri"], (
            f"rule={rule_id} helpUri does not deep-link to its template entry"
        )


def test_run_exporter_writes_sarif_to_disk(offline_run_dir: Path) -> None:
    result = run_exporter(name="sarif", run_dir=str(offline_run_dir))
    artifact = Path(result["artifacts"][0]["path"])
    assert artifact.exists()
    assert artifact.suffix in {".json", ".sarif"} or artifact.name.endswith(".sarif.json")
    document = json.loads(artifact.read_text(encoding="utf-8"))
    assert document["version"] == "2.1.0"


def test_oscal_export_has_assessment_results_shape(offline_run_dir: Path) -> None:
    result = run_exporter(name="oscal", run_dir=str(offline_run_dir))
    artifact = Path(result["artifacts"][0]["path"])
    document = json.loads(artifact.read_text(encoding="utf-8"))
    assert "assessment-results" in document
    assessment = document["assessment-results"]
    assert "uuid" in assessment
    assert "metadata" in assessment
    assert isinstance(assessment["results"], list)
    assert assessment["results"][0]["uuid"]


def test_oscal_findings_include_related_observations() -> None:
    from auditex.reporting import render_oscal

    findings = [
        {
            "id": "f1",
            "rule_id": "rule.alpha",
            "severity": "high",
            "title": "Alpha",
            "category": "x",
            "framework_mappings": {"nist_800_53": ["AC-3", "AC-6"]},
            "remediation": "Do the thing",
        }
    ]
    document = render_oscal(
        findings=findings,
        summary={"tenant_name": "acme"},
        manifest={"run_id": "run-1", "schema_contract_version": "2026-04-21"},
    )
    result = document["assessment-results"]["results"][0]
    assert result["findings"][0]["title"] == "Alpha"
    related = result["findings"][0]["related-observations"]
    assert related and related[0]["observation-uuid"]
    related_ctrls = result["findings"][0].get("related-risks") or []
    # control IDs surface via target.target-id
    targets = [
        target_id
        for finding in result["findings"]
        for target_id in finding.get("target-ids", [])
    ]
    assert "AC-3" in targets or "nist_800_53:AC-3" in targets
