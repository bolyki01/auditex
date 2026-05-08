from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    from azure_tenant_audit.cli import run_offline

    rc = run_offline(
        REPO_ROOT / "examples" / "sample_audit_bundle" / "sample_result.json",
        tmp_path,
        "contoso",
        "gate-test",
        auditor_profile="global-reader",
        plane="inventory",
    )
    assert rc == 0
    return tmp_path / "contoso-gate-test"


def _write_findings(run_dir: Path, findings: list[dict[str, object]]) -> None:
    findings_path = run_dir / "findings" / "findings.json"
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    findings_path.write_text(json.dumps(findings), encoding="utf-8")
    report_path = run_dir / "reports" / "report-pack.json"
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["findings"] = findings
        report_path.write_text(json.dumps(report), encoding="utf-8")


def _gate(args: list[str]) -> tuple[int, str]:
    from auditex.cli import main

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        rc = main(args)
    return rc, buffer.getvalue()


def test_gate_passes_when_no_findings_meet_threshold(run_dir: Path) -> None:
    _write_findings(
        run_dir,
        [
            {"id": "f1", "rule_id": "x", "severity": "low", "title": "Low one", "status": "open"},
            {"id": "f2", "rule_id": "y", "severity": "medium", "title": "Medium one", "status": "open"},
        ],
    )

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high"])

    assert rc == 0
    payload = json.loads(output)
    assert payload["pass"] is True
    assert payload["fail_on"] == "high"
    assert payload["counts_at_or_above_threshold"] == 0


def test_gate_fails_when_finding_meets_threshold(run_dir: Path) -> None:
    _write_findings(
        run_dir,
        [
            {"id": "f1", "rule_id": "x", "severity": "high", "title": "High one", "status": "open"},
        ],
    )

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high"])

    assert rc == 2
    payload = json.loads(output)
    assert payload["pass"] is False
    assert payload["counts_at_or_above_threshold"] == 1


def test_gate_critical_threshold_does_not_fail_on_high(run_dir: Path) -> None:
    _write_findings(
        run_dir,
        [
            {"id": "f1", "rule_id": "x", "severity": "high", "title": "High one", "status": "open"},
            {"id": "f2", "rule_id": "y", "severity": "high", "title": "High two", "status": "open"},
        ],
    )

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "critical"])

    assert rc == 0
    payload = json.loads(output)
    assert payload["pass"] is True


def test_gate_skips_waived_findings(run_dir: Path) -> None:
    _write_findings(
        run_dir,
        [
            {"id": "f1", "rule_id": "x", "severity": "critical", "title": "Crit", "status": "waived"},
        ],
    )

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high"])

    assert rc == 0
    payload = json.loads(output)
    assert payload["pass"] is True
    assert payload["counts_at_or_above_threshold"] == 0


def test_gate_returns_severity_breakdown(run_dir: Path) -> None:
    _write_findings(
        run_dir,
        [
            {"id": "f1", "rule_id": "x", "severity": "critical", "title": "Crit", "status": "open"},
            {"id": "f2", "rule_id": "y", "severity": "high", "title": "High", "status": "open"},
            {"id": "f3", "rule_id": "z", "severity": "medium", "title": "Medium", "status": "open"},
            {"id": "f4", "rule_id": "w", "severity": "low", "title": "Low", "status": "open"},
        ],
    )

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "medium"])

    assert rc == 2
    payload = json.loads(output)
    assert payload["counts_by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 1}
    assert payload["counts_at_or_above_threshold"] == 3
