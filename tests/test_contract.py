from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.contracts import ROOT_REQUIRED_ARTIFACTS, build_validation_report


REPO_ROOT = Path(__file__).resolve().parents[1]


def _offline_contract_run(tmp_path: Path) -> Path:
    rc = run_offline(
        REPO_ROOT / "examples" / "sample_audit_bundle" / "sample_result.json",
        tmp_path,
        "contoso",
        "contract",
        auditor_profile="global-reader",
        plane="inventory",
    )
    assert rc == 0
    return tmp_path / "contoso-contract"


def test_offline_bundle_satisfies_frozen_contract(tmp_path: Path) -> None:
    run_dir = _offline_contract_run(tmp_path)

    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))

    assert manifest["schema_contract_version"] == "2026-04-21"
    assert manifest["contract_status"] == "valid"
    assert manifest["contract_issue_count"] == 0
    assert summary["schema_version"] == "2026-04-21"
    assert validation["valid"] is True, validation["issues"]
    assert validation["issues"] == []
    for relative in ROOT_REQUIRED_ARTIFACTS:
        assert (run_dir / relative).exists(), relative

    with sqlite3.connect(run_dir / "index" / "evidence.sqlite") as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"run_meta", "section_stats", "normalized_records"}.issubset(tables)
        assert conn.execute("SELECT COUNT(*) FROM normalized_records").fetchone()[0] > 0


def test_contract_validation_fails_loudly_for_missing_artifacts(tmp_path: Path) -> None:
    run_dir = _offline_contract_run(tmp_path)
    (run_dir / "ai_context.json").unlink()

    report = build_validation_report(run_dir=run_dir)
    issue_codes = {item["code"] for item in report["issues"]}

    assert report["valid"] is False
    assert "missing_required_artifact" in issue_codes
    assert "invalid_json_artifact" in issue_codes
