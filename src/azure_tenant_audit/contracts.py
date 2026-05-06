from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .resources import list_resource_files, resolve_resource_path

CONTRACT_VERSION = "2026-04-21"

ROOT_REQUIRED_ARTIFACTS = (
    "run-manifest.json",
    "summary.json",
    "reports/report-pack.json",
    "index/evidence.sqlite",
    "ai_context.json",
    "validation.json",
)

_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "run-manifest.json": (
        "schema_version",
        "tenant_name",
        "run_id",
        "overall_status",
        "mode",
        "auditor_profile",
        "selected_collectors",
        "artifacts",
        "evidence_db_path",
        "ai_context_path",
        "validation_path",
    ),
    "summary.json": ("schema_version", "tenant_name", "run_id", "collectors"),
    "reports/report-pack.json": ("schema_version", "summary", "findings", "evidence_paths"),
    "ai_context.json": ("schema_version", "run", "privacy", "counts", "coverage", "findings", "artifacts", "read_order"),
}

_EVIDENCE_REF_REQUIRED = ("artifact_path", "artifact_kind", "collector", "record_key")
_AI_SAFE_SENSITIVE_KEYS = re.compile(
    r"(access[_-]?token|refresh[_-]?token|client[_-]?secret|secret|password|credential|authorization|raw_claims)",
    re.IGNORECASE,
)
_AI_SAFE_SENSITIVE_VALUES = re.compile(r"(Bearer\s+[A-Za-z0-9._-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.)")
_SENSITIVE_CONTRACT_ARTIFACTS = (
    "run-manifest.json",
    "ai_context.json",
    "reports/report-pack.json",
    "normalized/auth_context.json",
)


def _read_json(path: Path, fallback: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return fallback


def _issue(code: str, *, path: str | None = None, details: Any = None, severity: str = "error") -> dict[str, Any]:
    payload: dict[str, Any] = {"code": code, "severity": severity}
    if path is not None:
        payload["path"] = path
    if details is not None:
        payload["details"] = details
    return payload


def _validate_required_json_fields(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    for relative, required_fields in _REQUIRED_FIELDS.items():
        path = run_dir / relative
        payload = _read_json(path, fallback=None)
        if not isinstance(payload, Mapping):
            issues.append(_issue("invalid_json_artifact", path=relative))
            continue
        missing = [field for field in required_fields if field not in payload]
        if missing:
            issues.append(_issue("missing_json_required_fields", path=relative, details=missing))


def _load_findings(run_dir: Path, supplied: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if supplied is not None:
        return [dict(item) for item in supplied if isinstance(item, Mapping)]
    payload = _read_json(run_dir / "findings" / "findings.json", fallback=[])
    return [dict(item) for item in payload if isinstance(item, Mapping)] if isinstance(payload, list) else []


def _validate_evidence_refs(run_dir: Path, findings: list[dict[str, Any]], issues: list[dict[str, Any]]) -> None:
    ids = [str(item.get("id")) for item in findings if item.get("id")]
    duplicate_ids = sorted(key for key, count in Counter(ids).items() if count > 1)
    if duplicate_ids:
        issues.append(_issue("duplicate_finding_ids", path="findings/findings.json", details=duplicate_ids))

    for index, finding in enumerate(findings):
        finding_id = str(finding.get("id") or f"finding:{index}")
        refs = finding.get("evidence_refs")
        if not isinstance(refs, list) or not refs:
            issues.append(_issue("missing_evidence_refs", path="findings/findings.json", details=finding_id))
            continue
        for ref_index, ref in enumerate(refs):
            if not isinstance(ref, Mapping):
                issues.append(
                    _issue(
                        "invalid_evidence_ref",
                        path="findings/findings.json",
                        details={"finding_id": finding_id, "ref_index": ref_index},
                    )
                )
                continue
            missing = [field for field in _EVIDENCE_REF_REQUIRED if not str(ref.get(field) or "").strip()]
            if missing:
                issues.append(
                    _issue(
                        "invalid_evidence_ref",
                        path="findings/findings.json",
                        details={"finding_id": finding_id, "ref_index": ref_index, "missing": missing},
                    )
                )
            artifact_path = str(ref.get("artifact_path") or "")
            if artifact_path and not (run_dir / artifact_path).exists():
                issues.append(
                    _issue(
                        "broken_evidence_ref",
                        path="findings/findings.json",
                        details={"finding_id": finding_id, "artifact_path": artifact_path},
                    )
                )


def _validate_normalized_records(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    normalized_dir = run_dir / "normalized"
    if not normalized_dir.exists():
        issues.append(_issue("missing_artifact_directory", path="normalized"))
        return
    for path in sorted(normalized_dir.glob("*.json")):
        payload = _read_json(path, fallback={})
        if not isinstance(payload, Mapping):
            issues.append(_issue("invalid_json_artifact", path=str(path.relative_to(run_dir))))
            continue
        records = payload.get("records")
        if records is None:
            continue
        if not isinstance(records, list):
            issues.append(_issue("invalid_records_shape", path=str(path.relative_to(run_dir))))
            continue
        bad: list[int] = []
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                bad.append(index)
                continue
            key = (
                record.get("key")
                or record.get("id")
                or record.get("name")
                or record.get("display_name")
                or record.get("collector")
                or record.get("surface")
            )
            if key is None or not str(key).strip():
                bad.append(index)
        if bad:
            issues.append(_issue("bad_record_keys", path=str(path.relative_to(run_dir)), details=bad[:25]))


def _walk_sensitive_ai_safe(value: Any, path: str, hits: list[dict[str, Any]]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            current = f"{path}/{key_text}" if path else key_text
            if _AI_SAFE_SENSITIVE_KEYS.search(key_text):
                hits.append({"path": current, "reason": "sensitive_key"})
            _walk_sensitive_ai_safe(item, current, hits)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_sensitive_ai_safe(item, f"{path}[{index}]", hits)
    elif isinstance(value, str) and _AI_SAFE_SENSITIVE_VALUES.search(value):
        hits.append({"path": path, "reason": "sensitive_value"})


def _validate_ai_safe(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    ai_safe_dir = run_dir / "ai_safe"
    if not ai_safe_dir.exists():
        return
    for path in sorted(ai_safe_dir.glob("*.json")):
        payload = _read_json(path, fallback={})
        hits: list[dict[str, Any]] = []
        _walk_sensitive_ai_safe(payload, "", hits)
        if hits:
            issues.append(_issue("unsafe_ai_safe_artifact", path=str(path.relative_to(run_dir)), details=hits[:25]))


def _validate_sensitive_contract_artifacts(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    for relative in _SENSITIVE_CONTRACT_ARTIFACTS:
        path = run_dir / relative
        if not path.exists():
            continue
        payload = _read_json(path, fallback={})
        hits: list[dict[str, Any]] = []
        _walk_sensitive_ai_safe(payload, "", hits)
        if hits:
            issues.append(_issue("unsafe_contract_artifact", path=relative, details=hits[:25]))


def _validate_evidence_db(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    db_path = run_dir / "index" / "evidence.sqlite"
    if not db_path.exists():
        issues.append(_issue("missing_required_artifact", path="index/evidence.sqlite"))
        return
    try:
        with sqlite3.connect(db_path) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            required = {"run_meta", "section_stats", "normalized_records"}
            missing = sorted(required - tables)
            if missing:
                issues.append(_issue("invalid_evidence_sqlite_schema", path="index/evidence.sqlite", details=missing))
    except sqlite3.DatabaseError as exc:
        issues.append(_issue("invalid_evidence_sqlite", path="index/evidence.sqlite", details=str(exc)))


def build_validation_report(
    *,
    run_dir: str | Path,
    ai_context: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    required_artifacts: tuple[str, ...] = ROOT_REQUIRED_ARTIFACTS,
) -> dict[str, Any]:
    run_path = Path(run_dir)
    issues: list[dict[str, Any]] = []

    for relative in required_artifacts:
        if not (run_path / relative).exists():
            # validation.json is allowed to be absent while the report itself is being built.
            if relative == "validation.json":
                continue
            issues.append(_issue("missing_required_artifact", path=relative))

    _validate_required_json_fields(run_path, issues)
    loaded_findings = _load_findings(run_path, findings)
    _validate_evidence_refs(run_path, loaded_findings, issues)
    _validate_normalized_records(run_path, issues)
    _validate_ai_safe(run_path, issues)
    _validate_sensitive_contract_artifacts(run_path, issues)
    _validate_evidence_db(run_path, issues)

    context = ai_context if isinstance(ai_context, Mapping) else _read_json(run_path / "ai_context.json", fallback={})
    if not isinstance(context, Mapping):
        issues.append(_issue("invalid_json_artifact", path="ai_context.json"))
    else:
        counts = context.get("counts")
        if not isinstance(counts, Mapping) or not isinstance(counts.get("normalized_counts"), Mapping):
            issues.append(_issue("missing_normalized_counts", path="ai_context.json"))

    errors = [item for item in issues if item.get("severity") == "error"]
    return {
        "schema_version": CONTRACT_VERSION,
        "contract_version": CONTRACT_VERSION,
        "valid": not errors,
        "issue_count": len(issues),
        "error_count": len(errors),
        "warning_count": len(issues) - len(errors),
        "required_artifacts": list(required_artifacts),
        "issues": issues,
    }


def contract_schema_manifest(schema_dir: str | Path = "schemas") -> dict[str, Any]:
    root = resolve_resource_path(schema_dir)
    schemas = [path.name for path in list_resource_files(schema_dir, "*.schema.json")]
    return {"contract_version": CONTRACT_VERSION, "schema_dir": str(root), "schemas": schemas}
