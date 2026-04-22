from __future__ import annotations

from pathlib import Path
from typing import Any

from auditex.evidence_db import build_run_evidence_index

from .ai_context import build_ai_context, build_privacy_block, build_validation_report
from .contracts import CONTRACT_VERSION
from .output import AuditWriter


def finalize_bundle_contract(
    *,
    writer: AuditWriter,
    bundle_metadata: dict[str, Any],
    run_metadata: dict[str, Any],
    normalized_snapshot: dict[str, Any],
    capability_rows: list[dict[str, Any]],
    coverage_ledger: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Write the stable post-run contract artifacts through one path.

    The manifest must exist before the evidence DB and validation can be checked against
    it, so this function writes a suppressed manifest snapshot first, builds the DB,
    writes ai_context/validation, then writes the final manifest.
    """

    privacy = bundle_metadata.get("privacy") or build_privacy_block(safe_for_external_llm=False)
    metadata = dict(bundle_metadata)
    metadata.update(
        {
            "privacy": privacy,
            "ai_context_path": "ai_context.json",
            "validation_path": "validation.json",
            "evidence_db_path": "index/evidence.sqlite",
            "schema_contract_version": CONTRACT_VERSION,
        }
    )

    writer.write_bundle({**metadata, "_suppress_completion_log": True})
    evidence_db_path = build_run_evidence_index(writer.run_dir)
    writer._record_artifact(evidence_db_path)

    ai_context = build_ai_context(
        run_dir=writer.run_dir,
        run_metadata=run_metadata,
        normalized_snapshot=normalized_snapshot,
        capability_rows=capability_rows,
        coverage_ledger=coverage_ledger,
        blockers=blockers,
        findings=findings,
    )
    writer.write_json_artifact("ai_context.json", ai_context)
    validation = build_validation_report(run_dir=writer.run_dir, ai_context=ai_context, findings=findings)
    writer.write_json_artifact("validation.json", validation)
    writer.log_event(
        "contract.validation.passed" if validation.get("valid") else "contract.validation.failed",
        "Bundle contract validation passed" if validation.get("valid") else "Bundle contract validation failed",
        {
            "contract_version": validation.get("contract_version"),
            "valid": validation.get("valid"),
            "issue_count": validation.get("issue_count", 0),
            "error_count": validation.get("error_count", 0),
        },
    )

    final_metadata = dict(metadata)
    final_metadata["contract_status"] = "valid" if validation.get("valid") else "invalid"
    final_metadata["contract_issue_count"] = validation.get("issue_count", 0)
    writer.write_bundle(final_metadata)

    return {
        "evidence_db_path": str(Path(evidence_db_path).relative_to(writer.run_dir)),
        "ai_context_path": "ai_context.json",
        "validation_path": "validation.json",
        "validation": validation,
    }
