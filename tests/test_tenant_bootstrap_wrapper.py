from __future__ import annotations

from pathlib import Path


def test_run_audit_collector_prefers_repo_root_runtime() -> None:
    script = Path("tenant-bootstrap/scripts/run-audit-collector.sh").read_text(encoding="utf-8")
    repo_root_index = script.index('if [[ -f "${REPO_ROOT}/src/azure_tenant_audit/cli.py"')
    bootstrap_index = script.index('elif [[ -f "${TENANT_BOOTSTRAP_ROOT}/azure_tenant_audit/cli.py"')
    assert repo_root_index < bootstrap_index
