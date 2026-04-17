from __future__ import annotations

import os
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


def test_tenant_audit_login_uses_saved_local_m365_app_id(tmp_path: Path) -> None:
    auth_env = tmp_path / "m365-auth.env"
    auth_env.write_text("M365_CLI_APP_ID=test-app-id\n", encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    az_log = tmp_path / "az.log"
    m365_log = tmp_path / "m365.log"

    _write_executable(
        fake_bin / "az",
        f"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> {az_log!s}
exit 0
""",
    )
    _write_executable(
        fake_bin / "m365",
        f"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> {m365_log!s}
exit 0
""",
    )

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["AUDITEX_LOCAL_AUTH_ENV"] = str(auth_env)

    result = subprocess.run(
        ["bash", "scripts/tenant-audit-login", "bolyki.eu", "--m365"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    m365_args = m365_log.read_text(encoding="utf-8")
    assert "login --authType browser --tenant bolyki.eu --output text --appId test-app-id" in m365_args


def test_tenant_audit_full_sources_local_auth_helper() -> None:
    script = (REPO_ROOT / "scripts/tenant-audit-full").read_text(encoding="utf-8")
    assert 'source "${CURRENT_DIR}/load-local-auth.sh"' in script
