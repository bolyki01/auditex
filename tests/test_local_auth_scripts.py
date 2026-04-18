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
    pwsh_log = tmp_path / "pwsh.log"

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
if [[ "${{1:-}}" == "status" ]]; then
  printf '{{"connectionName":"tenant-user","connectedAs":"user","appTenant":"bolyki.eu"}}\n'
fi
exit 0
""",
    )
    _write_executable(
        fake_bin / "pwsh",
        f"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> {pwsh_log!s}
if [[ "$*" == *"Get-Module -ListAvailable ExchangeOnlineManagement"* ]]; then
  printf '{{"Name":"ExchangeOnlineManagement","Version":"3.7.0"}}\n'
fi
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
    az_args = az_log.read_text(encoding="utf-8")
    assert "login --tenant bolyki.eu --allow-no-subscriptions" in az_args
    m365_args = m365_log.read_text(encoding="utf-8")
    assert "login --authType browser --tenant bolyki.eu --output text --appId test-app-id" in m365_args
    pwsh_args = pwsh_log.read_text(encoding="utf-8")
    assert "Get-Module -ListAvailable ExchangeOnlineManagement" in pwsh_args


def test_tenant_audit_full_sources_local_auth_helper() -> None:
    script = (REPO_ROOT / "scripts/tenant-audit-full").read_text(encoding="utf-8")
    assert 'source "${CURRENT_DIR}/load-local-auth.sh"' in script


def test_tenant_audit_full_uses_allow_no_subscriptions(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    az_log = tmp_path / "az.log"
    py_log = tmp_path / "py.log"

    _write_executable(
        fake_bin / "az",
        f"""#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "account" && "$2" == "show" ]]; then
  exit 1
fi
printf '%s\n' "$*" >> {az_log!s}
exit 0
""",
    )
    _write_executable(
        fake_bin / "python3",
        f"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> {py_log!s}
exit 0
""",
    )

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"

    result = subprocess.run(
        ["bash", "scripts/tenant-audit-full", "--tenant-id", "bolyki.eu", "--tenant-name", "BOLYKI"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    az_args = az_log.read_text(encoding="utf-8")
    assert "login --tenant bolyki.eu --allow-no-subscriptions" in az_args
    py_args = py_log.read_text(encoding="utf-8")
    assert "azure_tenant_audit" in py_args
