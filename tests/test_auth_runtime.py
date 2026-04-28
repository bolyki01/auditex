from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from auditex.auth_runtime import AuthRuntimeAdapters, ProductAuthRuntime, ToolchainRuntime, ToolchainRuntimeAdapters


class _FakeAuthAdapters:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.local_path = Path("/tmp/fake-auth.env")

    def load_local_auth_env(self) -> Path:
        return self.local_path

    def masked_local_auth_values(self, path: Path) -> dict[str, Any]:
        return {"path": str(path), "present": False}

    def json_command(self, command: list[str]) -> dict[str, Any]:
        self.commands.append(command)
        return {"status": "supported", "payload": {"connectionName": "tenant-user", "connectedAs": "user"}}

    def exchange_module_status(self) -> dict[str, Any]:
        return {"status": "supported", "module_version": "3.7.0"}

    def list_adapter_capabilities(self) -> list[dict[str, Any]]:
        return [{"name": "m365_cli"}]


def test_auth_runtime_uses_adapter_for_shell_status_checks() -> None:
    fake = _FakeAuthAdapters()
    runtime = ProductAuthRuntime(
        AuthRuntimeAdapters(
            load_local_auth_env=fake.load_local_auth_env,
            masked_local_auth_values=fake.masked_local_auth_values,
            json_command=fake.json_command,
            exchange_module_status=fake.exchange_module_status,
            list_adapter_capabilities=fake.list_adapter_capabilities,
        )
    )

    status = runtime.get_auth_status(include_azure_cli=False, include_m365=True, include_exchange=False)

    assert fake.commands == [["m365", "status", "--output", "json"], ["m365", "connection", "list", "--output", "json"]]
    assert status["local_auth"]["path"] == "/tmp/fake-auth.env"
    assert status["azure_cli"]["status"] == "skipped"
    assert status["m365"]["active_connection"] == "tenant-user"
    assert status["exchange"]["status"] == "skipped"
    assert status["adapter_capabilities"] == [{"name": "m365_cli"}]


def test_auth_runtime_resolves_active_auth_context_from_fake_store() -> None:
    store = {
        "active_context": "customer-a",
        "contexts": {
            "customer-a": {
                "name": "customer-a",
                "auth_type": "imported_token",
                "tenant_id": "tenant-1",
                "token_preview": "token...",
                "token_claims": {"delegated_scopes": ["Directory.Read.All"], "expires_at_utc": "2030-01-01T00:00:00Z"},
            }
        },
    }
    runtime = ProductAuthRuntime(AuthRuntimeAdapters(load_auth_context_store=lambda: store))

    context = runtime.resolve_auth_context()
    listed = runtime.list_auth_contexts()

    assert context["name"] == "customer-a"
    assert listed["active_context"] == "customer-a"
    assert listed["contexts"][0]["active"] is True
    assert listed["contexts"][0]["tenant_id"] == "tenant-1"


class _FakeToolchainAdapters:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def which(self, command_name: str) -> str | None:
        return f"/fake/bin/{command_name}" if command_name in {"az", "bash"} else None

    def run_json_command(self, command: list[str]) -> dict[str, Any]:
        self.commands.append(command)
        if command[0].endswith("az"):
            return {"status": "supported", "stdout": json.dumps({"azure-cli": "2.72.0"}), "stderr": "", "returncode": 0}
        return {"status": "blocked", "stdout": "", "stderr": "nope", "returncode": 1}


def test_toolchain_runtime_checks_versions_through_fake_adapter(tmp_path: Path) -> None:
    select_python = tmp_path / "select-python.sh"
    select_python.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    fake = _FakeToolchainAdapters()
    runtime = ToolchainRuntime(
        ToolchainRuntimeAdapters(which=fake.which, run_json_command=fake.run_json_command),
        repo_root=tmp_path,
        select_python_script=select_python,
        venv_dir=tmp_path / ".venv",
    )

    az = runtime.tool_status("az", version_args=["version", "--output", "json"], version_parser=lambda output: json.loads(output)["azure-cli"])
    node = runtime.tool_status("node", version_args=["--version"])

    assert az["status"] == "supported"
    assert az["version"] == "2.72.0"
    assert node["status"] == "blocked"
    assert node["error"] == "command_not_found"
    assert fake.commands == [["/fake/bin/az", "version", "--output", "json"]]
