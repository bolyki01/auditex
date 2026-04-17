from __future__ import annotations

from azure_tenant_audit.adapters import get_adapter
from azure_tenant_audit.adapters.m365_cli import M365CLIAdapter
from azure_tenant_audit.adapters.m365dsc import M365DSCAdapter
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter


def test_adapter_registry_exposes_m365_cli() -> None:
    adapter = get_adapter("m365_cli")
    assert isinstance(adapter, M365CLIAdapter)
    assert adapter.name == "m365_cli"
    assert adapter.auth_requirements


def test_adapter_registry_exposes_powershell_graph_and_m365dsc() -> None:
    graph_adapter = get_adapter("powershell_graph")
    dsc_adapter = get_adapter("m365dsc")
    assert isinstance(graph_adapter, PowerShellGraphAdapter)
    assert isinstance(dsc_adapter, M365DSCAdapter)
    assert graph_adapter.auth_requirements
    assert dsc_adapter.auth_requirements


def test_powershell_graph_adapter_marks_missing_tool_dependency(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda *_, **__: None)

    adapter = PowerShellGraphAdapter()
    result = adapter.run("Get-Date")
    assert result["error_class"] == "command_not_found"


def test_m365dsc_adapter_executes_via_powershell(monkeypatch) -> None:
    payload = {"value": [{"name": "ok"}]}

    class _FakePowerShell:
        def run(self, command, log_event=None):  # noqa: ARG002
            assert "Invoke-Expression" in command
            return {"value": payload["value"]}

    monkeypatch.setattr("azure_tenant_audit.adapters.m365dsc.shutil.which", lambda *_: True)
    monkeypatch.setattr("azure_tenant_audit.adapters.m365dsc.PowerShellGraphAdapter", lambda: _FakePowerShell())

    adapter = M365DSCAdapter()
    result = adapter.run("Get-M365DSCResource")
    assert result["source"] == "m365dsc"
    assert result["value"] == payload["value"]
