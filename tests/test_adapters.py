from __future__ import annotations

from azure_tenant_audit.adapters import get_adapter
from azure_tenant_audit.adapters.m365_cli import M365CLIAdapter


def test_adapter_registry_exposes_m365_cli() -> None:
    adapter = get_adapter("m365_cli")
    assert isinstance(adapter, M365CLIAdapter)
    assert adapter.name == "m365_cli"
    assert adapter.auth_requirements
