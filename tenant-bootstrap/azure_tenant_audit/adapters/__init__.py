from __future__ import annotations

from .base import Adapter
from .m365_cli import M365CLIAdapter
from .m365dsc import M365DSCAdapter
from .powershell_graph import PowerShellGraphAdapter

ADAPTERS: dict[str, Adapter] = {
    "m365_cli": M365CLIAdapter(),
    "m365dsc": M365DSCAdapter(),
    "powershell_graph": PowerShellGraphAdapter(),
}


def get_adapter(name: str) -> Adapter:
    return ADAPTERS[name]
