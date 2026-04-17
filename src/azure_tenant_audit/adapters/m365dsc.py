from __future__ import annotations

import shutil
from typing import Any, Callable, Optional

from .base import Adapter, AdapterMetadata
from .powershell_graph import PowerShellGraphAdapter


class M365DSCAdapter(Adapter):
    metadata = AdapterMetadata(
        name="m365dsc",
        auth_requirements=("app_or_delegated",),
        tool_dependencies=("pwsh",),
    )

    def dependency_check(self) -> bool:
        return shutil.which("pwsh") is not None

    @staticmethod
    def _looks_like_module_missing(text: str) -> bool:
        lowered = text.lower()
        return (
            "cannot find path" in lowered
            or "not recognized" in lowered
            or "import-module" in lowered and "microsoft365dsc" in lowered and "not" in lowered
        )

    def run(
        self,
        command: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        powershell = PowerShellGraphAdapter()
        script = command.replace("'", "''")
        module_guard = "if (-not (Get-Module -ListAvailable Microsoft365DSC)) { throw 'Microsoft365DSC module not installed' }"
        wrapped = f"{module_guard}; Invoke-Expression '{script}'"
        response = powershell.run(wrapped, log_event=log_event)
        if response.get("error") and response.get("error_class") == "command_not_found":
            return {
                "error": "module_not_found",
                "error_class": "module_not_found",
                "command": command,
                "command_variants": [command],
                "source": "m365dsc",
            }

        if response.get("error"):
            stderr = str(response.get("stderr") or response.get("error") or "")
            if self._looks_like_module_missing(stderr):
                response["error_class"] = "module_not_found"
                response["error"] = "module_not_found"
            response.setdefault("source", "m365dsc")
            response.setdefault("command", command)
            return response

        response.setdefault("command", command)
        response.setdefault("source", "m365dsc")
        return response
