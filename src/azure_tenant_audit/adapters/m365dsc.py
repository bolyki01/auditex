from __future__ import annotations

import shutil
from typing import Any, Callable, Optional

from .base import Adapter, AdapterMetadata


class M365DSCAdapter(Adapter):
    metadata = AdapterMetadata(
        name="m365dsc",
        auth_requirements=("app_or_delegated",),
        tool_dependencies=("pwsh",),
    )

    def dependency_check(self) -> bool:
        return shutil.which("pwsh") is not None

    def run(self, command: str, log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None) -> dict[str, Any]:  # noqa: ARG002
        return {"error": "adapter_not_implemented", "error_class": "adapter_not_implemented", "command": command}
