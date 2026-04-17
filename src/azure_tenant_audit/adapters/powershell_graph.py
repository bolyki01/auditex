from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import time
from typing import Any, Callable, Optional

from .base import Adapter, AdapterMetadata


class PowerShellGraphAdapter(Adapter):
    metadata = AdapterMetadata(
        name="powershell_graph",
        auth_requirements=("app_or_delegated",),
        tool_dependencies=("pwsh",),
    )

    def dependency_check(self) -> bool:
        return shutil.which("pwsh") is not None

    @staticmethod
    def _looks_like_not_found(text: str) -> bool:
        lowered = text.lower()
        return (
            "not recognized" in lowered
            or "command not found" in lowered
            or ("the term" in lowered and "is not recognized" in lowered)
        )

    @staticmethod
    def _looks_like_auth_required(text: str) -> bool:
        lowered = text.lower()
        return (
            "not authorized" in lowered
            or "access denied" in lowered
            or ("sign in" in lowered and "denied" in lowered)
            or "connect-exchangeonline" in lowered
        )

    @staticmethod
    def _normalize_payload(parsed: object) -> dict[str, Any]:
        if isinstance(parsed, dict):
            if "value" in parsed and isinstance(parsed["value"], list):
                return parsed
            return {"value": [parsed]}
        if isinstance(parsed, list):
            return {"value": parsed}
        if parsed is None:
            return {}
        return {"value": [parsed]}

    def run(
        self,
        command: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        exe = shutil.which("pwsh")
        if exe is None:
            if log_event:
                log_event("command.failed", "PowerShell executable not found", {"command": command})
            return {"error": "command_not_found:pwsh", "error_class": "command_not_found", "command": command}

        script = command.strip()
        if script.startswith("pwsh"):
            parts = shlex.split(script)
            script = " ".join(parts[1:]) if len(parts) > 1 else ""

        if not script:
            return {"error": "command_empty", "error_class": "command_parse_error", "command": command}

        prepared = f"{script} | ConvertTo-Json -Depth 20 -Compress"
        try:
            if log_event:
                log_event("command.started", "PowerShell command started", {"command": command, "executable": exe})

            start = time.time()
            result = subprocess.run(
                [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prepared],
                text=True,
                capture_output=True,
                timeout=120,
            )
            duration_ms = round((time.time() - start) * 1000, 2)
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            combined = f"{stdout}\n{stderr}".lower()

            if log_event:
                log_event(
                    "command.completed",
                    "PowerShell command completed",
                    {
                        "command": command,
                        "return_code": result.returncode,
                        "duration_ms": duration_ms,
                        "stdout_bytes": len(stdout),
                        "stderr_bytes": len(stderr),
                        "stdout_sample": stdout[:500],
                    },
                )

            if result.returncode != 0 or self._looks_like_not_found(combined) or self._looks_like_auth_required(combined):
                if self._looks_like_not_found(combined):
                    error_class = "command_not_found"
                elif self._looks_like_auth_required(combined):
                    error_class = "command_not_authenticated"
                else:
                    error_class = "command_error"
                return {
                    "error": f"command_failed:{result.returncode}",
                    "error_class": error_class,
                    "command": command,
                    "return_code": result.returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                }

            if not stdout.strip():
                return {
                    "error": "command_output_empty",
                    "error_class": "command_output_empty",
                    "command": command,
                    "stdout": stdout,
                    "stderr": stderr,
                }

            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                return {
                    "error": "command_output_parse_error",
                    "error_class": "command_parse_error",
                    "command": command,
                    "stdout": stdout,
                    "stderr": stderr,
                }

            response = self._normalize_payload(parsed)
            response["command"] = command
            return response
        except subprocess.TimeoutExpired:
            if log_event:
                log_event("command.failed", "PowerShell command timed out", {"command": command})
            return {"error": "command_timeout", "error_class": "command_timeout", "command": command}
        except subprocess.CalledProcessError as exc:  # noqa: BLE001
            if log_event:
                log_event("command.failed", "PowerShell command failed", {"command": command, "error": str(exc)})
            return {"error": f"command_failed:{exc.returncode}", "error_class": "command_error", "command": command}
        except Exception as exc:  # noqa: BLE001
            if log_event:
                log_event("command.failed", "PowerShell command exception", {"command": command, "error": str(exc)})
            return {"error": str(exc), "error_class": "command_exception", "command": command}
