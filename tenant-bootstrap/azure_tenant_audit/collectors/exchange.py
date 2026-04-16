from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import time
from typing import Any, Callable, Optional

from .base import Collector, CollectorResult
from ..graph import GraphError


class ExchangeCollector(Collector):
    name = "exchange"
    description = "Exchange checks via optional command execution."
    required_permissions = ["Exchange.ManageAsApp"]
    command_collectors = [
        {
            "name": "exchangeConnectivityCheck",
            "commands": [
                "m365 status --output json",
                "m365 tenant info get --output json",
                "m365 tenant status",
            ],
        },
        {
            "name": "mailboxCount",
            "commands": [
                "m365 outlook report mailboxusagemailboxcount --period D30 --output json",
                "m365 outlook roomlist list --output json",
                "m365 exo mailbox list --output json",
            ],
        },
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get(
            "audit_logger"
        )
        payload: dict[str, Any] = {}
        total = 0
        coverage: list[dict[str, Any]] = []
        graph_client = context.get("client")
        top = context.get("top", 500)

        for command in self.command_collectors:
            start = time.perf_counter()
            command_variants = command.get("commands")
            if not isinstance(command_variants, list):
                command_variants = [str(command.get("command", ""))]

            response = self._run_command_variants(command_variants, command["name"], log_event)
            if response.get("error") and command["name"] == "mailboxCount":
                graph_response = self._run_mailbox_count_graph_fallback(graph_client, top=top)
                if graph_response is not None:
                    graph_response["command_variants"] = command_variants
                    graph_response["operation"] = command["name"]
                    response = graph_response
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            payload[command["name"]] = response

            value = response.get("value")
            item_count = len(value) if isinstance(value, list) else 0
            if isinstance(value, list):
                total += len(value)

            status = "failed" if response.get("error") else "ok"
            error_class = response.get("error_class") or ("command_error" if response.get("error") else None)
            message = response.get("error")
            coverage.append(
                {
                    "collector": self.name,
                    "type": "command",
                    "name": command["name"],
                    "command": response.get("command", ""),
                    "command_variants": response.get("command_variants"),
                    "status": status,
                    "item_count": item_count,
                    "duration_ms": duration_ms,
                    "error_class": error_class,
                    "error": message,
                }
            )

        status = "ok" if all(not entry.get("error") for entry in payload.values()) else "partial"
        message = "Exchange checks may require command tool availability."
        return CollectorResult(
            name=self.name,
            status=status,
            payload=payload,
            item_count=total,
            message=message,
            coverage=coverage,
        )

    def _run_command_variants(
        self,
        commands: list[str],
        operation: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        last_response: dict[str, Any] = {}

        for command in commands:
            response = self._run_command(command, log_event)
            response["command_variants"] = commands
            response["operation"] = operation

            if response.get("error") is None:
                return response

            last_response = response

        if not last_response:
            return {
                "error": "command_all_variants_failed",
                "error_class": "command_error",
                "operation": operation,
                "command_variants": commands,
            }

        return last_response

    @staticmethod
    def _looks_like_not_found(text: str) -> bool:
        lowered = text.lower()
        return (
            "command '" in lowered and " was not found." in lowered
            or "was not found" in lowered
            or "unknown command" in lowered
            or "command not found" in lowered
        )

    @staticmethod
    def _looks_like_auth_required(text: str) -> bool:
        lowered = text.lower()
        return (
            "log in to microsoft 365 first" in lowered
            or "logged out" in lowered
            or "please sign in" in lowered
        )

    @staticmethod
    def _looks_like_json(text: str) -> bool:
        return text.lstrip().startswith("{") or text.lstrip().startswith("[")

    @staticmethod
    def _looks_like_help_output(text: str) -> bool:
        lowered = text.lower()
        return lowered.startswith("cli for microsoft 365 v") or "commands:" in lowered

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

    def _run_command(
        self,
        command: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        cmd_parts = shlex.split(command)
        exe = shutil.which(cmd_parts[0]) if cmd_parts else None
        if exe is None:
            if log_event:
                log_event(
                    "command.failed",
                    "Command executable not found",
                    {
                        "command": cmd_parts[0] if cmd_parts else command,
                    },
                )
            return {
                "error": f"command_not_found:{cmd_parts[0] if cmd_parts else command}",
                "error_class": "command_not_found",
                "command": command,
            }

        try:
            if log_event:
                log_event("command.started", "Exchange command started", {"command": command, "executable": exe})

            start = time.time()
            result = subprocess.run(
                cmd_parts,
                text=True,
                capture_output=True,
                shell=False,
                timeout=120,
            )
            duration_ms = round((time.time() - start) * 1000, 2)
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            status = "ok" if result.returncode == 0 else "error"
            if log_event:
                log_event(
                    "command.completed",
                    "Exchange command completed",
                    {
                        "command": command,
                        "return_code": result.returncode,
                        "duration_ms": duration_ms,
                        "status": status,
                        "stdout_bytes": len(stdout),
                        "stderr_bytes": len(stderr),
                        "stdout_sample": stdout[:500],
                    },
                )

            combined = f"{stdout}\n{stderr}".lower()
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
                    "command": command,
                    "error": "command_output_empty",
                    "error_class": "command_output_empty",
                    "stdout": stdout,
                    "stderr": stderr,
                }

            if self._looks_like_help_output(stdout):
                return {
                    "command": command,
                    "error": "command_output_invalid_help",
                    "error_class": "command_parse_error",
                    "stdout": stdout,
                    "stderr": stderr,
                }

            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                return {
                    "command": command,
                    "error": "command_output_parse_error",
                    "error_class": "command_parse_error",
                    "stdout": stdout,
                    "stderr": stderr,
                }

            response = self._normalize_payload(parsed)
            response["command"] = command
            return response

        except subprocess.CalledProcessError as exc:  # noqa: BLE001
            if log_event:
                log_event(
                    "command.failed",
                    "Exchange command failed",
                    {
                        "command": command,
                        "return_code": exc.returncode,
                        "error": str(exc),
                    },
                )
            return {
                "error": f"command_failed:{exc.returncode}",
                "error_class": "command_error",
                "command": command,
                "output": str(exc.output),
            }
        except Exception as exc:  # noqa: BLE001
            if log_event:
                log_event(
                    "command.failed",
                    "Exchange command exception",
                    {"command": command, "error": str(exc)},
                )
            return {"error": str(exc), "error_class": "command_exception", "command": command}

    def _run_mailbox_count_graph_fallback(
        self,
        graph_client: Any,
        top: int | str,
    ) -> dict[str, Any] | None:
        if graph_client is None or not hasattr(graph_client, "get_all"):
            return None

        try:
            users = graph_client.get_all(
                "/users",
                params={
                    "$select": "id,displayName,userPrincipalName,mail",
                    "$top": str(top),
                },
            )
            mail_enabled_users = [
                user for user in users
                if isinstance(user, dict) and user.get("mail")
            ]
            return {
                "command": "graph /users local-mail-filter",
                "value": mail_enabled_users,
                "error_class": None,
            }
        except GraphError as exc:
            return {
                "command": "graph /users local-mail-filter",
                "error": str(exc),
                "error_class": "insufficient_permissions",
            }
