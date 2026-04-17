from __future__ import annotations

import json
import time
from typing import Any, Callable, Optional

from ..adapters import get_adapter
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

    def _run_command(
        self,
        command: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        adapter = get_adapter("m365_cli")
        return adapter.run(command, log_event=log_event)

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
                    "$select": "id,displayName,userPrincipalName,mail,mailboxSettings",
                    "$filter": "mail ne null",
                    "$top": str(top),
                },
            )
            return {
                "command": "graph /users?filter=mail ne null",
                "value": users,
                "error_class": None,
            }
        except GraphError as exc:
            return {
                "command": "graph /users?filter=mail ne null",
                "error": str(exc),
                "error_class": "insufficient_permissions",
            }
