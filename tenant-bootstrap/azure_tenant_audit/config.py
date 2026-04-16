from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


@dataclass
class AuthConfig:
    tenant_id: str
    client_id: str | None
    auth_mode: str = "app"
    client_secret: Optional[str] = None
    access_token: Optional[str] = None
    authority: str = "https://login.microsoftonline.com/"
    graph_scope: str = "https://graph.microsoft.com/.default"
    interactive_scopes: Optional[list[str]] = None
    timeout_seconds: int = 60


@dataclass
class RunConfig:
    tenant_name: str
    output_dir: Path
    collectors: Optional[list[str]] = None
    excluded_collectors: Optional[list[str]] = None
    include_exchange: bool = False
    offline: bool = False
    sample_path: Optional[Path] = None
    run_name: Optional[str] = None
    top_items: int = 500

    def selected_collectors(self, available: Iterable[str]) -> list[str]:
        requested = set(self.collectors or [])
        excluded = set(self.excluded_collectors or [])
        explicit_request = self.collectors is not None

        ordered = []
        for name in available:
            if name in excluded:
                continue
            if explicit_request and name not in requested:
                continue
            if name == "exchange" and not self.include_exchange:
                continue
            ordered.append(name)
        return ordered


@dataclass
class CollectorDefinition:
    collector_id: str
    description: str
    enabled: bool
    required_permissions: list[str]
    query_plan: list[str]
    command_collectors: Optional[list[dict]] = None


@dataclass
class CollectorConfig:
    collectors: dict[str, CollectorDefinition]
    default_order: list[str]

    @classmethod
    def from_path(cls, path: Path) -> "CollectorConfig":
        payload = json.loads(path.read_text(encoding="utf-8"))
        collectors = {
            key: CollectorDefinition(
                collector_id=key,
                description=value.get("description", ""),
                enabled=bool(value.get("enabled", False)),
                required_permissions=value.get("required_permissions", []),
                query_plan=value.get("query_plan", []),
                command_collectors=value.get("command_collectors"),
            )
            for key, value in payload.get("collectors", {}).items()
        }
        return cls(collectors=collectors, default_order=payload.get("default_order", list(collectors.keys())))
