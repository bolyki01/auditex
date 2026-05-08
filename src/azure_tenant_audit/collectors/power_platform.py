"""Collector for Microsoft Power Platform admin posture.

Capability-gated by design: if the tenant has no Power Platform admin token
configured, the collector emits structured `service_not_available` diagnostics
rather than failing the whole run. With a token, it enumerates environments,
DLP policies, and tenant-level Power Platform settings.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

from ..power_platform import PowerPlatformClient, PowerPlatformError
from .base import Collector, CollectorResult


class PowerPlatformCollector(Collector):
    name = "power_platform"
    description = (
        "Power Platform admin posture: environments, DLP policies, and tenant settings. "
        "Capability-gated; if no Power Platform admin token is available the collector "
        "records a structured diagnostic instead of crashing the run."
    )
    required_permissions: list[str] = []

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("power_platform_client")
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get("audit_logger")
        coverage: list[dict[str, Any]] = []
        payload: dict[str, Any] = {
            "environments": {"value": []},
            "dlpPolicies": {"value": []},
            "tenantSettings": {"value": []},
        }

        if client is None:
            for endpoint_name, endpoint in (
                ("environments", "/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments"),
                ("dlpPolicies", "/providers/PowerPlatform.Governance/v2/policies"),
                ("tenantSettings", "/providers/Microsoft.BusinessAppPlatform/listTenantSettings"),
            ):
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "bap",
                        "name": endpoint_name,
                        "endpoint": endpoint,
                        "status": "skipped",
                        "item_count": 0,
                        "duration_ms": 0.0,
                        "error_class": "service_not_available",
                        "error": "no Power Platform admin token configured",
                    }
                )
            return CollectorResult(
                name=self.name,
                status="partial",
                payload=payload,
                item_count=0,
                message="Power Platform collection skipped: no admin token",
                coverage=coverage,
            )

        environments = self._fetch_environments(client, coverage, log_event)
        payload["environments"] = {"value": environments}

        dlp_policies = self._fetch_dlp_policies(client, coverage, log_event)
        payload["dlpPolicies"] = {"value": dlp_policies}

        settings = self._fetch_tenant_settings(client, coverage, log_event)
        if settings:
            payload["tenantSettings"] = {"value": [settings]}

        partial = any(row.get("status") not in {"ok"} for row in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=len(environments) + len(dlp_policies),
            message="Power Platform collection partially completed" if partial else "",
            coverage=coverage,
        )

    def _fetch_environments(
        self,
        client: PowerPlatformClient,
        coverage: list[dict[str, Any]],
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]],
    ) -> list[dict[str, Any]]:
        path = "/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments"
        raw, status = self._safe_get(client, path)
        rows: list[dict[str, Any]] = []
        if isinstance(raw, dict):
            for env in raw.get("value", []) or []:
                if not isinstance(env, dict):
                    continue
                properties = env.get("properties") or {}
                rows.append(
                    {
                        "id": env.get("id") or env.get("name"),
                        "name": env.get("name"),
                        "display_name": properties.get("displayName"),
                        "environment_sku": properties.get("environmentSku"),
                        "is_default": bool(properties.get("isDefault")),
                        "created_time": properties.get("createdTime"),
                        "linked_environment_metadata": properties.get("linkedEnvironmentMetadata"),
                    }
                )
        coverage.append(self._coverage_row("environments", path, status, len(rows)))
        if log_event:
            self._log(log_event, "environments", status, len(rows))
        return rows

    def _fetch_dlp_policies(
        self,
        client: PowerPlatformClient,
        coverage: list[dict[str, Any]],
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]],
    ) -> list[dict[str, Any]]:
        path = "/providers/PowerPlatform.Governance/v2/policies"
        raw, status = self._safe_get(client, path)
        rows: list[dict[str, Any]] = []
        if isinstance(raw, dict):
            for policy in raw.get("value", []) or []:
                if not isinstance(policy, dict):
                    continue
                business = 0
                non_business = 0
                blocked = 0
                for group in policy.get("connectorGroups", []) or []:
                    if not isinstance(group, dict):
                        continue
                    classification = str(group.get("classification") or "").lower()
                    connector_count = len(group.get("connectors") or [])
                    if classification == "business":
                        business += connector_count
                    elif classification == "nonbusiness":
                        non_business += connector_count
                    elif classification == "blocked":
                        blocked += connector_count
                rows.append(
                    {
                        "id": policy.get("name") or policy.get("id"),
                        "display_name": policy.get("displayName"),
                        "environment_type": policy.get("environmentType"),
                        "business_connector_count": business,
                        "non_business_connector_count": non_business,
                        "blocked_connector_count": blocked,
                    }
                )
        coverage.append(self._coverage_row("dlpPolicies", path, status, len(rows)))
        if log_event:
            self._log(log_event, "dlpPolicies", status, len(rows))
        return rows

    def _fetch_tenant_settings(
        self,
        client: PowerPlatformClient,
        coverage: list[dict[str, Any]],
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]],
    ) -> dict[str, Any] | None:
        path = "/providers/Microsoft.BusinessAppPlatform/listTenantSettings"
        raw, status = self._safe_get(client, path)
        coverage.append(self._coverage_row("tenantSettings", path, status, 1 if raw else 0))
        if log_event:
            self._log(log_event, "tenantSettings", status, 1 if raw else 0)
        if not isinstance(raw, dict):
            return None
        return {
            "is_power_apps_enabled": raw.get("isPowerAppsEnabled"),
            "is_power_automate_enabled": raw.get("isPowerAutomateEnabled"),
            "is_dataverse_enabled": raw.get("isDataverseEnabled"),
            "raw": raw,
        }

    @staticmethod
    def _safe_get(client: PowerPlatformClient, path: str) -> tuple[Any, dict[str, Any]]:
        start = time.perf_counter()
        try:
            raw = client.get(path)
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            return raw, {"status": "ok", "duration_ms": duration_ms, "error_class": None, "error": None}
        except PowerPlatformError as exc:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            error_class = "insufficient_permissions"
            if exc.status in (404, 410):
                error_class = "service_not_available"
            elif exc.status is None:
                error_class = "client_error"
            return None, {
                "status": "failed",
                "duration_ms": duration_ms,
                "error_class": error_class,
                "error": str(exc),
            }
        except Exception as exc:  # noqa: BLE001
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            return None, {
                "status": "failed",
                "duration_ms": duration_ms,
                "error_class": "client_error",
                "error": str(exc),
            }

    def _coverage_row(self, name: str, endpoint: str, status: dict[str, Any], item_count: int) -> dict[str, Any]:
        return {
            "collector": self.name,
            "type": "bap",
            "name": name,
            "endpoint": endpoint,
            "status": status["status"],
            "item_count": item_count,
            "duration_ms": status["duration_ms"],
            "error_class": status["error_class"],
            "error": status["error"],
        }

    def _log(self, log_event: Callable[[str, str, Optional[dict[str, Any]]], None], name: str, status: dict[str, Any], item_count: int) -> None:
        log_event(
            "collector.endpoint.finished",
            "Collector endpoint request completed",
            {
                "collector": self.name,
                "endpoint_name": name,
                "status": status["status"],
                "item_count": item_count,
                "duration_ms": status["duration_ms"],
                "error_class": status["error_class"],
            },
        )
