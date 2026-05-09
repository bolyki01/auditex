"""Collector for DNS / email-auth posture (SPF, DKIM, DMARC, MTA-STS, BIMI)."""
from __future__ import annotations

import time
from typing import Any, Callable, Iterable, Optional

from ..dns_lookup import (
    DEFAULT_DOH_ENDPOINT,
    DohClient,
    DohError,
    DnsResolver,
    collect_domain_posture,
)
from ..graph import GraphClient, GraphError
from .base import Collector, CollectorResult, _classify_graph_error


DEFAULT_DKIM_SELECTORS = ("selector1", "selector2")
# Probed only when DEFAULT_DKIM_SELECTORS all miss. Covers common non-M365 origins
# (Google Workspace ``google``; SendGrid/Mailchimp/MailerLite ``s1``/``s2``;
# manual rotations ``k1``; legacy ``default``/``mail``).
FALLBACK_DKIM_SELECTORS = ("s1", "s2", "google", "default", "k1", "mail")


class DnsPostureCollector(Collector):
    name = "dns_posture"
    description = (
        "DNS / email-authentication posture (SPF, DKIM, DMARC, MTA-STS, BIMI) for verified tenant domains."
    )
    required_permissions = ["Directory.Read.All"]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient | None = context.get("client")
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get("audit_logger")
        resolver: DnsResolver = context.get("dns_resolver") or DohClient(
            endpoint=context.get("doh_endpoint", DEFAULT_DOH_ENDPOINT)
        )
        dkim_selectors: Iterable[str] = context.get("dkim_selectors", DEFAULT_DKIM_SELECTORS)
        dkim_fallback_selectors: Iterable[str] = context.get(
            "dkim_fallback_selectors", FALLBACK_DKIM_SELECTORS
        )

        coverage: list[dict[str, Any]] = []
        payload: dict[str, Any] = {}
        domains_payload: list[dict[str, Any]] = []
        domains_status = "ok"
        domains_error_class: str | None = None
        domains_error: str | None = None

        start = time.perf_counter()
        try:
            domains_payload = list(self._fetch_domains(client))
        except Exception as exc:  # noqa: BLE001
            domains_status = "failed"
            domains_error_class, domains_error = _classify_graph_error(exc)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        coverage.append(
            {
                "collector": self.name,
                "type": "graph",
                "name": "domains",
                "endpoint": "/domains",
                "status": domains_status,
                "item_count": len(domains_payload),
                "duration_ms": duration_ms,
                "error_class": domains_error_class,
                "error": domains_error,
            }
        )
        if log_event:
            log_event(
                "collector.endpoint.finished",
                "Collector endpoint request completed",
                {
                    "collector": self.name,
                    "endpoint_name": "domains",
                    "status": domains_status,
                    "item_count": len(domains_payload),
                    "duration_ms": duration_ms,
                    "error_class": domains_error_class,
                },
            )

        verified_domains = [
            entry for entry in domains_payload if isinstance(entry, dict) and entry.get("isVerified")
        ]

        assessments: list[dict[str, Any]] = []
        for entry in verified_domains:
            domain_name = str(entry.get("id") or "").strip()
            if not domain_name:
                continue
            domain_start = time.perf_counter()
            try:
                posture = collect_domain_posture(
                    domain_name,
                    resolver,
                    dkim_selectors=dkim_selectors,
                    dkim_fallback_selectors=dkim_fallback_selectors,
                )
                status = "ok"
                error_class: str | None = None
                error: str | None = None
            except DohError as exc:
                attempted_selectors = list(dkim_selectors) + [
                    s for s in dkim_fallback_selectors if s not in dkim_selectors
                ]
                posture = {
                    "domain": domain_name,
                    "managed_by_microsoft": domain_name.lower().endswith(".onmicrosoft.com"),
                    "resolver_error": str(exc),
                    "spf": {"present": False},
                    "dmarc": {"present": False},
                    "dkim": {"selectors_present": [], "selectors_missing": attempted_selectors},
                    "mta_sts": {"dns_present": False},
                    "bimi": {"present": False},
                }
                status = "failed"
                error_class = "dns_resolver_error"
                error = str(exc)
            posture.setdefault("isDefault", entry.get("isDefault"))
            posture.setdefault("authentication_type", entry.get("authenticationType"))
            assessments.append(posture)
            domain_duration_ms = round((time.perf_counter() - domain_start) * 1000, 2)
            coverage.append(
                {
                    "collector": self.name,
                    "type": "dns",
                    "name": f"posture:{domain_name}",
                    "endpoint": f"doh://{domain_name}",
                    "status": status,
                    "item_count": 1,
                    "duration_ms": domain_duration_ms,
                    "error_class": error_class,
                    "error": error,
                }
            )

        payload["domains"] = {"value": domains_payload}
        payload["domainPosture"] = {"value": assessments}

        partial = any(row.get("status") != "ok" for row in coverage)
        message = "DNS posture collection partially completed" if partial else ""
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=sum(int(row.get("item_count") or 0) for row in coverage),
            message=message,
            coverage=coverage,
        )

    @staticmethod
    def _fetch_domains(client: GraphClient | None) -> list[dict[str, Any]]:
        if client is None:
            raise GraphError("graph client unavailable", request="/domains")
        params = {"$select": "id,authenticationType,isDefault,isVerified,isRoot"}
        if hasattr(client, "get_all"):
            payload = client.get_all("/domains", params=params)
            if isinstance(payload, list):
                return [item for item in payload if isinstance(item, dict)]
            if isinstance(payload, dict):
                values = payload.get("value")
                if isinstance(values, list):
                    return [item for item in values if isinstance(item, dict)]
        if hasattr(client, "get_json"):
            payload = client.get_json("/domains", params=params)
            if isinstance(payload, dict):
                values = payload.get("value")
                if isinstance(values, list):
                    return [item for item in values if isinstance(item, dict)]
        raise GraphError("graph client missing get_all/get_json", request="/domains")
