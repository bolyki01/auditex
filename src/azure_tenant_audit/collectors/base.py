from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..graph import GraphClient, GraphError


def _classify_graph_error(exc: Exception) -> tuple[str, str]:
    message = str(exc)
    if isinstance(exc, GraphError):
        if exc.error_code == "PermissionStop":
            return "permission_stop", message
        status = exc.status
        if status == 401:
            return "unauthenticated", message
        if status == 403:
            return "insufficient_permissions", message
        if status == 404:
            return "resource_not_found", message
        if status == 400:
            lower = message.lower()
            if "no reply address is registered" in lower:
                return "app_missing_reply_url", message
            if "minimum page size" in lower:
                return "query_page_minimum", message
            if "unsupported" in lower and "query" in lower:
                return "unsupported_query", message
            return "bad_request", message
        if status and status >= 500:
            return "graph_transient", message
        return f"graph_http_{status}", message
    if "No reply address is registered" in message:
        return "app_missing_reply_url", message
    return "client_error", message


def _normalize_top(
    params: dict[str, Any] | None,
    top: int | None,
    *,
    min_top: int | None = None,
) -> dict[str, Any]:
    query: dict[str, Any] = dict(params) if params else {}
    if top is None:
        return query
    normalized_top = top
    if min_top is not None:
        normalized_top = max(top, min_top)
    query_top = query.get("$top")
    if query_top is None:
        query["$top"] = str(normalized_top)
        return query
    try:
        int(query_top)
    except (TypeError, ValueError):
        query["$top"] = str(normalized_top)
    return query


def run_graph_endpoints(
    collector: str,
    client: GraphClient,
    endpoint_specs: dict[str, dict[str, Any]],
    top: int,
    *,
    page_size: int | None = None,
    chunk_writer: Optional[Callable[[str, str, int, list[dict[str, Any]], Optional[dict[str, Any]]], str | None]] = None,
    log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Execute a set of Graph endpoints for one collector.

    Returns both the raw payload per section and per-endpoint coverage entries.
    """
    payload: dict[str, Any] = {}
    coverage: list[dict[str, Any]] = []

    for key, spec in endpoint_specs.items():
        endpoint = spec["endpoint"]
        page = spec.get("page", True)
        apply_top = spec.get("apply_top", True)
        effective_top = page_size if page_size is not None else top
        if not page or not apply_top:
            # Non-collection calls often do not accept $top.
            effective_top = None
        query = _normalize_top(spec.get("params"), effective_top, min_top=spec.get("min_top"))
        if log_event:
            log_event(
                "collector.endpoint.started",
                "Collector endpoint request started",
                {"collector": collector, "endpoint_name": key, "endpoint": endpoint, "top": query.get("$top")},
            )

        start = time.perf_counter()
        item_count = 0
        error_class: str | None = None
        error: str | None = None
        status = "ok"

        try:
            if page:
                if chunk_writer is not None and hasattr(client, "iter_pages"):
                    sample: list[dict[str, Any]] = []
                    chunk_files: list[str] = []
                    remaining = max(top, 0)
                    for page_number, page_payload in enumerate(client.iter_pages(endpoint, params=query), start=1):
                        values = page_payload.get("value", [])
                        if not isinstance(values, list):
                            raise GraphError(f"Non-list response from {endpoint}", request=endpoint)
                        if remaining <= 0:
                            break
                        limited_values = values[:remaining]
                        if limited_values:
                            chunk_path = chunk_writer(
                                collector,
                                key,
                                page_number,
                                limited_values,
                                {"endpoint": endpoint, "page_number": page_number},
                            )
                            if chunk_path:
                                chunk_files.append(chunk_path)
                        item_count += len(limited_values)
                        remaining -= len(limited_values)
                        if len(sample) < 20:
                            sample.extend(limited_values[: 20 - len(sample)])
                        if remaining <= 0:
                            break
                    payload[key] = {
                        "value": sample,
                        "item_count": item_count,
                        "sample_truncated": item_count > len(sample),
                    }
                    if chunk_files:
                        payload[key]["chunk_files"] = chunk_files
                else:
                    if hasattr(client, "iter_items"):
                        rows = list(client.iter_items(endpoint, params=query, result_limit=top))
                    else:
                        rows = client.get_all(endpoint, params=query)
                    if isinstance(rows, list):
                        item_count = len(rows)
                        payload[key] = {"value": rows}
                    elif isinstance(rows, dict):
                        payload[key] = rows
                        item_count = len(rows.get("value", [])) if isinstance(rows.get("value"), list) else 0
                    else:
                        payload[key] = {"value": rows}
            else:
                page_result = client.get_json(endpoint, params=query)
                values = page_result.get("value") if isinstance(page_result, dict) else page_result
                payload[key] = page_result if isinstance(page_result, dict) else {"value": page_result}
                if isinstance(values, list):
                    item_count = len(values)
                    payload[key] = {"value": values}
            status = "ok"
        except Exception as exc:  # noqa: BLE001
            status = "failed"
            error_class, error = _classify_graph_error(exc)
            payload[key] = {"error": error, "error_class": error_class}
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        if log_event:
            log_event(
                "collector.endpoint.finished",
                "Collector endpoint request completed",
                {
                    "collector": collector,
                    "endpoint_name": key,
                    "status": status,
                    "item_count": item_count,
                    "duration_ms": duration_ms,
                    "error_class": error_class,
                },
            )

        coverage.append(
            {
                "collector": collector,
                "type": "graph",
                "name": key,
                "endpoint": endpoint,
                    "status": status,
                    "top": query.get("$top"),
                    "result_limit": top if page else None,
                    "page": page,
                    "item_count": item_count,
                    "duration_ms": duration_ms,
                "error_class": error_class,
                "error": error,
            }
        )

    return payload, coverage

@dataclass
class CollectorResult:
    name: str
    status: str
    payload: dict[str, Any]
    item_count: int
    message: str = ""
    error: Optional[str] = None
    coverage: list[dict[str, Any]] | None = None


class Collector:
    name: str = "base"
    description: str = ""
    required_permissions: list[str] = []
    command_collectors: list[dict[str, str]] | None = None

    def run(self, context: Any) -> CollectorResult:
        raise NotImplementedError

    @staticmethod
    def _safe_count(payload: dict[str, Any]) -> int:
        value = payload.get("value")
        if isinstance(value, list):
            return len(value)
        if isinstance(payload, dict):
            return len(payload)
        return 0
