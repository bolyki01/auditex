from __future__ import annotations

from azure_tenant_audit.collectors.base import run_graph_endpoints


class _LargePagedClient:
    def iter_pages(self, endpoint, params=None):  # noqa: ANN001
        assert endpoint == "/users"
        assert params["$top"] == "100"
        for page_index in range(100):
            start = page_index * 100
            yield {
                "value": [
                    {"id": f"user-{start + offset}", "displayName": f"User {start + offset}"}
                    for offset in range(100)
                ]
            }


def test_run_graph_endpoints_streams_large_tenant_results_into_chunks() -> None:
    chunk_calls: list[tuple[int, int, dict[str, int]]] = []

    def chunk_writer(collector, name, page_number, records, metadata=None):  # noqa: ANN001
        chunk_calls.append((page_number, len(records), metadata or {}))
        return f"chunks/{collector}/{name}-{page_number:05d}.jsonl"

    payload, coverage = run_graph_endpoints(
        "identity",
        _LargePagedClient(),
        {"users": {"endpoint": "/users", "params": {}}},
        top=10_000,
        page_size=100,
        chunk_writer=chunk_writer,
    )

    assert coverage[0]["status"] == "ok"
    assert coverage[0]["item_count"] == 10_000
    assert payload["users"]["item_count"] == 10_000
    assert payload["users"]["sample_truncated"] is True
    assert len(payload["users"]["value"]) == 20
    assert len(payload["users"]["chunk_files"]) == 100
    assert len(chunk_calls) == 100
    assert all(record_count == 100 for _, record_count, _ in chunk_calls)
    assert chunk_calls[0][2]["page_number"] == 1
    assert chunk_calls[-1][2]["page_number"] == 100
