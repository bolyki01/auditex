from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Iterator

from azure_tenant_audit.perf_runtime import EndpointAccumulator, PageWindow, json_size_bytes, write_metric_snapshot


class FakePagedGraphClient:
    def __init__(self, *, pages: int, rows_per_page: int) -> None:
        self.pages = pages
        self.rows_per_page = rows_per_page

    def iter_pages(self, endpoint: str, params: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        for page in range(1, self.pages + 1):
            yield {
                "value": [
                    {
                        "id": f"{endpoint.strip('/')}:{page}:{index}",
                        "displayName": f"Object {page}-{index}",
                        "synthetic": True,
                    }
                    for index in range(self.rows_per_page)
                ]
            }


def run_fake_paged_collection(*, pages: int, rows_per_page: int, limit: int, sample_limit: int) -> dict[str, Any]:
    client = FakePagedGraphClient(pages=pages, rows_per_page=rows_per_page)
    accumulator = EndpointAccumulator(sample_limit=sample_limit)
    window = PageWindow.from_limit(limit)
    started = time.perf_counter()
    chunk_count = 0
    for page_number, page in enumerate(client.iter_pages("/users"), start=1):
        rows = page.get("value", [])
        selected, window = window.take(rows)
        if not selected and window.exhausted:
            break
        chunk_count += 1
        accumulator.add_page(selected, chunk_file=f"chunks/users-{page_number:05d}.jsonl")
        if window.exhausted:
            break
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    payload = accumulator.payload()
    return {
        "pages_requested": pages,
        "rows_per_page": rows_per_page,
        "limit": limit,
        "elapsed_ms": elapsed_ms,
        "item_count": accumulator.item_count,
        "page_count": accumulator.page_count,
        "chunk_count": chunk_count,
        "sample_count": len(payload["value"]),
        "sample_truncated": payload["sample_truncated"],
        "payload_bytes": json_size_bytes(payload),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Synthetic Auditex paged Graph benchmark without tenant credentials.")
    parser.add_argument("--pages", type=int, default=100)
    parser.add_argument("--rows-per-page", type=int, default=1000)
    parser.add_argument("--limit", type=int, default=50000)
    parser.add_argument("--sample-limit", type=int, default=20)
    parser.add_argument("--output", default="benchmark-results/fake-graph.json")
    args = parser.parse_args()
    metrics = run_fake_paged_collection(
        pages=args.pages,
        rows_per_page=args.rows_per_page,
        limit=args.limit,
        sample_limit=args.sample_limit,
    )
    output_path = write_metric_snapshot(Path(args.output), metrics)
    print(json.dumps({"output": str(output_path), **metrics}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
