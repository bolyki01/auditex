from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default
    return payload if payload is not None else default


def _scalar_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value, sort_keys=True, default=str)


def _record_key(record: dict[str, Any], section_name: str, record_index: int) -> str:
    key = record.get("key")
    if key:
        return str(key)
    record_id = record.get("id")
    if record_id:
        return f"{section_name}:{record_id}"
    display_name = record.get("display_name") or record.get("name")
    if display_name:
        return f"{section_name}:{display_name}"
    return f"{section_name}:{record_index}"


def _iter_normalized_payloads(run_dir: Path) -> Iterable[tuple[str, Path, list[dict[str, Any]]]]:
    normalized_dir = run_dir / "normalized"
    if not normalized_dir.exists():
        return []

    payloads: list[tuple[str, Path, list[dict[str, Any]]]] = []
    for path in sorted(normalized_dir.glob("*.json")):
        payload = _load_json(path, default={})
        if not isinstance(payload, dict):
            continue
        section_name = str(payload.get("kind") or path.stem)
        records = payload.get("records", [])
        if not isinstance(records, list):
            records = []
        payloads.append((section_name, path, [item for item in records if isinstance(item, dict)]))
    return payloads


def build_run_evidence_index(run_dir: str | Path, db_path: str | Path | None = None) -> Path:
    run_path = Path(run_dir)
    target = Path(db_path) if db_path is not None else run_path / "index" / "evidence.sqlite"
    target.parent.mkdir(parents=True, exist_ok=True)

    manifest = _load_json(run_path / "run-manifest.json", default={})
    if not isinstance(manifest, dict):
        manifest = {}
    summary = _load_json(run_path / "summary.json", default={})
    if not isinstance(summary, dict):
        summary = {}

    conn = sqlite3.connect(target)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("DROP TABLE IF EXISTS run_meta")
        conn.execute("DROP TABLE IF EXISTS section_stats")
        conn.execute("DROP TABLE IF EXISTS normalized_records")
        conn.execute("CREATE TABLE run_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute(
            "CREATE TABLE section_stats (section_name TEXT PRIMARY KEY, item_count INTEGER NOT NULL, source_path TEXT NOT NULL)"
        )
        conn.execute(
            """
            CREATE TABLE normalized_records (
                run_id TEXT NOT NULL,
                tenant_name TEXT NOT NULL,
                section_name TEXT NOT NULL,
                record_index INTEGER NOT NULL,
                record_key TEXT NOT NULL,
                display_name TEXT NOT NULL,
                source_name TEXT NOT NULL,
                collector TEXT NOT NULL,
                severity TEXT NOT NULL,
                record_json TEXT NOT NULL,
                source_path TEXT NOT NULL,
                PRIMARY KEY (section_name, record_index)
            )
            """
        )

        meta_rows = {"run_dir": str(run_path)}
        meta_rows.update({str(key): _scalar_value(value) for key, value in manifest.items()})
        meta_rows["summary"] = _scalar_value(summary)
        conn.executemany("INSERT INTO run_meta (key, value) VALUES (?, ?)", sorted(meta_rows.items()))
        run_id = _scalar_value(manifest.get("run_id"))
        tenant_name = _scalar_value(manifest.get("tenant_name"))

        for section_name, path, records in _iter_normalized_payloads(run_path):
            conn.execute(
                "INSERT INTO section_stats (section_name, item_count, source_path) VALUES (?, ?, ?)",
                (section_name, len(records), str(path.relative_to(run_path))),
            )
            for index, record in enumerate(records):
                conn.execute(
                    """
                    INSERT INTO normalized_records (
                        run_id, tenant_name, section_name, record_index, record_key,
                        display_name, source_name, collector, severity, record_json, source_path
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        tenant_name,
                        section_name,
                        index,
                        _record_key(record, section_name, index),
                        _scalar_value(record.get("display_name") or record.get("name")),
                        _scalar_value(record.get("source_name")),
                        _scalar_value(record.get("collector")),
                        _scalar_value(record.get("severity")),
                        json.dumps(record, sort_keys=True, default=str),
                        str(path.relative_to(run_path)),
                    ),
                )

        conn.commit()
    finally:
        conn.close()

    return target


def load_run_index_summary(run_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    db_path = run_path / "index" / "evidence.sqlite"
    if not db_path.exists():
        return {}
    conn = sqlite3.connect(db_path)
    try:
        meta = dict(conn.execute("select key, value from run_meta").fetchall())
        section_stats = [
            {
                "name": row[0],
                "item_count": row[1],
                "source_path": row[2],
            }
            for row in conn.execute(
                "select section_name, item_count, source_path from section_stats order by section_name"
            ).fetchall()
        ]
        return {
            "run_id": meta.get("run_id"),
            "tenant_name": meta.get("tenant_name"),
            "tenant_id": meta.get("tenant_id"),
            "created_utc": meta.get("created_utc"),
            "overall_status": meta.get("overall_status"),
            "auditor_profile": meta.get("auditor_profile"),
            "section_stats": section_stats,
            "item_count": sum(row["item_count"] for row in section_stats),
        }
    finally:
        conn.close()
