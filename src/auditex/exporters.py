from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

from .reporting import render_report


BUILTIN_EXPORTERS = {
    "json": {"name": "json", "description": "Render report bundle as JSON", "formats": ["json"], "builtin": True},
    "md": {"name": "md", "description": "Render report bundle as Markdown", "formats": ["md"], "builtin": True},
    "csv": {"name": "csv", "description": "Render report bundle as CSV", "formats": ["csv"], "builtin": True},
    "html": {"name": "html", "description": "Render report bundle as HTML", "formats": ["html"], "builtin": True},
}


def _iter_external_exporters() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        discovered = entry_points(group="auditex.exporters")
    except TypeError:
        discovered = entry_points().get("auditex.exporters", [])  # type: ignore[assignment]
    for item in discovered:
        rows.append(
            {
                "name": item.name,
                "description": f"External exporter from {item.module}",
                "formats": [],
                "builtin": False,
            }
        )
    return rows


def list_exporters() -> list[dict[str, Any]]:
    rows = list(BUILTIN_EXPORTERS.values())
    rows.extend(_iter_external_exporters())
    return sorted(rows, key=lambda row: row["name"])


def run_exporter(
    *,
    name: str,
    run_dir: str,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    if name in BUILTIN_EXPORTERS:
        result = render_report(
            run_dir=run_dir,
            format_name=name,
            include_sections=include_sections,
            exclude_sections=exclude_sections,
            output_path=output_path,
        )
        return {"name": name, "artifacts": [{"path": result["output_path"], "format": name}]}

    try:
        discovered = entry_points(group="auditex.exporters")
    except TypeError:
        discovered = entry_points().get("auditex.exporters", [])  # type: ignore[assignment]
    for item in discovered:
        if item.name != name:
            continue
        plugin = item.load()
        if callable(plugin):
            payload = plugin(
                run_dir=run_dir,
                include_sections=include_sections,
                exclude_sections=exclude_sections,
                output_path=output_path,
            )
        elif hasattr(plugin, "run"):
            payload = plugin.run(
                run_dir=run_dir,
                include_sections=include_sections,
                exclude_sections=exclude_sections,
                output_path=output_path,
            )
        else:
            raise TypeError(f"Exporter '{name}' is not callable")
        if isinstance(payload, dict):
            return payload
        raise TypeError(f"Exporter '{name}' returned invalid payload")
    raise KeyError(f"Unknown exporter: {name}")
