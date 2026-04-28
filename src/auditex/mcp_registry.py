from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


Handler = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class McpToolEntry:
    name: str
    description: str
    read_only_hint: bool

    @property
    def annotations(self) -> dict[str, bool]:
        return {"readOnlyHint": self.read_only_hint}

    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "readOnlyHint": self.read_only_hint,
        }


TOOL_REGISTRY: tuple[McpToolEntry, ...] = (
    McpToolEntry(
        name="auditex_list_collectors",
        description="List collector IDs, required permissions, and query plans from the active definitions file.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_list_adapters",
        description="List configured adapters and their dependency requirements.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_list_response_actions",
        description="List guarded response actions exposed by the response plane.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_list_profiles",
        description="List built-in delegated and app-readonly audit profiles.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_auth_status",
        description="Show local Auditex auth state, including Azure CLI and saved m365 connections.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_auth_list",
        description="List saved m365 connections for the local Auditex operator environment.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_auth_use",
        description="Switch the active saved m365 connection.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_auth_import_token",
        description="Store a customer-provided Graph bearer token as a local auth context.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_auth_inspect_token",
        description="Decode a Graph bearer token locally and return its claims summary.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_auth_capability",
        description="Map a saved auth context to collector capability and missing read permissions.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_contract_schema_manifest",
        description="List versioned output contract schemas shipped with this Auditex build.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_run_offline_validation",
        description="Run the offline sample audit to validate local packaging without tenant access.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_run_delegated_audit",
        description="Run the Azure CLI token or supplied-token audit path against a tenant and return the run manifest path.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_summarize_run",
        description="Read a completed run directory and return summary, manifest, and diagnostics paths.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_diff_runs",
        description="Compare normalized snapshots between two completed run directories.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_compare_runs",
        description="Compare multiple completed runs with same-tenant gating and timeline output.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_probe_live",
        description="Run a live capability probe against a tenant and emit capability/toolchain/blocker artifacts.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_probe_summarize",
        description="Read a completed probe run and return capability, toolchain, and blocker artifact paths.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_list_blockers",
        description="Read blocker artifacts from a completed audit or probe run.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_report_preview",
        description="Build an in-memory report preview for a completed run without writing files.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_export_list",
        description="List available report exporters.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_notify_preview",
        description="Build the dry-run notification payload for a completed run.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_rules_inventory",
        description="List built-in rule inventory rows with optional routing filters.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_run_response_action",
        description="Run a guarded response action in a separate response bundle.",
        read_only_hint=False,
    ),
)


def iter_tool_specs() -> tuple[dict[str, Any], ...]:
    return tuple(entry.spec() for entry in TOOL_REGISTRY)


def register_fastmcp_tools(server: Any, handlers: Mapping[str, Handler]) -> None:
    for entry in TOOL_REGISTRY:
        if entry.name not in handlers:
            continue
        handler = handlers[entry.name]
        handler.__name__ = entry.name
        _tool_decorator(server, entry)(handler)


def _tool_decorator(server: Any, entry: McpToolEntry) -> Callable[[Handler], Handler]:
    metadata = {
        "name": entry.name,
        "description": entry.description,
        "annotations": entry.annotations,
    }
    try:
        return server.tool(**metadata)
    except TypeError:
        return server.tool()
