from __future__ import annotations

from auditex.mcp_registry import iter_tool_specs, register_fastmcp_tools


def test_registry_owns_tool_names_and_read_only_hints() -> None:
    specs = list(iter_tool_specs())
    by_name = {item["name"]: item for item in specs}

    assert "auditex_list_profiles" in by_name
    assert by_name["auditex_list_profiles"]["readOnlyHint"] is True
    assert by_name["auditex_run_delegated_audit"]["readOnlyHint"] is False
    assert by_name["auditex_run_response_action"]["readOnlyHint"] is False
    assert len(by_name) == len(specs)


def test_registry_registers_fake_fastmcp_from_handlers() -> None:
    registered: list[tuple[str, str, bool]] = []

    class _FakeFastMCP:
        def tool(self, **metadata):
            def decorator(func):
                registered.append(
                    (
                        metadata["name"],
                        func.__name__,
                        metadata["annotations"]["readOnlyHint"],
                    )
                )
                return func

            return decorator

    def _handler() -> dict[str, bool]:
        return {"ok": True}

    register_fastmcp_tools(_FakeFastMCP(), {"auditex_list_profiles": _handler})

    assert registered == [("auditex_list_profiles", "auditex_list_profiles", True)]
