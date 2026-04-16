from __future__ import annotations

from azure_tenant_audit.collectors.exchange import ExchangeCollector


class _FallbackCollector(ExchangeCollector):
    class _GraphClient:
        def get_all(self, _path, params=None):  # noqa: ARG002
            return [
                {"id": "mailbox-graph-1", "mail": "x@example.com"},
                {"id": "mailbox-graph-2", "mail": "y@example.com"},
            ]

    def _run_command(self, command, log_event=None):  # noqa: ARG002
        if command == "m365 tenant info get --output json":
            return {
                "command": command,
                "error": "command_not_found:m365",
                "error_class": "command_not_found",
            }
        if command == "m365 tenant status":
            return {
                "command": command,
                "value": [{"tenant": "ok"}],
            }
        if command == "m365 outlook report mailboxusagemailboxcount --period D30 --output json":
            return {
                "command": command,
                "error": "command_output_empty",
                "error_class": "command_output_empty",
            }
        if command == "m365 outlook roomlist list --output json":
            return {
                "command": command,
                "error": "command_not_found:m365",
                "error_class": "command_not_found",
            }
        if command == "m365 exo mailbox list --output json":
            return {
                "command": command,
                "error": "command_not_found:m365",
                "error_class": "command_not_found",
            }

        return {
            "command": command,
            "error": "unexpected",
            "error_class": "command_error",
        }

def test_exchange_collector_falls_back_to_next_command_and_uses_successful_variant() -> None:
    collector = _FallbackCollector()
    result = collector.run({"audit_logger": None, "client": _FallbackCollector._GraphClient()})

    assert result.status == "ok"
    assert result.item_count == 3
    assert result.payload["exchangeConnectivityCheck"]["command"] == "m365 tenant status"
    assert result.payload["mailboxCount"]["command"] == "graph /users?filter=mail ne null"
    assert result.coverage is not None
    assert len(result.coverage) == 2
    assert result.coverage[0]["command_variants"] == [
        "m365 status --output json",
        "m365 tenant info get --output json",
        "m365 tenant status",
    ]
    assert result.coverage[1]["command_variants"] == [
        "m365 outlook report mailboxusagemailboxcount --period D30 --output json",
        "m365 outlook roomlist list --output json",
        "m365 exo mailbox list --output json",
    ]
