from __future__ import annotations

from typing import Any

from azure_tenant_audit.collectors.mailbox_forwarding import MailboxForwardingCollector


class _FakeClient:
    def __init__(
        self,
        users: list[dict[str, Any]],
        domains: list[dict[str, Any]],
        inbox_rules: dict[str, Any],
        mailbox_settings: dict[str, Any] | None = None,
    ) -> None:
        self._users = users
        self._domains = domains
        self._inbox_rules = inbox_rules
        self._mailbox_settings = mailbox_settings or {}
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        self.calls.append((path, dict(params or {})))
        if path == "/users":
            return list(self._users)
        if path == "/domains":
            return list(self._domains)
        raise AssertionError(f"unexpected path: {path}")

    def get_json(self, path: str, params: dict[str, Any] | None = None, full_url: bool = False) -> dict[str, Any]:
        self.calls.append((path, dict(params or {})))
        if path.startswith("/users/") and path.endswith("/mailFolders/inbox/messageRules"):
            user_id = path.split("/")[2]
            response = self._inbox_rules.get(user_id, [])
            if isinstance(response, Exception):
                raise response
            return {"value": response}
        if path.startswith("/users/") and path.endswith("/mailboxSettings"):
            user_id = path.split("/")[2]
            response = self._mailbox_settings.get(user_id, {})
            if isinstance(response, Exception):
                raise response
            return response
        raise AssertionError(f"unexpected path: {path}")


def test_collector_flags_external_forwarding_rule() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [
        {"id": "contoso.com", "isVerified": True, "isDefault": True},
        {"id": "contoso.onmicrosoft.com", "isVerified": True, "isDefault": False},
    ]
    rules = {
        "u1": [
            {
                "id": "rule-1",
                "displayName": "Forward to external",
                "isEnabled": True,
                "actions": {
                    "forwardTo": [
                        {"emailAddress": {"address": "attacker@evil.example", "name": "attacker"}}
                    ]
                },
                "conditions": {},
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    assert result.status == "ok"
    rules_payload = result.payload["messageRules"]["value"]
    assert len(rules_payload) == 1
    rule = rules_payload[0]
    assert rule["forwards_externally"] is True
    assert rule["external_recipients"] == ["attacker@evil.example"]


def test_collector_classifies_internal_only_forwarding() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [
        {"id": "contoso.com", "isVerified": True, "isDefault": True},
    ]
    rules = {
        "u1": [
            {
                "id": "rule-1",
                "displayName": "Forward internally",
                "isEnabled": True,
                "actions": {
                    "forwardTo": [
                        {"emailAddress": {"address": "bob@contoso.com"}}
                    ]
                },
                "conditions": {},
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    rule = result.payload["messageRules"]["value"][0]
    assert rule["forwards_externally"] is False
    assert rule["external_recipients"] == []
    assert rule["forwards_internally"] is True


def test_collector_detects_hide_from_user_pattern() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {
        "u1": [
            {
                "id": "rule-1",
                "displayName": ".",
                "isEnabled": True,
                "actions": {
                    "moveToFolder": "RSS Feeds",
                    "delete": True,
                },
                "conditions": {
                    "subjectContains": ["invoice", "payment", "wire"],
                },
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    rule = result.payload["messageRules"]["value"][0]
    assert rule["hide_from_user"] is True


def test_collector_records_mailbox_forwarding_settings() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    settings = {
        "u1": {
            "automaticRepliesSetting": {"status": "disabled"},
            "delegateMeetingMessageDeliveryOptions": "sendToDelegateAndInformationToPrincipal",
        }
    }
    collector = MailboxForwardingCollector()
    result = collector.run(
        {
            "client": _FakeClient(users, domains, inbox_rules={"u1": []}, mailbox_settings=settings),
            "top": 100,
        }
    )

    forwarding = result.payload["mailboxSettings"]["value"]
    assert forwarding[0]["user_id"] == "u1"


def test_collector_skips_users_without_mail() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": None, "accountEnabled": True},
        {"id": "u2", "userPrincipalName": "bob@contoso.com", "mail": "bob@contoso.com", "accountEnabled": True},
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {"u2": []}
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    coverage = result.coverage or []
    assert any(row["name"] == "messageRules:u2" for row in coverage)
    assert all(row["name"] != "messageRules:u1" for row in coverage)


def test_collector_records_per_user_403_in_coverage() -> None:
    from azure_tenant_audit.graph import GraphError

    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {"u1": GraphError("forbidden", status=403, request="/users/u1/mailFolders/inbox/messageRules")}

    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    assert result.status == "partial"
    coverage = result.coverage or []
    assert any(
        row["status"] == "failed" and row["error_class"] == "insufficient_permissions"
        for row in coverage
    )
