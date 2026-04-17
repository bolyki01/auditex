from __future__ import annotations

from azure_tenant_audit.normalize import build_ai_safe_summary, build_normalized_snapshot


def test_build_normalized_snapshot_extracts_core_objects() -> None:
    collector_payloads = {
        "identity": {
            "users": {
                "value": [
                    {
                        "id": "user-1",
                        "displayName": "Alice Example",
                        "userPrincipalName": "alice@example.com",
                        "department": "Sales",
                        "accountEnabled": True,
                    }
                ]
            },
            "groups": {
                "value": [
                    {
                        "id": "group-1",
                        "displayName": "Sales Team",
                        "mail": "sales@example.com",
                        "groupTypes": ["Unified"],
                    }
                ]
            },
            "roleDefinitions": {"value": [{"id": "role-def-1", "displayName": "Global Reader"}]},
            "roleAssignments": {"value": [{"id": "role-assign-1", "roleDefinitionId": "role-def-1", "principalId": "user-1"}]},
        },
        "intune": {
            "managedDevices": {
                "value": [
                    {
                        "id": "device-1",
                        "deviceName": "W365-01",
                        "operatingSystem": "Windows",
                        "complianceState": "compliant",
                    }
                ]
            },
            "deviceCompliancePolicies": {"value": [{"id": "policy-1", "displayName": "Windows Compliance"}]},
        },
        "security": {
            "conditionalAccessPolicies": {
                "value": [
                    {
                        "id": "ca-1",
                        "displayName": "Require MFA for Admins",
                        "state": "enabled",
                    }
                ]
            }
        },
        "sharepoint": {
            "sites": {
                "value": [
                    {
                        "id": "site-1",
                        "displayName": "Executive Portal",
                        "webUrl": "https://contoso.sharepoint.com/sites/executive",
                    }
                ]
            }
        },
    }
    diagnostics = [
        {
            "collector": "security",
            "item": "securityAlerts",
            "status": "failed",
            "error_class": "insufficient_permissions",
        }
    ]

    normalized = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads=collector_payloads,
        diagnostics=diagnostics,
    )

    assert normalized["snapshot"]["tenant_name"] == "acme"
    assert normalized["snapshot"]["run_id"] == "run-1"
    assert normalized["snapshot"]["object_counts"]["users"] == 1
    assert normalized["snapshot"]["object_counts"]["groups"] == 1
    assert normalized["snapshot"]["object_counts"]["devices"] == 1
    assert normalized["snapshot"]["object_counts"]["policies"] == 2
    assert normalized["snapshot"]["object_counts"]["sites"] == 1
    assert normalized["snapshot"]["blocker_count"] == 1

    user = normalized["users"]["records"][0]
    assert user["key"] == "user:user-1"
    assert user["principal_name"] == "alice@example.com"

    device = normalized["devices"]["records"][0]
    assert device["key"] == "device:device-1"
    assert device["platform"] == "Windows"

    policy_keys = {record["key"] for record in normalized["policies"]["records"]}
    assert "policy:deviceCompliancePolicies:policy-1" in policy_keys
    assert "policy:conditionalAccessPolicies:ca-1" in policy_keys


def test_build_ai_safe_summary_uses_normalized_snapshot_counts() -> None:
    normalized = {
        "snapshot": {
            "tenant_name": "acme",
            "run_id": "run-1",
            "object_counts": {"users": 2, "groups": 3, "devices": 1},
            "blocker_count": 1,
        },
        "users": {"records": [{"key": "user:user-1"}, {"key": "user:user-2"}]},
    }
    findings = [{"id": "security:securityAlerts", "severity": "high"}]

    ai_safe = build_ai_safe_summary(normalized, findings=findings)

    assert ai_safe["tenant_name"] == "acme"
    assert ai_safe["run_id"] == "run-1"
    assert ai_safe["object_counts"]["groups"] == 3
    assert ai_safe["findings_count"] == 1
    assert ai_safe["blocker_count"] == 1
