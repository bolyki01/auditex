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
        "conditional_access": {
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
            "item": "directoryAudits",
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


def test_build_normalized_snapshot_extracts_security_incidents_scores_and_exchange_mailboxes() -> None:
    collector_payloads = {
        "defender": {
            "defenderIncidents": {
                "value": [
                    {
                        "id": "incident-1",
                        "displayName": "Suspicious Inbox Rule",
                        "severity": "high",
                        "status": "active",
                    }
                ]
            },
            "secureScores": {
                "value": [
                    {
                        "id": "score-1",
                        "currentScore": 41.5,
                        "maxScore": 82.0,
                        "createdDateTime": "2026-04-01T00:00:00Z",
                    }
                ]
            },
        },
        "exchange": {
            "mailboxCount": {
                "value": [
                    {
                        "ExternalDirectoryObjectId": "mailbox-1",
                        "DisplayName": "Alice Example",
                        "PrimarySmtpAddress": "alice@example.com",
                        "RecipientTypeDetails": "UserMailbox",
                    }
                ]
            }
        },
    }

    normalized = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-2",
        collector_payloads=collector_payloads,
    )

    assert normalized["snapshot"]["object_counts"]["incidents"] == 1
    assert normalized["snapshot"]["object_counts"]["security_scores"] == 1
    assert normalized["snapshot"]["object_counts"]["mailboxes"] == 1
    assert normalized["incidents"]["records"][0]["severity"] == "high"
    assert normalized["security_scores"]["records"][0]["current_score"] == 41.5
    assert normalized["mailboxes"]["records"][0]["primary_smtp_address"] == "alice@example.com"


def _make_large_identity_payload(*, users: int, groups: int, applications: int) -> dict:
    return {
        "users": {"value": [{"id": f"user-{idx}", "displayName": f"User {idx}"} for idx in range(users)]},
        "groups": {
            "value": [
                {
                    "id": f"group-{idx}",
                    "displayName": f"Group-{idx}" if idx != 0 else "Emergency-Response",
                    "groupTypes": [],
                }
                for idx in range(groups)
            ]
        },
        "applications": {
            "value": [
                {"id": f"app-{idx}", "displayName": f"App {idx}", "appId": f"app-id-{idx}"}
                for idx in range(applications)
            ]
        },
        "roleDefinitions": {
            "value": [
                {"id": "role-admin", "displayName": "Global Administrator"},
            ]
        },
        "roleAssignments": {
            "value": [
                {"id": "role-admin-assignment", "roleDefinitionId": "role-admin", "principalId": "user-0"},
            ]
        },
    }


def test_conditional_access_graph_scales_with_large_identity_and_multiple_policies() -> None:
    user_count = 2000
    group_count = 180
    app_count = 120
    location_count = 16
    auth_strength_count = 8
    policy_count = 600

    identities = _make_large_identity_payload(users=user_count, groups=group_count, applications=app_count)
    conditional_access = {
        "conditionalAccessPolicies": {
            "value": [
                {
                    "id": f"ca-{idx}",
                    "displayName": f"Policy {idx}",
                    "state": "enabled",
                    "conditions": {
                        "users": {
                            "includeUsers": [f"user-{idx % user_count}"],
                            "excludeUsers": [f"user-{(idx + 1) % user_count}"],
                            "includeGroups": [f"group-{idx % group_count}"],
                            "excludeGroups": [f"group-{(idx + 1) % group_count}"],
                        },
                        "applications": {
                            "includeApplications": [f"app-{idx % app_count}"],
                            "excludeApplications": [f"app-{(idx + 1) % app_count}"],
                        },
                        "locations": {
                            "includeLocations": [f"loc-{idx % location_count}"],
                            "excludeLocations": [f"loc-{(idx + 1) % location_count}"],
                        },
                        "authenticationStrength": {"includePolicies": [f"as-{idx % auth_strength_count}"]},
                    },
                    "grantControls": {"builtInControls": ["mfa"], "operator": "AND"},
                }
                for idx in range(policy_count)
            ]
        },
        "namedLocations": {
            "value": [{"id": f"loc-{idx}", "displayName": f"loc-{idx}"} for idx in range(location_count)]
        },
        "authenticationStrengthPolicies": {
            "value": [{"id": f"as-{idx}", "displayName": f"auth-strength-{idx}"} for idx in range(auth_strength_count)]
        },
        "authenticationContextClassReferences": {"value": []},
    }

    first = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-large-1",
        collector_payloads={
            "identity": identities,
            "conditional_access": conditional_access,
            "auth_methods": {"userRegistrationDetails": {"value": [{"isMfaRegistered": True}, {"isMfaRegistered": False}]}},
        },
    )

    second = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-large-1",
        collector_payloads={
            "identity": identities,
            "conditional_access": conditional_access,
            "auth_methods": {"userRegistrationDetails": {"value": [{"isMfaRegistered": True}, {"isMfaRegistered": False}]}},
        },
    )

    assert first["snapshot"]["object_counts"]["users"] == user_count
    assert first["snapshot"]["object_counts"]["groups"] == group_count
    assert first["snapshot"]["object_counts"]["conditional_access_graph"] == policy_count
    assert first["snapshot"]["object_counts"]["relationships"] == policy_count * 9
    assert first["snapshot"]["object_counts"]["ca_findings"] >= 1
    assert first["conditional_access_graph"]["records"][0]["enabled_for_reporting"] is False
    assert first["conditional_access_graph"]["records"][0]["relationships"]
    assert first["snapshot"]["object_counts"]["ca_findings"] == len(first["ca_findings"]["records"])
    assert second["conditional_access_graph"]["records"] == first["conditional_access_graph"]["records"]
    assert second["relationships"]["records"] == first["relationships"]["records"]
