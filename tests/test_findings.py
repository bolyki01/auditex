from __future__ import annotations

from azure_tenant_audit.findings import build_findings, build_report_pack


def test_build_findings_classifies_permission_and_partial_failures() -> None:
    diagnostics = [
        {
            "collector": "security",
            "item": "securityAlerts",
            "status": "failed",
            "error_class": "insufficient_permissions",
            "error": "Forbidden",
            "recommendations": {"required_graph_scopes": ["SecurityEvents.Read.All"]},
        },
        {
            "collector": "sharepoint",
            "item": "sites",
            "status": "partial",
            "error_class": "service_unavailable",
            "error": "Tenant mysite not provisioned",
            "recommendations": {"notes": ["OneDrive not provisioned"]},
        },
    ]

    findings = build_findings(diagnostics)

    assert len(findings) == 2
    permission_finding = findings[0]
    assert permission_finding["id"] == "security:securityAlerts"
    assert permission_finding["severity"] == "high"
    assert permission_finding["category"] == "permission"
    assert permission_finding["recommendations"]["required_graph_scopes"] == ["SecurityEvents.Read.All"]

    service_finding = findings[1]
    assert service_finding["severity"] == "medium"
    assert service_finding["category"] == "service"
    assert service_finding["affected_objects"] == ["sites"]


def test_build_report_pack_includes_findings_and_evidence_paths() -> None:
    findings = [
        {
            "id": "security:securityAlerts",
            "severity": "high",
            "title": "security collector issue",
            "status": "open",
            "category": "permission",
            "affected_objects": ["securityAlerts"],
        }
    ]

    report = build_report_pack(
        tenant_name="acme",
        overall_status="partial",
        findings=findings,
        evidence_paths=["run-manifest.json", "findings/findings.json"],
        blocker_count=1,
    )

    assert report["summary"]["tenant_name"] == "acme"
    assert report["summary"]["overall_status"] == "partial"
    assert report["summary"]["finding_count"] == 1
    assert report["summary"]["blocker_count"] == 1
    assert report["findings"][0]["id"] == "security:securityAlerts"
    assert report["evidence_paths"] == ["run-manifest.json", "findings/findings.json"]


def test_build_findings_promotes_normalized_workload_risks() -> None:
    normalized = {
        "sharepoint_sharing_findings": {
            "records": [
                {
                    "id": "site-1:perm-1:sharing",
                    "site_id": "site-1",
                    "site_name": "Executive",
                    "link_scope": "anonymous",
                    "severity": "high",
                }
            ]
        },
        "sharepoint_site_posture_objects": {
            "records": [
                {
                    "id": "site-1",
                    "site_name": "Executive",
                    "site_kind": "personal",
                    "sharing_capability": "externalUserAndGuestSharing",
                    "permission_count": 1,
                    "principal_count": 1,
                    "anonymous_link_count": 1,
                    "ownership_state": "weak",
                }
            ]
        },
        "application_consents": {
            "records": [
                {
                    "id": "grant-1",
                    "service_principal_name": "Contoso App",
                    "scope": "Directory.Read.All Mail.Read",
                    "owner_count": 0,
                }
            ]
        },
        "exchange_policy_objects": {
            "records": [
                {
                    "id": "forwarding-user-1",
                    "source_name": "mailboxForwarding",
                    "display_name": "Alice Example",
                    "forwarding_smtp_address": "external@example.net",
                }
            ]
        },
        "teams_policy_objects": {
            "records": [
                {
                    "id": "teams-federation-1",
                    "source_name": "tenantFederationConfiguration",
                    "policy_name": "Global",
                    "allow_public_users": True,
                    "allow_federated_users": True,
                }
            ]
        },
        "service_health_objects": {
            "records": [
                {
                    "id": "issue-1",
                    "source_name": "serviceIssues",
                    "service": "Exchange Online",
                    "title": "Mail delivery delay",
                    "status": "serviceDegradation",
                }
            ]
        },
        "external_identity_objects": {
            "records": [
                {
                    "id": "authz-1",
                    "source_name": "authorizationPolicy",
                    "allow_invites_from": "everyone",
                }
            ]
        },
        "consent_policy_objects": {
            "records": [
                {
                    "id": "consent-1",
                    "source_name": "adminConsentRequestPolicy",
                    "is_enabled": False,
                }
            ]
        },
        "onedrive_posture_objects": {
            "records": [
                {
                    "id": "od-1",
                    "site_name": "Alice OneDrive",
                    "site_kind": "personal",
                    "sharing_capability": "externalUserAndGuestSharing",
                },
                {
                    "id": "team-1",
                    "site_name": "Team Site",
                    "site_kind": "team",
                    "sharing_capability": "externalUserAndGuestSharing",
                },
            ]
        },
        "snapshot": {"tenant_name": "acme", "run_id": "run-1", "object_counts": {}},
    }

    findings = build_findings([], normalized_snapshot=normalized)
    ids = {item["id"] for item in findings}

    assert "sharepoint:site-1:perm-1:sharing" in ids
    assert "sharepoint_site_posture:site-1:weak_ownership" in ids
    assert "onedrive_posture:od-1:external_sharing_enabled" in ids
    assert "app_consent:grant-1:high_privilege" in ids
    assert "exchange:forwarding-user-1:mailbox_forwarding" in ids
    assert "teams_policy:teams-federation-1:external_federation_open" in ids
    assert "service_health:issue-1:active_service_issue" in ids
    assert "external_identity:authz-1:broad_guest_invite_policy" in ids
    assert "consent_policy:consent-1:admin_consent_workflow_disabled" in ids
