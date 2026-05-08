from __future__ import annotations

import json
from pathlib import Path

import pytest

import azure_tenant_audit.findings as findings_module
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
    assert permission_finding["risk_rating"] == "high"
    assert permission_finding["category"] == "permission"
    assert permission_finding["recommendations"]["required_graph_scopes"] == ["SecurityEvents.Read.All"]
    assert permission_finding["evidence_refs"][0]["artifact_path"] == "raw/security.json"

    service_finding = findings[1]
    assert service_finding["severity"] == "medium"
    assert service_finding["category"] == "service"
    assert service_finding["affected_objects"] == ["sites"]


def test_build_report_pack_includes_findings_and_evidence_paths() -> None:
    findings = [
        {
            "id": "security:securityAlerts",
            "rule_id": "collector.issue.permission",
            "severity": "high",
            "title": "security collector issue",
            "status": "open",
            "category": "permission",
            "affected_objects": ["securityAlerts"],
            "remediation": "Grant the missing read scope or reduce the collector set.",
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
    assert report["summary"]["open_count"] == 1
    assert report["summary"]["accepted_count"] == 0
    assert report["privacy"] == {}
    assert report["findings"][0]["id"] == "security:securityAlerts"
    assert report["evidence_paths"] == ["run-manifest.json", "findings/findings.json"]
    assert report["action_plan"][0]["rule_id"] == "collector.issue.permission"


def test_build_findings_applies_waivers_and_adds_richer_fields(tmp_path: Path) -> None:
    waiver_path = tmp_path / "waivers.json"
    waiver_path.write_text(
        """
        {
          "waivers": [
            {
              "rule_id": "collector.issue.permission",
              "comment": "Expected in reader-only tenant",
              "expires_on": "2099-01-01"
            }
          ]
        }
        """.strip(),
        encoding="utf-8",
    )
    diagnostics = [
        {
            "collector": "security",
            "item": "securityAlerts",
            "status": "failed",
            "error_class": "insufficient_permissions",
            "error": "Forbidden",
            "recommendations": {"required_graph_scopes": ["SecurityEvents.Read.All"]},
        }
    ]

    findings = build_findings(diagnostics, waiver_file=waiver_path)

    assert findings[0]["rule_id"] == "collector.issue.permission"
    assert findings[0]["status"] == "accepted_risk"
    assert findings[0]["waiver"]["comment"] == "Expected in reader-only tenant"
    assert findings[0]["description"]
    assert findings[0]["impact"]
    assert findings[0]["remediation"]
    assert findings[0]["references"]


def test_build_findings_uses_registry_metadata_for_templates_and_framework_mappings() -> None:
    findings = build_findings(
        [
            {
                "collector": "security",
                "item": "securityAlerts",
                "status": "failed",
                "error_class": "insufficient_permissions",
                "error": "Forbidden",
            }
        ]
    )

    finding = findings[0]
    assert finding["rule_id"] == "collector.issue.permission"
    assert finding["description"] == "Auditex could not read the requested Microsoft 365 surface with the supplied identity."
    assert finding["impact"] == "The report has a confirmed evidence gap for this area, so the related control cannot be asserted from this run."
    assert finding["remediation"] == "Rerun with the minimum read permission required for the blocked surface, or exclude that surface from the agreed scope."
    assert finding["control_ids"] == ["AUDITEX-COLLECTOR-PERMISSION"]
    assert finding["framework_mappings"]["cis_m365_v3"] == ["1.1.1"]
    assert finding["framework_mappings"]["nist_800_53"] == ["AC-3", "AC-6", "AU-2"]
    assert finding["framework_mappings"]["mitre_attack"] == ["T1078"]
    assert finding["framework_mappings"]["iso_27001"] == ["A.5.15", "A.8.2"]
    assert finding["framework_mappings"]["nis2"] == ["Article 21(2)(d)"]
    assert finding["framework_mappings"]["dora"] == ["Article 9(2)"]


def test_build_findings_keeps_python_fallback_when_registry_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(findings_module, "_FINDING_TEMPLATE_REGISTRY", {})
    monkeypatch.setattr(findings_module, "_CONTROL_MAPPING_REGISTRY", {})

    findings = build_findings(
        [
            {
                "collector": "security",
                "item": "securityAlerts",
                "status": "failed",
                "error_class": "insufficient_permissions",
                "error": "Forbidden",
            }
        ]
    )

    finding = findings[0]
    assert finding["description"] == "Auditex could not read the requested Microsoft 365 surface with the supplied identity."
    assert finding["impact"] == "The report has a confirmed evidence gap for this area, so the related control cannot be asserted from this run."
    assert finding["remediation"] == "Rerun with the minimum read permission required for the blocked surface, or exclude that surface from the agreed scope."
    assert finding["references"] == ["Microsoft Graph permission review", "Auditex collector permission matrix"]
    assert "framework_mappings" not in finding


def test_finding_schema_includes_framework_mappings() -> None:
    schema = json.loads(Path("schemas/finding.schema.json").read_text(encoding="utf-8"))

    assert "framework_mappings" in schema["properties"]


def test_build_report_pack_excludes_accepted_findings_from_action_plan() -> None:
    findings = [
        {
            "id": "security:securityAlerts",
            "rule_id": "collector.issue.permission",
            "severity": "high",
            "title": "security collector issue",
            "status": "accepted_risk",
            "category": "permission",
            "affected_objects": ["securityAlerts"],
            "remediation": "Grant the missing read scope or reduce the collector set.",
        },
        {
            "id": "sharepoint:site-1",
            "rule_id": "sharepoint.broad_link",
            "severity": "high",
            "title": "Broad SharePoint link",
            "status": "open",
            "category": "exposure",
            "affected_objects": ["site-1"],
            "remediation": "Disable anonymous links.",
        },
    ]

    report = build_report_pack(
        tenant_name="acme",
        overall_status="partial",
        findings=findings,
        evidence_paths=["run-manifest.json"],
        blocker_count=1,
    )

    assert report["summary"]["accepted_count"] == 1
    assert report["summary"]["open_count"] == 1
    assert len(report["action_plan"]) == 1
    assert report["action_plan"][0]["rule_id"] == "sharepoint.broad_link"


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


def test_build_findings_makes_conditional_access_ids_unique() -> None:
    normalized = {
        "ca_findings": {
            "records": [
                {"id": "ca-1", "finding_type": "ca_reporting_only", "policy_id": "policy-1", "policy_name": "One"},
                {"id": "ca-2", "finding_type": "ca_reporting_only", "policy_id": "policy-2", "policy_name": "Two"},
            ]
        }
    }

    findings = build_findings([], normalized_snapshot=normalized)

    assert {item["id"] for item in findings} == {
        "conditional_access:ca_reporting_only:policy-1",
        "conditional_access:ca_reporting_only:policy-2",
    }
