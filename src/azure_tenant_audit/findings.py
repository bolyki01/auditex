from __future__ import annotations

from collections import Counter
from typing import Any


_PERMISSION_CLASSES = {"insufficient_permissions", "unauthenticated"}
_SERVICE_CLASSES = {"service_unavailable", "not_found", "not_enabled"}


def _category_for(error_class: str | None) -> str:
    if error_class in _PERMISSION_CLASSES:
        return "permission"
    if error_class in _SERVICE_CLASSES:
        return "service"
    return "collector"


def _severity_for(error_class: str | None, status: str | None) -> str:
    if error_class in _PERMISSION_CLASSES:
        return "high"
    if status == "failed":
        return "high"
    return "medium"


def _normalized_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for item in ((normalized_snapshot.get("sharepoint_sharing_findings") or {}).get("records") or []):
        findings.append(
            {
                "id": f"sharepoint:{item.get('id')}",
                "severity": item.get("severity", "medium"),
                "category": "exposure",
                "title": "Broad SharePoint or OneDrive sharing link",
                "status": "open",
                "collector": "sharepoint_access",
                "affected_objects": [item.get("site_name") or item.get("site_id")],
                "evidence": item,
            }
        )

    for item in ((normalized_snapshot.get("sharepoint_site_posture_objects") or {}).get("records") or []):
        ownership_state = str(item.get("ownership_state") or "").lower()
        if ownership_state not in {"weak", "orphaned"}:
            continue
        findings.append(
            {
                "id": f"sharepoint_site_posture:{item.get('id')}:{'orphaned_site' if ownership_state == 'orphaned' else 'weak_ownership'}",
                "severity": "high" if ownership_state == "orphaned" else "medium",
                "category": "exposure",
                "title": "SharePoint site ownership is weak",
                "status": "open",
                "collector": "sharepoint_access",
                "affected_objects": [item.get("site_name") or item.get("id")],
                "evidence": item,
            }
        )

    for item in ((normalized_snapshot.get("onedrive_posture_objects") or {}).get("records") or []):
        site_kind = str(item.get("site_kind") or "").lower()
        sharing_capability = str(item.get("sharing_capability") or "").lower()
        if site_kind != "personal" or not sharing_capability or sharing_capability == "disabled":
            continue
        findings.append(
            {
                "id": f"onedrive_posture:{item.get('id')}:external_sharing_enabled",
                "severity": "high",
                "category": "exposure",
                "title": "OneDrive external sharing is enabled",
                "status": "open",
                "collector": "onedrive_posture",
                "affected_objects": [item.get("site_name") or item.get("id")],
                "evidence": item,
            }
        )

    risky_scopes = {
        "Directory.Read.All",
        "RoleManagement.Read.Directory",
        "Mail.Read",
        "Sites.Read.All",
        "AuditLog.Read.All",
        "eDiscovery.Read.All",
        "Exchange.ManageAsApp",
    }
    for item in ((normalized_snapshot.get("application_consents") or {}).get("records") or []):
        if item.get("source_name") not in (None, "oauth2PermissionGrants"):
            continue
        scope_tokens = {str(token) for token in str(item.get("scope") or "").split() if token}
        high_risk = sorted(scope_tokens & risky_scopes)
        if not high_risk and int(item.get("owner_count") or 0) > 0:
            continue
        findings.append(
            {
                "id": f"app_consent:{item.get('id')}:high_privilege",
                "severity": "high" if high_risk else "medium",
                "category": "application",
                "title": "High privilege or weakly owned enterprise application consent",
                "status": "open",
                "collector": "app_consent",
                "affected_objects": [item.get("service_principal_name") or item.get("service_principal_id")],
                "evidence": item,
                "recommendations": {
                    "high_risk_scopes": high_risk,
                    "owner_count": item.get("owner_count"),
                },
            }
        )

    exchange_records = ((normalized_snapshot.get("exchange_policy_objects") or {}).get("records") or [])
    for item in exchange_records:
        if item.get("source_name") != "mailboxForwarding" or not item.get("forwarding_smtp_address"):
            continue
        findings.append(
            {
                "id": f"exchange:{item.get('id')}:mailbox_forwarding",
                "severity": "high",
                "category": "mail_flow",
                "title": "Mailbox forwarding configured",
                "status": "open",
                "collector": "exchange_policy",
                "affected_objects": [item.get("display_name") or item.get("primary_smtp_address")],
                "evidence": item,
            }
        )

    teams_records = ((normalized_snapshot.get("teams_policy_objects") or {}).get("records") or [])
    for item in teams_records:
        if item.get("source_name") != "tenantFederationConfiguration":
            continue
        if not (item.get("allow_public_users") or item.get("allow_federated_users")):
            continue
        findings.append(
            {
                "id": f"teams_policy:{item.get('id')}:external_federation_open",
                "severity": "medium",
                "category": "collaboration",
                "title": "Teams external federation is enabled",
                "status": "open",
                "collector": "teams_policy",
                "affected_objects": [item.get("policy_name") or item.get("id")],
                "evidence": item,
            }
        )

    service_health_records = ((normalized_snapshot.get("service_health_objects") or {}).get("records") or [])
    active_service_health_statuses = {"serviceDegradation", "serviceInterruption", "investigating", "restoringService"}
    for item in service_health_records:
        if item.get("source_name") != "serviceIssues":
            continue
        if item.get("status") not in active_service_health_statuses:
            continue
        findings.append(
            {
                "id": f"service_health:{item.get('id')}:active_service_issue",
                "severity": "medium",
                "category": "service",
                "title": "Active Microsoft 365 service issue",
                "status": "open",
                "collector": "service_health",
                "affected_objects": [item.get("service") or item.get("title") or item.get("id")],
                "evidence": item,
            }
        )

    external_identity_records = ((normalized_snapshot.get("external_identity_objects") or {}).get("records") or [])
    broad_guest_invite_settings = {"everyone", "everyoneAndGuestInviters"}
    for item in external_identity_records:
        if item.get("source_name") != "authorizationPolicy":
            continue
        if item.get("allow_invites_from") not in broad_guest_invite_settings:
            continue
        findings.append(
            {
                "id": f"external_identity:{item.get('id')}:broad_guest_invite_policy",
                "severity": "medium",
                "category": "external_access",
                "title": "Broad guest invitation policy is enabled",
                "status": "open",
                "collector": "external_identity",
                "affected_objects": [item.get("id")],
                "evidence": item,
            }
        )

    consent_policy_records = ((normalized_snapshot.get("consent_policy_objects") or {}).get("records") or [])
    for item in consent_policy_records:
        if item.get("source_name") != "adminConsentRequestPolicy":
            continue
        if item.get("is_enabled") is not False:
            continue
        findings.append(
            {
                "id": f"consent_policy:{item.get('id')}:admin_consent_workflow_disabled",
                "severity": "medium",
                "category": "application",
                "title": "Admin consent request workflow is disabled",
                "status": "open",
                "collector": "consent_policy",
                "affected_objects": [item.get("id")],
                "evidence": item,
            }
        )

    governance_records = ((normalized_snapshot.get("governance_objects") or {}).get("records") or [])
    assignment_count = sum(1 for item in governance_records if item.get("kind") == "role_assignment_schedule")
    eligibility_count = sum(1 for item in governance_records if item.get("kind") == "role_eligibility_schedule")
    if assignment_count and not eligibility_count:
        findings.append(
            {
                "id": "identity_governance:standing_privilege_only",
                "severity": "medium",
                "category": "governance",
                "title": "Privileged standing assignments observed without eligibility schedules",
                "status": "open",
                "collector": "identity_governance",
                "affected_objects": ["role_assignment_schedules"],
                "recommendations": {
                    "role_assignment_schedule_count": assignment_count,
                    "role_eligibility_schedule_count": eligibility_count,
                },
            }
        )

    intune_assignments = ((normalized_snapshot.get("intune_assignment_objects") or {}).get("records") or [])
    policy_count = ((normalized_snapshot.get("snapshot") or {}).get("object_counts") or {}).get("policies", 0)
    if policy_count and not intune_assignments:
        findings.append(
            {
                "id": "intune:intune_policies_without_assignments",
                "severity": "medium",
                "category": "device_management",
                "title": "Policies observed without sampled Intune assignments",
                "status": "open",
                "collector": "intune_depth",
                "affected_objects": ["intune_policies"],
            }
        )

    for item in ((normalized_snapshot.get("ca_findings") or {}).get("records") or []):
        finding_id = item.get("finding_type") or item.get("id")
        findings.append(
            {
                "id": f"conditional_access:{finding_id}",
                "severity": item.get("severity", "medium"),
                "category": "identity",
                "title": item.get("title") or item.get("finding_type") or "Conditional Access finding",
                "status": "open",
                "collector": "conditional_access",
                "affected_objects": [item.get("policy_name") or item.get("policy_id")],
                "evidence": item,
            }
        )

    return findings


def build_findings(
    diagnostics: list[dict[str, Any]],
    *,
    normalized_snapshot: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in diagnostics:
        collector = str(item.get("collector") or "unknown")
        target = item.get("item") or item.get("endpoint") or collector
        error_class = str(item.get("error_class")) if item.get("error_class") else None
        findings.append(
            {
                "id": f"{collector}:{target}",
                "severity": _severity_for(error_class, str(item.get("status") or "")),
                "category": _category_for(error_class),
                "title": f"{collector} collector issue",
                "status": "open",
                "collector": collector,
                "affected_objects": [str(target)] if target else [],
                "error_class": error_class,
                "error": item.get("error"),
                "recommendations": item.get("recommendations", {}),
            }
        )
    if normalized_snapshot:
        findings.extend(_normalized_findings(normalized_snapshot))
    return findings


def build_report_pack(
    *,
    tenant_name: str,
    overall_status: str,
    findings: list[dict[str, Any]],
    evidence_paths: list[str],
    blocker_count: int = 0,
    diff_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    severity_counts = Counter(str(item.get("severity") or "unknown") for item in findings)
    summary = {
        "tenant_name": tenant_name,
        "overall_status": overall_status,
        "finding_count": len(findings),
        "blocker_count": blocker_count,
        "severity_counts": dict(severity_counts),
    }
    if diff_summary:
        summary["diff_summary"] = diff_summary
    return {
        "summary": summary,
        "findings": findings,
        "evidence_paths": list(dict.fromkeys(evidence_paths)),
    }
