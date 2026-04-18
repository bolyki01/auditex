from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

from .waivers import apply_waivers, load_waivers


_PERMISSION_CLASSES = {"insufficient_permissions", "unauthenticated"}
_SERVICE_CLASSES = {"service_unavailable", "not_found", "not_enabled"}

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_rule_registry(path: Path) -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(payload, dict):
        return {}
    registry: dict[str, dict[str, Any]] = {}
    for rule_id, value in payload.items():
        if isinstance(rule_id, str) and isinstance(value, dict):
            registry[rule_id] = value
    return registry


_FINDING_TEMPLATE_REGISTRY = _load_rule_registry(_REPO_ROOT / "configs" / "finding-templates.json")
_CONTROL_MAPPING_REGISTRY = _load_rule_registry(_REPO_ROOT / "configs" / "control-mappings.json")

_FALLBACK_FINDING_TEMPLATES = {
    "collector.issue.permission": {
        "risk_rating": "high",
        "description": "The current auth context cannot read this surface.",
        "impact": "Coverage is incomplete and the audit cannot confirm this control.",
        "remediation": "Grant the missing read permission or rerun with a deeper profile.",
        "references": ["Graph read permission guidance"],
        "control_ids": ["AUDITEX-COLLECTOR-PERMISSION"],
        "expected_value": "Requested surface is readable",
    },
    "collector.issue.service": {
        "risk_rating": "medium",
        "description": "The target service surface is unavailable or not enabled.",
        "impact": "Coverage is partial until the service becomes available.",
        "remediation": "Validate tenant service state and rerun the affected collector.",
        "references": ["Service readiness guidance"],
        "control_ids": ["AUDITEX-COLLECTOR-SERVICE"],
        "expected_value": "Requested surface is available",
    },
    "collector.issue.collector": {
        "risk_rating": "medium",
        "description": "The collector reported an operational issue.",
        "impact": "Audit evidence for this surface may be incomplete or stale.",
        "remediation": "Review collector diagnostics and rerun after fixing the failure.",
        "references": ["Collector diagnostics"],
        "control_ids": ["AUDITEX-COLLECTOR-FAILURE"],
        "expected_value": "Collector completes successfully",
    },
    "sharepoint.broad_link": {
        "risk_rating": "high",
        "description": "A site exposes broad sharing through organization-wide or anonymous links.",
        "impact": "Data can be exposed beyond the intended audience.",
        "remediation": "Disable broad sharing links or reduce sharing capability.",
        "references": ["SharePoint sharing control guidance"],
        "control_ids": ["AUDITEX-SPO-BROAD-LINK"],
        "expected_value": "Broad links are disabled or tightly scoped",
    },
    "app_consent.high_privilege": {
        "risk_rating": "high",
        "description": "An enterprise application has risky delegated scopes or weak ownership.",
        "impact": "Compromised or abandoned app consent can expose tenant data broadly.",
        "remediation": "Review app consent, remove unused grants, and assign responsible owners.",
        "references": ["Application consent review guidance"],
        "control_ids": ["AUDITEX-APP-CONSENT-HIGH-PRIVILEGE"],
        "expected_value": "Only approved apps keep high-risk scopes and every app has owners",
    },
}


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


def _template_for(rule_id: str) -> dict[str, Any]:
    template = deepcopy(_FALLBACK_FINDING_TEMPLATES.get(rule_id, {}))
    registry_template = _FINDING_TEMPLATE_REGISTRY.get(rule_id)
    if registry_template:
        template.update(deepcopy(registry_template))
    return template


def _framework_mappings_for(rule_id: str) -> dict[str, list[str]]:
    mappings = _CONTROL_MAPPING_REGISTRY.get(rule_id)
    if not mappings:
        return {}
    return deepcopy(mappings)


def _metadata_for(rule_id: str) -> dict[str, Any]:
    metadata = _template_for(rule_id)
    framework_mappings = _framework_mappings_for(rule_id)
    if framework_mappings:
        metadata["framework_mappings"] = framework_mappings
    return metadata


def _rule_id_for(error_class: str | None) -> str:
    if error_class in _PERMISSION_CLASSES:
        return "collector.issue.permission"
    if error_class in _SERVICE_CLASSES:
        return "collector.issue.service"
    return "collector.issue.collector"


def _normalized_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for item in ((normalized_snapshot.get("sharepoint_sharing_findings") or {}).get("records") or []):
        findings.append(
            {
                "id": f"sharepoint:{item.get('id')}",
                "rule_id": "sharepoint.broad_link",
                "severity": item.get("severity", "medium"),
                "category": "exposure",
                "title": "Broad SharePoint or OneDrive sharing link",
                "status": "open",
                "collector": "sharepoint_access",
                "affected_objects": [item.get("site_name") or item.get("site_id")],
                "evidence": item,
                "returned_value": item.get("link_scope"),
                **_metadata_for("sharepoint.broad_link"),
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
                "rule_id": "app_consent.high_privilege",
                "returned_value": sorted(high_risk) if high_risk else item.get("owner_count"),
                "recommendations": {
                    "high_risk_scopes": high_risk,
                    "owner_count": item.get("owner_count"),
                },
                **_metadata_for("app_consent.high_privilege"),
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
    waiver_file: str | Path | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in diagnostics:
        collector = str(item.get("collector") or "unknown")
        target = item.get("item") or item.get("endpoint") or collector
        error_class = str(item.get("error_class")) if item.get("error_class") else None
        rule_id = _rule_id_for(error_class)
        findings.append(
            {
                "id": f"{collector}:{target}",
                "rule_id": rule_id,
                "severity": _severity_for(error_class, str(item.get("status") or "")),
                "category": _category_for(error_class),
                "title": f"{collector} collector issue",
                "status": "open",
                "collector": collector,
                "affected_objects": [str(target)] if target else [],
                "error_class": error_class,
                "error": item.get("error"),
                "returned_value": item.get("error"),
                "recommendations": item.get("recommendations", {}),
                **_metadata_for(rule_id),
            }
        )
    if normalized_snapshot:
        findings.extend(_normalized_findings(normalized_snapshot))
    waiver_rows = load_waivers(Path(waiver_file)) if waiver_file else []
    return apply_waivers(findings, waiver_rows) if waiver_rows else findings


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
    status_counts = Counter(str(item.get("status") or "unknown") for item in findings)
    action_plan = [
        {
            "id": item.get("id"),
            "rule_id": item.get("rule_id"),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "category": item.get("category"),
            "impact": item.get("impact"),
            "remediation": item.get("remediation"),
            "status": item.get("status"),
        }
        for item in findings
        if str(item.get("status") or "open") == "open"
    ]
    summary = {
        "tenant_name": tenant_name,
        "overall_status": overall_status,
        "finding_count": len(findings),
        "blocker_count": blocker_count,
        "severity_counts": dict(severity_counts),
        "status_counts": dict(status_counts),
        "open_count": status_counts.get("open", 0),
        "accepted_count": status_counts.get("accepted_risk", 0),
    }
    if diff_summary:
        summary["diff_summary"] = diff_summary
    return {
        "schema_version": "2026-04-18",
        "summary": summary,
        "findings": findings,
        "action_plan": action_plan,
        "evidence_paths": list(dict.fromkeys(evidence_paths)),
    }
