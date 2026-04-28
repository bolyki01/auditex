from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

from .resources import resolve_resource_path
from .waivers import apply_waivers, load_waivers


_PERMISSION_CLASSES = {"insufficient_permissions", "unauthenticated"}
_SERVICE_CLASSES = {"service_unavailable", "not_found", "not_enabled"}

def _load_rule_registry(path: Path) -> dict[str, dict[str, Any]]:
    path = resolve_resource_path(path)
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


_FINDING_TEMPLATE_REGISTRY = _load_rule_registry(Path("configs/finding-templates.json"))
_CONTROL_MAPPING_REGISTRY = _load_rule_registry(Path("configs/control-mappings.json"))

_FALLBACK_FINDING_TEMPLATES = {
    "collector.issue.permission": {
        "risk_rating": "high",
        "description": "Auditex could not read the requested Microsoft 365 surface with the supplied identity.",
        "impact": "The report has a confirmed evidence gap for this area, so the related control cannot be asserted from this run.",
        "remediation": "Rerun with the minimum read permission required for the blocked surface, or exclude that surface from the agreed scope.",
        "references": ["Microsoft Graph permission review", "Auditex collector permission matrix"],
        "control_ids": ["AUDITEX-COLLECTOR-PERMISSION"],
        "expected_value": "The collector can read the requested surface.",
    },
    "collector.issue.service": {
        "risk_rating": "medium",
        "description": "The collector reached a tenant surface that is absent, disabled, not provisioned, or temporarily unavailable.",
        "impact": "Evidence for the affected service remains partial until the tenant state or service availability changes.",
        "remediation": "Confirm licensing and service availability, then rerun only the affected collector where appropriate.",
        "references": ["Microsoft service health", "Auditex collector diagnostics"],
        "control_ids": ["AUDITEX-COLLECTOR-SERVICE"],
        "expected_value": "The target service surface responds successfully.",
    },
    "collector.issue.collector": {
        "risk_rating": "medium",
        "description": "A collector finished with an operational error unrelated to normal permission or service-state handling.",
        "impact": "The affected evidence set may be missing, incomplete, or unsuitable for comparison.",
        "remediation": "Inspect the collector diagnostic row, fix the runtime or input condition, and rerun the collector.",
        "references": ["Auditex collector diagnostics"],
        "control_ids": ["AUDITEX-COLLECTOR-FAILURE"],
        "expected_value": "The collector completes without runtime errors.",
    },
    "sharepoint.broad_link": {
        "risk_rating": "high",
        "description": "SharePoint or OneDrive evidence indicates a sharing link with broad audience reach.",
        "impact": "Content may be reachable by users outside the intended collaboration boundary.",
        "remediation": "Reduce the sharing scope, remove stale broad links, and retest affected sites.",
        "references": ["SharePoint sharing policy review"],
        "control_ids": ["AUDITEX-SPO-BROAD-LINK"],
        "expected_value": "External and organization-wide links are absent or explicitly approved.",
    },
    "app_consent.high_privilege": {
        "risk_rating": "high",
        "description": "Application consent evidence shows sensitive scopes or weak ownership governance.",
        "impact": "Over-privileged or unowned application consent can become a durable path to tenant data exposure.",
        "remediation": "Review the consent grant, remove unused scopes, and assign accountable owners before accepting the application.",
        "references": ["Application consent governance review"],
        "control_ids": ["AUDITEX-APP-CONSENT-HIGH-PRIVILEGE"],
        "expected_value": "Sensitive app grants are approved, current, and owned.",
    },
}

_CATEGORY_DEFAULTS = {
    "permission": {
        "description": "Audit evidence for this surface is incomplete because the active identity could not read one or more required endpoints.",
        "impact": "Conclusions for the affected control area are limited to observed data and cannot be treated as complete assurance.",
        "remediation": "Grant the minimum required read permission or rerun with a profile that is approved for this surface.",
        "expected_value": "Collector reads the target surface successfully.",
    },
    "service": {
        "description": "The collector hit a tenant service surface that was unavailable, not provisioned, or not enabled during this run.",
        "impact": "The affected service area remains partially evidenced and may require a scoped rerun after tenant or service changes.",
        "remediation": "Confirm service availability, licensing, and endpoint readiness, then rerun the affected collector.",
        "expected_value": "Target service endpoint returns usable data.",
    },
    "collector": {
        "description": "The collector completed with an operational issue that reduced evidence quality for this surface.",
        "impact": "Collected data for the affected surface may be partial, stale, or missing.",
        "remediation": "Review the collector error and rerun the affected surface after fixing the runtime condition.",
        "expected_value": "Collector completes without runtime errors.",
    },
    "identity": {
        "description": "Identity control evidence indicates a configuration that should be reviewed.",
        "impact": "Identity control strength may be lower than intended for the affected objects.",
        "remediation": "Review the affected identity control and apply the documented secure baseline.",
        "expected_value": "Identity control aligns with the intended baseline.",
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


def _canonical_severity(value: Any, *, fallback: str = "medium") -> str:
    text = str(value or fallback).strip().lower()
    return text if text in {"low", "medium", "high", "critical"} else fallback


def _evidence_ref(
    *,
    artifact_path: str,
    artifact_kind: str,
    collector: str,
    record_key: str,
    source_name: str | None = None,
    json_pointer: str | None = None,
    jsonl_line: int | None = None,
    endpoint: str | None = None,
    response_status: str | None = None,
    query_params: dict[str, Any] | None = None,
    collected_at: str | None = None,
    content_hash: str | None = None,
) -> dict[str, Any]:
    ref = {
        "artifact_path": artifact_path,
        "artifact_kind": artifact_kind,
        "collector": collector,
        "record_key": record_key,
    }
    if source_name:
        ref["source_name"] = source_name
    if json_pointer:
        ref["json_pointer"] = json_pointer
    if jsonl_line is not None:
        ref["jsonl_line"] = jsonl_line
    if endpoint:
        ref["endpoint"] = endpoint
    if response_status:
        ref["response_status"] = response_status
    if query_params:
        ref["query_params"] = query_params
    if collected_at:
        ref["collected_at"] = collected_at
    if content_hash:
        ref["content_hash"] = content_hash
    return ref


def _normalized_evidence_refs(section: str, record: dict[str, Any], collector: str) -> list[dict[str, Any]]:
    record_key = str(record.get("key") or record.get("id") or f"{section}:record")
    return [
        _evidence_ref(
            artifact_path=f"normalized/{section}.json",
            artifact_kind="normalized_json",
            collector=collector,
            record_key=record_key,
            source_name=str(record.get("source_name") or section),
        )
    ]


def _finalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(finding)
    severity = _canonical_severity(result.get("severity"))
    result["severity"] = severity
    result["risk_rating"] = severity
    category = str(result.get("category") or "collector")
    defaults = _CATEGORY_DEFAULTS.get(category, _CATEGORY_DEFAULTS["collector"])
    result["description"] = result.get("description") or defaults["description"]
    result["impact"] = result.get("impact") or defaults["impact"]
    result["remediation"] = result.get("remediation") or defaults["remediation"]
    result["expected_value"] = result.get("expected_value") or defaults["expected_value"]
    if "returned_value" not in result:
        result["returned_value"] = None
    refs = result.get("references")
    result["references"] = list(refs) if isinstance(refs, list) else []
    affected = result.get("affected_objects")
    result["affected_objects"] = [str(item) for item in affected] if isinstance(affected, list) else []
    evidence_refs = result.get("evidence_refs")
    normalized_refs = [dict(item) for item in evidence_refs if isinstance(item, dict)] if isinstance(evidence_refs, list) else []
    if not normalized_refs:
        collector = str(result.get("collector") or "unknown")
        normalized_refs = [
            _evidence_ref(
                artifact_path="normalized/snapshot.json",
                artifact_kind="normalized_json",
                collector=collector,
                record_key=str(result.get("id") or collector),
                source_name="snapshot",
            )
        ]
        result["evidence_ref_generated"] = True
    result["evidence_refs"] = normalized_refs
    result.setdefault("control_ids", [])
    return result


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
            _finalize_finding(
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
                "evidence_refs": _normalized_evidence_refs("sharepoint_sharing_findings", item, "sharepoint_access"),
                **_metadata_for("sharepoint.broad_link"),
            }
            )
        )

    for item in ((normalized_snapshot.get("sharepoint_site_posture_objects") or {}).get("records") or []):
        ownership_state = str(item.get("ownership_state") or "").lower()
        if ownership_state not in {"weak", "orphaned"}:
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"sharepoint_site_posture:{item.get('id')}:{'orphaned_site' if ownership_state == 'orphaned' else 'weak_ownership'}",
                "severity": "high" if ownership_state == "orphaned" else "medium",
                "category": "exposure",
                "title": "SharePoint site ownership is weak",
                "status": "open",
                "collector": "sharepoint_access",
                "affected_objects": [item.get("site_name") or item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("sharepoint_site_posture_objects", item, "sharepoint_access"),
            }
            )
        )

    for item in ((normalized_snapshot.get("onedrive_posture_objects") or {}).get("records") or []):
        site_kind = str(item.get("site_kind") or "").lower()
        sharing_capability = str(item.get("sharing_capability") or "").lower()
        if site_kind != "personal" or not sharing_capability or sharing_capability == "disabled":
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"onedrive_posture:{item.get('id')}:external_sharing_enabled",
                "severity": "high",
                "category": "exposure",
                "title": "OneDrive external sharing is enabled",
                "status": "open",
                "collector": "onedrive_posture",
                "affected_objects": [item.get("site_name") or item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("onedrive_posture_objects", item, "onedrive_posture"),
            }
            )
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
            _finalize_finding(
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
                "evidence_refs": _normalized_evidence_refs("application_consents", item, "app_consent"),
                **_metadata_for("app_consent.high_privilege"),
            }
            )
        )

    exchange_records = ((normalized_snapshot.get("exchange_policy_objects") or {}).get("records") or [])
    for item in exchange_records:
        if item.get("source_name") != "mailboxForwarding" or not item.get("forwarding_smtp_address"):
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"exchange:{item.get('id')}:mailbox_forwarding",
                "severity": "high",
                "category": "mail_flow",
                "title": "Mailbox forwarding configured",
                "status": "open",
                "collector": "exchange_policy",
                "affected_objects": [item.get("display_name") or item.get("primary_smtp_address")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("exchange_policy_objects", item, "exchange_policy"),
            }
            )
        )

    teams_records = ((normalized_snapshot.get("teams_policy_objects") or {}).get("records") or [])
    for item in teams_records:
        if item.get("source_name") != "tenantFederationConfiguration":
            continue
        if not (item.get("allow_public_users") or item.get("allow_federated_users")):
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"teams_policy:{item.get('id')}:external_federation_open",
                "severity": "medium",
                "category": "collaboration",
                "title": "Teams external federation is enabled",
                "status": "open",
                "collector": "teams_policy",
                "affected_objects": [item.get("policy_name") or item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("teams_policy_objects", item, "teams_policy"),
            }
            )
        )

    service_health_records = ((normalized_snapshot.get("service_health_objects") or {}).get("records") or [])
    active_service_health_statuses = {"serviceDegradation", "serviceInterruption", "investigating", "restoringService"}
    for item in service_health_records:
        if item.get("source_name") != "serviceIssues":
            continue
        if item.get("status") not in active_service_health_statuses:
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"service_health:{item.get('id')}:active_service_issue",
                "severity": "medium",
                "category": "service",
                "title": "Active Microsoft 365 service issue",
                "status": "open",
                "collector": "service_health",
                "affected_objects": [item.get("service") or item.get("title") or item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("service_health_objects", item, "service_health"),
            }
            )
        )

    external_identity_records = ((normalized_snapshot.get("external_identity_objects") or {}).get("records") or [])
    broad_guest_invite_settings = {"everyone", "everyoneAndGuestInviters"}
    for item in external_identity_records:
        if item.get("source_name") != "authorizationPolicy":
            continue
        if item.get("allow_invites_from") not in broad_guest_invite_settings:
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"external_identity:{item.get('id')}:broad_guest_invite_policy",
                "severity": "medium",
                "category": "external_access",
                "title": "Broad guest invitation policy is enabled",
                "status": "open",
                "collector": "external_identity",
                "affected_objects": [item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("external_identity_objects", item, "external_identity"),
            }
            )
        )

    consent_policy_records = ((normalized_snapshot.get("consent_policy_objects") or {}).get("records") or [])
    for item in consent_policy_records:
        if item.get("source_name") != "adminConsentRequestPolicy":
            continue
        if item.get("is_enabled") is not False:
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"consent_policy:{item.get('id')}:admin_consent_workflow_disabled",
                "severity": "medium",
                "category": "application",
                "title": "Admin consent request workflow is disabled",
                "status": "open",
                "collector": "consent_policy",
                "affected_objects": [item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("consent_policy_objects", item, "consent_policy"),
            }
            )
        )

    governance_records = ((normalized_snapshot.get("governance_objects") or {}).get("records") or [])
    assignment_count = sum(1 for item in governance_records if item.get("kind") == "role_assignment_schedule")
    eligibility_count = sum(1 for item in governance_records if item.get("kind") == "role_eligibility_schedule")
    if assignment_count and not eligibility_count:
        findings.append(
            _finalize_finding(
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
                "evidence_refs": [
                    _evidence_ref(
                        artifact_path="normalized/governance_objects.json",
                        artifact_kind="normalized_json",
                        collector="identity_governance",
                        record_key="identity_governance:standing_privilege_only",
                        source_name="role_assignment_schedule",
                    )
                ],
            }
            )
        )

    intune_assignments = ((normalized_snapshot.get("intune_assignment_objects") or {}).get("records") or [])
    policy_count = ((normalized_snapshot.get("snapshot") or {}).get("object_counts") or {}).get("policies", 0)
    if policy_count and not intune_assignments:
        findings.append(
            _finalize_finding(
                {
                "id": "intune:intune_policies_without_assignments",
                "severity": "medium",
                "category": "device_management",
                "title": "Policies observed without sampled Intune assignments",
                "status": "open",
                "collector": "intune_depth",
                "affected_objects": ["intune_policies"],
                "returned_value": {"policy_count": policy_count, "assignment_count": 0},
                "evidence_refs": [
                    _evidence_ref(
                        artifact_path="normalized/snapshot.json",
                        artifact_kind="normalized_json",
                        collector="intune_depth",
                        record_key="intune:intune_policies_without_assignments",
                        source_name="snapshot",
                    )
                ],
            }
            )
        )

    for item in ((normalized_snapshot.get("ca_findings") or {}).get("records") or []):
        finding_id = item.get("finding_type") or item.get("id")
        policy_key = item.get("policy_id") or item.get("id") or item.get("policy_name") or "policy"
        findings.append(
            _finalize_finding(
                {
                "id": f"conditional_access:{finding_id}:{policy_key}",
                "severity": item.get("severity", "medium"),
                "category": "identity",
                "title": item.get("title") or item.get("finding_type") or "Conditional Access finding",
                "status": "open",
                "collector": "conditional_access",
                "affected_objects": [item.get("policy_name") or item.get("policy_id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("ca_findings", item, "conditional_access"),
            }
            )
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
        evidence_refs = item.get("evidence_refs")
        if not isinstance(evidence_refs, list):
            evidence_refs = [
                _evidence_ref(
                    artifact_path=f"raw/{collector}.json",
                    artifact_kind="raw_json",
                    collector=collector,
                    record_key=f"{collector}:{target}",
                    source_name=str(item.get("item") or target),
                    json_pointer=f"/{item.get('item') or ''}" if item.get("item") else None,
                    endpoint=str(item.get("endpoint")) if item.get("endpoint") else None,
                    response_status=str(item.get("status")) if item.get("status") else None,
                    query_params={
                        key: item.get(key)
                        for key in ("top", "page", "result_limit")
                        if item.get(key) is not None
                    }
                    or None,
                )
            ]
        findings.append(
            _finalize_finding(
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
                "evidence_refs": evidence_refs,
                **_metadata_for(rule_id),
            }
            )
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
    privacy: dict[str, Any] | None = None,
    artifact_map: dict[str, Any] | None = None,
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
        "schema_version": "2026-04-21",
        "summary": summary,
        "privacy": privacy or {},
        "artifact_map": artifact_map or {},
        "findings": findings,
        "action_plan": action_plan,
        "evidence_paths": list(dict.fromkeys(evidence_paths)),
    }
