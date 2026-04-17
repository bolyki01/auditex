from __future__ import annotations

from collections import Counter
from typing import Any


def _values(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    section = payload.get(key, {})
    values = section.get("value", []) if isinstance(section, dict) else []
    if isinstance(values, list):
        return [item for item in values if isinstance(item, dict)]
    return []


def _compact(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, [], {}, "")}


def _record(kind: str, source: str, object_id: str, **fields: Any) -> dict[str, Any]:
    payload = {
        "kind": kind,
        "source": source,
        "id": object_id,
        "key": f"{kind}:{object_id}",
    }
    payload.update(fields)
    return _compact(payload)


def build_normalized_snapshot(
    *,
    tenant_name: str,
    run_id: str,
    collector_payloads: dict[str, dict[str, Any]],
    diagnostics: list[dict[str, Any]] | None = None,
    result_rows: list[dict[str, Any]] | None = None,
    coverage_rows: list[dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    diagnostics = diagnostics or []
    result_rows = result_rows or []
    coverage_rows = coverage_rows or []

    users = [
        _record(
            "user",
            "identity.users",
            str(item.get("id")),
            display_name=item.get("displayName"),
            principal_name=item.get("userPrincipalName"),
            mail=item.get("mail"),
            department=item.get("department"),
            user_type=item.get("userType"),
            enabled=item.get("accountEnabled"),
        )
        for item in _values(collector_payloads.get("identity", {}), "users")
        if item.get("id")
    ]
    groups = [
        _record(
            "group",
            "identity.groups",
            str(item.get("id")),
            display_name=item.get("displayName"),
            mail=item.get("mail"),
            group_types=item.get("groupTypes"),
        )
        for item in _values(collector_payloads.get("identity", {}), "groups")
        if item.get("id")
    ]
    applications = [
        _record(
            "application",
            "identity.applications",
            str(item.get("id")),
            display_name=item.get("displayName"),
            created=item.get("createdDateTime"),
            audience=item.get("signInAudience"),
        )
        for item in _values(collector_payloads.get("identity", {}), "applications")
        if item.get("id")
    ]
    service_principals = [
        _record(
            "service_principal",
            "identity.servicePrincipals",
            str(item.get("id")),
            display_name=item.get("displayName"),
            app_id=item.get("appId"),
            service_principal_type=item.get("servicePrincipalType"),
        )
        for item in _values(collector_payloads.get("identity", {}), "servicePrincipals")
        if item.get("id")
    ]
    role_definitions = [
        _record(
            "role_definition",
            "identity.roleDefinitions",
            str(item.get("id")),
            display_name=item.get("displayName"),
            description=item.get("description"),
        )
        for item in _values(collector_payloads.get("identity", {}), "roleDefinitions")
        if item.get("id")
    ]
    role_assignments = [
        _record(
            "role_assignment",
            "identity.roleAssignments",
            str(item.get("id")),
            principal_id=item.get("principalId"),
            role_definition_id=item.get("roleDefinitionId"),
        )
        for item in _values(collector_payloads.get("identity", {}), "roleAssignments")
        if item.get("id")
    ]
    devices = [
        _record(
            "device",
            "intune.managedDevices",
            str(item.get("id")),
            display_name=item.get("deviceName"),
            platform=item.get("operatingSystem"),
            os_version=item.get("osVersion"),
            compliance_state=item.get("complianceState"),
            azure_ad_device_id=item.get("azureADDeviceId"),
        )
        for item in _values(collector_payloads.get("intune", {}), "managedDevices")
        if item.get("id")
    ]
    incidents = [
        _record(
            "incident",
            "security.securityIncidents",
            str(item.get("id")),
            display_name=item.get("displayName"),
            severity=item.get("severity"),
            status=item.get("status"),
            classification=item.get("classification"),
            determination=item.get("determination"),
        )
        for item in _values(collector_payloads.get("security", {}), "securityIncidents")
        if item.get("id")
    ]
    security_scores = [
        _record(
            "security_score",
            "security.secureScores",
            str(item.get("id")),
            current_score=item.get("currentScore"),
            max_score=item.get("maxScore"),
            created=item.get("createdDateTime"),
        )
        for item in _values(collector_payloads.get("security", {}), "secureScores")
        if item.get("id")
    ]
    exchange_mailbox_records: list[dict[str, Any]] = []
    for source_name in ("mailboxInventory", "mailboxCount"):
        for item in _values(collector_payloads.get("exchange", {}), source_name):
            mailbox_id = item.get("ExternalDirectoryObjectId") or item.get("id")
            if not mailbox_id:
                continue
            exchange_mailbox_records.append(
                _record(
                    "mailbox",
                    f"exchange.{source_name}",
                    str(mailbox_id),
                    display_name=item.get("DisplayName") or item.get("displayName"),
                    primary_smtp_address=item.get("PrimarySmtpAddress")
                    or item.get("primarySmtpAddress")
                    or item.get("mail"),
                    recipient_type=item.get("RecipientTypeDetails") or item.get("recipientTypeDetails"),
                )
            )
    mailboxes = list({record["key"]: record for record in exchange_mailbox_records}.values())

    policies: list[dict[str, Any]] = []
    for source_name in ("conditionalAccessPolicies",):
        for item in _values(collector_payloads.get("security", {}), source_name):
            if item.get("id"):
                policies.append(
                    _record(
                        "policy",
                        source_name,
                        f"{source_name}:{item.get('id')}",
                        display_name=item.get("displayName"),
                        state=item.get("state"),
                    )
                )
    for source_name in ("deviceCompliancePolicies", "deviceConfigurationProfiles"):
        for item in _values(collector_payloads.get("intune", {}), source_name):
            if item.get("id"):
                policies.append(
                    _record(
                        "policy",
                        source_name,
                        f"{source_name}:{item.get('id')}",
                        display_name=item.get("displayName"),
                        state=item.get("state"),
                    )
                )
    for source_name in ("authenticationMethodsPolicy", "registrationCampaign", "authenticationMethodConfigurations"):
        for item in _values(collector_payloads.get("auth_methods", {}), source_name):
            object_id = str(item.get("id") or item.get("policyType") or item.get("@odata.type") or source_name)
            policies.append(
                _record(
                    "policy",
                    source_name,
                    f"{source_name}:{object_id}",
                    display_name=item.get("displayName") or item.get("policyType") or object_id,
                    state=item.get("state"),
                )
            )

    sites = [
        _record(
            "site",
            "sharepoint.sites",
            str(item.get("id")),
            display_name=item.get("displayName") or item.get("name"),
            web_url=item.get("webUrl"),
        )
        for item in _values(collector_payloads.get("sharepoint", {}), "sites")
        if item.get("id")
    ]

    records_by_section = {
        "users": users,
        "groups": groups,
        "applications": applications,
        "service_principals": service_principals,
        "role_definitions": role_definitions,
        "role_assignments": role_assignments,
        "devices": devices,
        "incidents": incidents,
        "security_scores": security_scores,
        "mailboxes": mailboxes,
        "policies": policies,
        "sites": sites,
    }
    object_counts = {name: len(records) for name, records in records_by_section.items() if records}
    diagnostic_classes = Counter(str(item.get("error_class") or "unknown") for item in diagnostics)

    normalized: dict[str, dict[str, Any]] = {
        "snapshot": {
            "tenant_name": tenant_name,
            "run_id": run_id,
            "object_counts": object_counts,
            "collector_count": len(result_rows),
            "coverage_row_count": len(coverage_rows),
            "blocker_count": len(diagnostics),
            "diagnostic_classes": dict(diagnostic_classes),
        }
    }
    for section, records in records_by_section.items():
        if records:
            normalized[section] = {"kind": section, "records": records}
    return normalized


def build_ai_safe_summary(
    normalized_snapshot: dict[str, dict[str, Any]],
    *,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    snapshot = normalized_snapshot.get("snapshot", {})
    findings = findings or []
    return {
        "tenant_name": snapshot.get("tenant_name"),
        "run_id": snapshot.get("run_id"),
        "object_counts": snapshot.get("object_counts", {}),
        "blocker_count": snapshot.get("blocker_count", 0),
        "findings_count": len(findings),
        "top_findings": [
            {
                "id": item.get("id"),
                "severity": item.get("severity"),
                "category": item.get("category"),
                "title": item.get("title"),
            }
            for item in findings[:10]
        ],
    }
