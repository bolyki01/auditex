from __future__ import annotations

from collections import Counter
from collections import defaultdict
from typing import Any


_BREAK_GLASS_ROLE_KEYWORDS = (
    "global administrator",
    "privileged role administrator",
    "security administrator",
    "security operator",
    "exchange administrator",
    "intune administrator",
    "global reader",
)


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


def _build_index(items: list[dict[str, Any]], key: str = "id") -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for item in items:
        item_id = item.get(key)
        if isinstance(item_id, str) and item_id:
            index[item_id] = item
    return index


def _to_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int)) or item is not None]


def _ensure_placeholder_skipped(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        if value.lower() in {"all", "none", "unknownfuturevalue", "allusers", "all_guests"}:
            continue
        normalized.append(value)
    return normalized


def _build_break_glass_candidates(
    role_assignments: list[dict[str, Any]],
    role_definitions: list[dict[str, Any]],
    groups: list[dict[str, Any]],
) -> set[str]:
    role_by_id = _build_index(role_definitions)
    candidates: set[str] = set()
    for assignment in role_assignments:
        role_id = assignment.get("roleDefinitionId")
        if not isinstance(role_id, str):
            continue
        role = role_by_id.get(role_id)
        display_name = str(role.get("displayName", "")).lower() if role else ""
        if any(keyword in display_name for keyword in _BREAK_GLASS_ROLE_KEYWORDS):
            principal = assignment.get("principalId")
            if isinstance(principal, str):
                candidates.add(principal)
    for group in groups:
        group_name = str(group.get("displayName", "")).lower()
        if "break" in group_name and "glass" in group_name:
            group_id = group.get("id")
            if isinstance(group_id, str):
                candidates.add(group_id)
    return candidates


def _resolve_reference(
    reference_type: str,
    reference_id: str,
    indices: dict[str, dict[str, dict[str, Any]]],
) -> tuple[dict[str, Any] | None, str]:
    index = indices.get(reference_type, {})
    record = index.get(reference_id)
    if record is None:
        # Many policy surfaces are identity IDs but sometimes carry app IDs.
        app_alt = index.get(reference_id.lower())
        if app_alt is not None:
            record = app_alt
    if record is None:
        return None, "unresolved"
    return record, "resolved"


def _normalize_mfa_registration(user_registration_rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not user_registration_rows:
        return {
            "sampled_users": 0,
            "mfa_registered": 0,
            "mfa_not_registered": 0,
            "data": "unavailable",
        }
    mfa_registered = sum(1 for row in user_registration_rows if bool(row.get("isMfaRegistered")))
    total = len(user_registration_rows)
    return {
        "sampled_users": total,
        "mfa_registered": mfa_registered,
        "mfa_not_registered": max(total - mfa_registered, 0),
        "data": "sampled",
    }


def _extract_conditional_access_reference(
    *,
    references: dict[str, list[str]],
    target_type: str,
    source_id: str,
    resolved_target: dict[str, Any] | None,
    target_id: str,
    direction: str,
    relationship_type: str,
    indices: dict[str, dict[str, dict[str, Any]]],
) -> dict[str, Any]:
    if resolved_target:
        target_name = resolved_target.get("displayName") or resolved_target.get("name")
        if not target_name:
            target_name = resolved_target.get("appId") or resolved_target.get("id")
        status = "resolved"
    else:
        target_name = None
        status = "unresolved"
    reference_key = f"{source_id}:{direction}:{target_type}:{target_id}:{relationship_type}"
    if reference_key in references.get("edges", []):
        return {}
    references.setdefault("edges", [])
    references["edges"].append(reference_key)
    return {
        "kind": "relationship",
        "source_type": "conditional_access_policy",
        "source_id": source_id,
        "relationship_type": relationship_type,
        "direction": direction,
        "target_type": target_type,
        "target_id": target_id,
        "target_name": target_name,
        "resolution": status,
    }


def _build_conditional_access_graph(
    policies: list[dict[str, Any]],
    identity_payload: dict[str, Any],
    named_locations: list[dict[str, Any]],
    auth_strengths: list[dict[str, Any]],
    auth_contexts: list[dict[str, Any]],
    auth_methods_payload: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    users = _values(identity_payload, "users")
    groups = _values(identity_payload, "groups")
    role_definitions = _values(identity_payload, "roleDefinitions")
    role_assignments = _values(identity_payload, "roleAssignments")
    applications = _values(identity_payload, "applications")
    service_principals = _values(identity_payload, "servicePrincipals")

    indices: dict[str, dict[str, dict[str, Any]]] = {
        "group": _build_index(groups),
        "role_definition": _build_index(role_definitions),
        "application": _build_index(applications),
        "service_principal": _build_index(service_principals),
        "user": _build_index(users),
        "named_location": _build_index(named_locations),
        "auth_strength": _build_index(auth_strengths),
        "auth_context": _build_index(auth_contexts),
        "service_principal_app_id": {item.get("appId"): item for item in service_principals if item.get("appId")},
    }

    mfa_stats = _normalize_mfa_registration(_values(auth_methods_payload, "userRegistrationDetails"))
    break_glass_candidates = _build_break_glass_candidates(role_assignments, role_definitions, groups)

    reference_tracker: dict[str, list[str]] = {}
    graph_records: list[dict[str, Any]] = []
    relationship_records: list[dict[str, Any]] = []
    policy_findings: list[dict[str, Any]] = []

    for policy in policies:
        policy_id = str(policy.get("id"))
        if not policy_id:
            continue

        policy_state = str(policy.get("state", "") or "")
        conditions = policy.get("conditions") if isinstance(policy.get("conditions"), dict) else {}
        grant = policy.get("grantControls") if isinstance(policy.get("grantControls"), dict) else {}
        included_users = _ensure_placeholder_skipped(_to_str_list((conditions.get("users") or {}).get("includeUsers") if isinstance(conditions.get("users"), dict) else conditions.get("users")))
        excluded_users = _ensure_placeholder_skipped(_to_str_list((conditions.get("users") or {}).get("excludeUsers") if isinstance(conditions.get("users"), dict) else conditions.get("users")))
        included_groups = _ensure_placeholder_skipped(_to_str_list((conditions.get("users") or {}).get("includeGroups") if isinstance(conditions.get("users"), dict) else []))
        excluded_groups = _ensure_placeholder_skipped(_to_str_list((conditions.get("users") or {}).get("excludeGroups") if isinstance(conditions.get("users"), dict) else []))
        included_apps = _ensure_placeholder_skipped(_to_str_list((conditions.get("applications") or {}).get("includeApplications") if isinstance(conditions.get("applications"), dict) else []))
        excluded_apps = _ensure_placeholder_skipped(_to_str_list((conditions.get("applications") or {}).get("excludeApplications") if isinstance(conditions.get("applications"), dict) else []))
        include_locations = _ensure_placeholder_skipped(_to_str_list((conditions.get("locations") or {}).get("includeLocations") if isinstance(conditions.get("locations"), dict) else []))
        exclude_locations = _ensure_placeholder_skipped(_to_str_list((conditions.get("locations") or {}).get("excludeLocations") if isinstance(conditions.get("locations"), dict) else []))
        include_auth_strengths = _ensure_placeholder_skipped(_to_str_list((conditions.get("authenticationStrength") or {}).get("includePolicies") if isinstance(conditions.get("authenticationStrength"), dict) else []))

        built_in_controls = _to_str_list(grant.get("builtInControls") if isinstance(grant, dict) else grant.get("builtInControls"))
        built_in_controls = [str(item).lower() for item in built_in_controls]
        requires_mfa = "mfa" in built_in_controls

        for user_id in included_users:
            record, status = _resolve_reference("user", user_id, indices)
            if status == "resolved":
                relationship_records.append(
                    _extract_conditional_access_reference(
                        references=reference_tracker,
                        target_type="user",
                        source_id=policy_id,
                        resolved_target=record,
                        target_id=user_id,
                        direction="include",
                        relationship_type="principal",
                        indices=indices,
                    )
                )
            else:
                relationship_records.append(
                    {
                        "kind": "relationship",
                        "source_type": "conditional_access_policy",
                        "source_id": policy_id,
                        "relationship_type": "principal",
                        "direction": "include",
                        "target_type": "user",
                        "target_id": user_id,
                        "resolution": "unresolved",
                    }
                )

        for user_id in excluded_users:
            record, status = _resolve_reference("user", user_id, indices)
            if status == "resolved":
                relationship_records.append(
                    _extract_conditional_access_reference(
                        references=reference_tracker,
                        target_type="user",
                        source_id=policy_id,
                        resolved_target=record,
                        target_id=user_id,
                        direction="exclude",
                        relationship_type="principal",
                        indices=indices,
                    )
                )
            else:
                relationship_records.append(
                    {
                        "kind": "relationship",
                        "source_type": "conditional_access_policy",
                        "source_id": policy_id,
                        "relationship_type": "principal",
                        "direction": "exclude",
                        "target_type": "user",
                        "target_id": user_id,
                        "resolution": "unresolved",
                    }
                )

        for group_id in included_groups + excluded_groups:
            direction = "include" if group_id in included_groups else "exclude"
            record, status = _resolve_reference("group", group_id, indices)
            relationship_records.append(
                _extract_conditional_access_reference(
                    references=reference_tracker,
                    target_type="group",
                    source_id=policy_id,
                    resolved_target=record,
                    target_id=group_id,
                    direction=direction,
                    relationship_type="membership",
                    indices=indices,
                )
                if status == "resolved"
                else {
                    "kind": "relationship",
                    "source_type": "conditional_access_policy",
                    "source_id": policy_id,
                    "relationship_type": "membership",
                    "direction": direction,
                    "target_type": "group",
                    "target_id": group_id,
                    "resolution": "unresolved",
                }
            )

        for app_id in included_apps + excluded_apps:
            direction = "include" if app_id in included_apps else "exclude"
            record, status = _resolve_reference("application", app_id, indices)
            if status != "resolved":
                record = _build_index(service_principals).get(app_id) or _build_index(service_principals).get(app_id.lower())
                if record is not None:
                    status = "resolved"
                else:
                    sp_by_app_id = indices.get("service_principal_app_id", {})
                    record = sp_by_app_id.get(app_id)
                    if record is not None:
                        status = "resolved"
            relationship_records.append(
                _extract_conditional_access_reference(
                    references=reference_tracker,
                    target_type="application",
                    source_id=policy_id,
                    resolved_target=record,
                    target_id=app_id,
                    direction=direction,
                    relationship_type="application",
                    indices=indices,
                )
                if status == "resolved"
                else {
                    "kind": "relationship",
                    "source_type": "conditional_access_policy",
                    "source_id": policy_id,
                    "relationship_type": "application",
                    "direction": direction,
                    "target_type": "application",
                    "target_id": app_id,
                    "resolution": "unresolved",
                }
            )

        for loc_id in include_locations + exclude_locations:
            direction = "include" if loc_id in include_locations else "exclude"
            record, status = _resolve_reference("named_location", loc_id, indices)
            relationship_records.append(
                _extract_conditional_access_reference(
                    references=reference_tracker,
                    target_type="named_location",
                    source_id=policy_id,
                    resolved_target=record,
                    target_id=loc_id,
                    direction=direction,
                    relationship_type="location",
                    indices=indices,
                )
                if status == "resolved"
                else {
                    "kind": "relationship",
                    "source_type": "conditional_access_policy",
                    "source_id": policy_id,
                    "relationship_type": "location",
                    "direction": direction,
                    "target_type": "named_location",
                    "target_id": loc_id,
                    "resolution": "unresolved",
                }
            )

        for auth_strength_id in include_auth_strengths:
            record, status = _resolve_reference("auth_strength", auth_strength_id, indices)
            relationship_records.append(
                _extract_conditional_access_reference(
                    references=reference_tracker,
                    target_type="auth_strength",
                    source_id=policy_id,
                    resolved_target=record,
                    target_id=auth_strength_id,
                    direction="include",
                    relationship_type="auth_strength",
                    indices=indices,
                )
                if status == "resolved"
                else {
                    "kind": "relationship",
                    "source_type": "conditional_access_policy",
                    "source_id": policy_id,
                    "relationship_type": "auth_strength",
                    "direction": "include",
                    "target_type": "auth_strength",
                    "target_id": auth_strength_id,
                    "resolution": "unresolved",
                }
            )

        # Filter out accidental empty placeholder dictionaries from helper paths.
        relationship_records = [item for item in relationship_records if item]
        unique_relationship_records = list(
            {tuple(sorted(record.items())): record for record in relationship_records}.values()
        )
        relationship_records = unique_relationship_records

        missing_break_glass = False
        if policy_state == "enabled":
            if break_glass_candidates:
                excluded_ids = set(excluded_users + excluded_groups)
                missing_break_glass = not bool(break_glass_candidates.intersection(excluded_ids))

        report_only = policy_state == "enabledForReportingButNotEnforced"
        mfa_enforcement = {
            "requires_mfa": requires_mfa,
            "mfa_registration": mfa_stats,
            "mfa_enrollment_ratio": (
                round(mfa_stats["mfa_registered"] / mfa_stats["sampled_users"], 4)
                if mfa_stats["sampled_users"] > 0 and requires_mfa
                else None
            ),
        }

        graph_records.append(
            _record(
                "conditional_access_policy",
                "conditional_access.conditionalAccessPolicies",
                policy_id,
                display_name=policy.get("displayName"),
                state=policy_state,
                report_only=report_only,
                enabled_for_reporting=report_only,
                grant_controls={
                    "built_in_controls": built_in_controls,
                    "operator": grant.get("operator"),
                    "custom_auth_factors": grant.get("customAuthenticationFactors"),
                },
                include_exclude_counts={
                    "included_users": len(included_users),
                    "excluded_users": len(excluded_users),
                    "included_groups": len(included_groups),
                    "excluded_groups": len(excluded_groups),
                    "included_applications": len(included_apps),
                    "excluded_applications": len(excluded_apps),
                    "included_locations": len(include_locations),
                    "excluded_locations": len(exclude_locations),
                },
                missing_break_glass_exclusion=missing_break_glass,
                mfa_enforcement=mfa_enforcement,
                relationships=[
                    item
                    for item in relationship_records
                    if item.get("source_id") == policy_id
                ],
            )
        )

        if report_only:
            policy_findings.append(
                _record(
                    "ca_finding",
                    "conditional_access",
                    policy_id,
                    title="Conditional Access policy not enforcing",
                    finding_type="ca_reporting_only",
                    severity="medium",
                    description="Policy is in report-only mode.",
                    policy_id=policy_id,
                )
            )
        if missing_break_glass:
            policy_findings.append(
                _record(
                    "ca_finding",
                    "conditional_access",
                    f"{policy_id}:missing-break-glass-exception",
                    title="Potentially missing emergency access exclusion",
                    finding_type="ca_break_glass_exclusion",
                    severity="high",
                    description="Enabled policy does not explicitly exclude a detected emergency-access principal/group.",
                    policy_id=policy_id,
                )
            )

    relationship_records = [item for item in relationship_records if item]
    unique_relationship_records = list({tuple(sorted(item.items())): item for item in relationship_records}.values())

    summary = {
        "policy_count": len(policies),
        "relationship_count": len(unique_relationship_records),
        "report_only_policies": sum(1 for policy in graph_records if policy.get("enabled_for_reporting")),
        "enabled_policies": sum(1 for policy in graph_records if str(policy.get("state", "")).lower() == "enabled"),
        "policies_missing_break_glass_exclusion": sum(
            1 for policy in graph_records if policy.get("missing_break_glass_exclusion")
        ),
        "dangling_references": sum(1 for rel in unique_relationship_records if rel.get("resolution") == "unresolved"),
    }
    return graph_records, unique_relationship_records, summary, policy_findings


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
            "defender.defenderIncidents",
            str(item.get("id")),
            display_name=item.get("displayName"),
            severity=item.get("severity"),
            status=item.get("status"),
            classification=item.get("classification"),
            determination=item.get("determination"),
        )
        for item in _values(collector_payloads.get("defender", {}), "defenderIncidents")
        if item.get("id")
    ]
    security_scores = [
        _record(
            "security_score",
            "defender.secureScores",
            str(item.get("id")),
            current_score=item.get("currentScore"),
            max_score=item.get("maxScore"),
            created=item.get("createdDateTime"),
        )
        for item in _values(collector_payloads.get("defender", {}), "secureScores")
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
        for item in _values(collector_payloads.get("conditional_access", {}), source_name):
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
    purview_audit_jobs = [
        _record(
            "purview_audit_job",
            "purview.auditLogJobs",
            str(item.get("id") or item.get("name")),
            status=item.get("status"),
            created_date_time=item.get("createdDateTime") or item.get("createdDateTimeUTC"),
            operation=item.get("operation"),
            error_code=item.get("errorCode"),
            source=item.get("source"),
        )
        for item in _values(collector_payloads.get("purview", {}), "auditLogJobs")
        if item.get("id") or item.get("name")
    ]
    purview_audit_exports = [
        _record(
            "purview_audit_export",
            "purview.auditLogExports",
            str(item.get("id") or item.get("name")),
            status=item.get("status"),
            export_id=item.get("exportId"),
            download_url=item.get("downloadUrl") or item.get("download_url"),
            created_date_time=item.get("createdDateTime") or item.get("createdDateTimeUTC"),
            source=item.get("source"),
        )
        for item in _values(collector_payloads.get("purview", {}), "auditLogExports")
        if item.get("id") or item.get("name")
    ]
    purview_retention_labels = [
        _record(
            "purview_retention_label",
            "purview.retentionLabels",
            str(item.get("id") or item.get("name")),
            display_name=item.get("name") or item.get("displayName"),
            retention_duration=item.get("retentionDuration"),
            enabled=item.get("isEnabled"),
        )
        for item in _values(collector_payloads.get("purview", {}), "retentionLabels")
        if item.get("id") or item.get("name")
    ]
    purview_retention_policies = [
        _record(
            "purview_retention_policy",
            "purview.retentionPolicies",
            str(item.get("id") or item.get("name")),
            display_name=item.get("name") or item.get("displayName"),
            priority=item.get("priority"),
            type=item.get("type"),
        )
        for item in _values(collector_payloads.get("purview", {}), "retentionPolicies")
        if item.get("id") or item.get("name")
    ]
    purview_dlp_policies = [
        _record(
            "purview_dlp_policy",
            "purview.dlpPolicies",
            str(item.get("id") or item.get("name")),
            display_name=item.get("name") or item.get("displayName"),
            description=item.get("description"),
            priority=item.get("priority"),
        )
        for item in _values(collector_payloads.get("purview", {}), "dlpPolicies")
        if item.get("id") or item.get("name")
    ]
    ediscovery_cases = [
        _record(
            "ediscovery_case",
            "ediscovery.caseOverview",
            str(item.get("id") or item.get("name")),
            display_name=item.get("name") or item.get("displayName"),
            status=item.get("status"),
            created_date_time=item.get("createdDateTime"),
        )
        for item in _values(collector_payloads.get("ediscovery", {}), "caseOverview")
        if item.get("id") or item.get("name")
    ]
    ediscovery_searches = [
        _record(
            "ediscovery_search",
            "ediscovery.searchList",
            str(item.get("id") or item.get("name")),
            display_name=item.get("name") or item.get("displayName"),
            case_id=item.get("caseId"),
            status=item.get("status"),
        )
        for item in _values(collector_payloads.get("ediscovery", {}), "searchList")
        if item.get("id") or item.get("name")
    ]
    ediscovery_export_jobs = [
        _record(
            "ediscovery_export_job",
            "ediscovery.exportJobs",
            str(item.get("id") or item.get("name")),
            status=item.get("status"),
            case_id=item.get("caseId"),
            created_date_time=item.get("createdDateTime"),
        )
        for item in _values(collector_payloads.get("ediscovery", {}), "exportJobs")
        if item.get("id") or item.get("name")
    ]
    ediscovery_review_sets = [
        _record(
            "ediscovery_review_set",
            "ediscovery.reviewSets",
            str(item.get("id") or item.get("name")),
            status=item.get("status"),
            source=item.get("source"),
        )
        for item in _values(collector_payloads.get("ediscovery", {}), "reviewSets")
        if item.get("id") or item.get("name")
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
        "purview_audit_jobs": purview_audit_jobs,
        "purview_audit_exports": purview_audit_exports,
        "purview_retention_labels": purview_retention_labels,
        "purview_retention_policies": purview_retention_policies,
        "purview_dlp_policies": purview_dlp_policies,
        "ediscovery_cases": ediscovery_cases,
        "ediscovery_searches": ediscovery_searches,
        "ediscovery_export_jobs": ediscovery_export_jobs,
        "ediscovery_review_sets": ediscovery_review_sets,
    }

    conditional_access_graph_records, relationships, graph_summary, policy_findings = _build_conditional_access_graph(
        policies=_values(collector_payloads.get("conditional_access", {}), "conditionalAccessPolicies"),
        identity_payload=collector_payloads.get("identity", {}),
        named_locations=_values(collector_payloads.get("conditional_access", {}), "namedLocations"),
        auth_strengths=_values(collector_payloads.get("conditional_access", {}), "authenticationStrengthPolicies"),
        auth_contexts=_values(collector_payloads.get("conditional_access", {}), "authenticationContextClassReferences"),
        auth_methods_payload=collector_payloads.get("auth_methods", {}),
    )
    if conditional_access_graph_records:
        records_by_section["conditional_access_graph"] = conditional_access_graph_records
    if relationships:
        records_by_section["relationships"] = relationships
    if policy_findings:
        records_by_section["ca_findings"] = policy_findings

    for key, value in graph_summary.items():
        if value:
            # Make graph summary available in snapshot-level counts without inventing a separate section.
            pass

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
