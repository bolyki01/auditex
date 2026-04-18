from __future__ import annotations

from collections import Counter
from collections import defaultdict
from typing import Any

from .friendly_names import build_friendly_name_catalog


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


def _ordered_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _ordered_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [_ordered_value(item) for item in value]
        if normalized and all(isinstance(item, dict) for item in normalized):
            return sorted(
                normalized,
                key=lambda item: (
                    str(item.get("key") or ""),
                    str(item.get("id") or ""),
                    str(item.get("display_name") or item.get("title") or ""),
                ),
            )
        return normalized
    return value


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


def _iter_permission_targets(permission: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    targets: list[tuple[str, dict[str, Any]]] = []
    granted_v2 = permission.get("grantedToIdentitiesV2")
    if isinstance(granted_v2, list):
        identity_items = granted_v2
    else:
        identity_items = []
        granted_to_v2 = permission.get("grantedToV2")
        if isinstance(granted_to_v2, dict):
            identity_items = [granted_to_v2]

    for item in identity_items:
        if not isinstance(item, dict):
            continue
        for target_type in ("user", "group", "application", "siteUser", "device"):
            target = item.get(target_type)
            if isinstance(target, dict):
                targets.append((target_type, target))
                break
    return targets


def _first_non_empty(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key not in item:
            continue
        value = item.get(key)
        if value is not None and value != "":
            return value
    return None


def _site_kind_from_web_url(web_url: Any) -> str:
    url = str(web_url or "").lower()
    if "-my.sharepoint.com" in url:
        return "personal"
    if "/sites/" in url or "/teams/" in url:
        return "team"
    return "other"


def _site_permission_summary(
    item: dict[str, Any],
    *,
    default_sharing_capability: Any = None,
) -> dict[str, Any]:
    permissions = item.get("permissions")
    if not isinstance(permissions, list):
        permissions = []

    user_targets: set[str] = set()
    group_targets: set[str] = set()
    application_targets: set[str] = set()
    link_permission_count = 0
    anonymous_link_count = 0
    organization_link_count = 0
    write_like_permission_count = 0

    for permission in permissions:
        if not isinstance(permission, dict):
            continue

        raw_roles = permission.get("roles")
        roles = [str(role).lower() for role in raw_roles if role is not None] if isinstance(raw_roles, list) else []
        if any(role not in {"read", "view"} for role in roles):
            write_like_permission_count += 1

        link = permission.get("link") if isinstance(permission.get("link"), dict) else {}
        link_scope = str(link.get("scope") or "").lower()
        if link_scope:
            link_permission_count += 1
            if link_scope == "anonymous":
                anonymous_link_count += 1
            elif link_scope == "organization":
                organization_link_count += 1

        for target_type, target in _iter_permission_targets(permission):
            target_id = str(target.get("id") or target.get("userPrincipalName") or target.get("displayName") or "")
            if not target_id:
                continue
            if target_type == "user":
                user_targets.add(target_id)
            elif target_type == "group":
                group_targets.add(target_id)
            elif target_type == "application":
                application_targets.add(target_id)

    permission_count = _first_non_empty(item, "permissionCount", "permission_count")
    if permission_count is None:
        permission_count = len(permissions)
    else:
        permission_count = int(permission_count)

    principal_count = _first_non_empty(item, "principalCount", "principal_count")
    if principal_count is None:
        principal_count = len(user_targets | group_targets | application_targets)
    else:
        principal_count = int(principal_count)

    user_principal_count = _first_non_empty(item, "userPrincipalCount", "user_principal_count")
    if user_principal_count is None:
        user_principal_count = len(user_targets)
    else:
        user_principal_count = int(user_principal_count)

    group_principal_count = _first_non_empty(item, "groupPrincipalCount", "group_principal_count")
    if group_principal_count is None:
        group_principal_count = len(group_targets)
    else:
        group_principal_count = int(group_principal_count)

    application_principal_count = _first_non_empty(item, "applicationPrincipalCount", "application_principal_count")
    if application_principal_count is None:
        application_principal_count = len(application_targets)
    else:
        application_principal_count = int(application_principal_count)

    link_permission_count_value = _first_non_empty(item, "linkPermissionCount", "link_permission_count")
    if link_permission_count_value is None:
        link_permission_count_value = link_permission_count
    else:
        link_permission_count_value = int(link_permission_count_value)

    anonymous_link_count_value = _first_non_empty(item, "anonymousLinkCount", "anonymous_link_count")
    if anonymous_link_count_value is None:
        anonymous_link_count_value = anonymous_link_count
    else:
        anonymous_link_count_value = int(anonymous_link_count_value)

    organization_link_count_value = _first_non_empty(item, "organizationLinkCount", "organization_link_count")
    if organization_link_count_value is None:
        organization_link_count_value = organization_link_count
    else:
        organization_link_count_value = int(organization_link_count_value)

    write_like_permission_count_value = _first_non_empty(item, "writeLikePermissionCount", "write_like_permission_count")
    if write_like_permission_count_value is None:
        write_like_permission_count_value = write_like_permission_count
    else:
        write_like_permission_count_value = int(write_like_permission_count_value)

    site_kind = _first_non_empty(item, "siteKind", "site_kind")
    if isinstance(site_kind, str) and site_kind:
        site_kind = site_kind.lower()
    else:
        site_kind = _site_kind_from_web_url(_first_non_empty(item, "webUrl", "web_url"))

    sharing_capability = _first_non_empty(item, "sharingCapability", "sharing_capability")
    if sharing_capability is None:
        sharing_capability = default_sharing_capability

    ownership_state = _first_non_empty(item, "ownershipState", "ownership_state")
    if not ownership_state:
        if permission_count:
            if principal_count == 0:
                ownership_state = "orphaned"
            elif principal_count <= 1:
                ownership_state = "weak"
            else:
                ownership_state = "sampled"
        else:
            ownership_state = "unknown"

    return {
        "site_kind": site_kind,
        "sharing_capability": sharing_capability,
        "permission_count": permission_count,
        "principal_count": principal_count,
        "user_principal_count": user_principal_count,
        "group_principal_count": group_principal_count,
        "application_principal_count": application_principal_count,
        "link_permission_count": link_permission_count_value,
        "anonymous_link_count": anonymous_link_count_value,
        "organization_link_count": organization_link_count_value,
        "write_like_permission_count": write_like_permission_count_value,
        "ownership_state": ownership_state,
    }


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
    sharepoint_site_posture_objects: list[dict[str, Any]] = []
    sharepoint_permission_edges: list[dict[str, Any]] = []
    sharepoint_sharing_findings: list[dict[str, Any]] = []
    for item in _values(collector_payloads.get("sharepoint_access", {}), "sitePermissionsBySite"):
        site_id = str(item.get("siteId") or "")
        site_name = item.get("siteName")
        web_url = item.get("webUrl")
        site_kind = item.get("siteKind") or _site_kind_from_web_url(web_url)
        sharing_capability = item.get("sharingCapability")
        permissions = item.get("permissions")
        if not site_id:
            continue
        sharepoint_site_posture_objects.append(
            _record(
                "sharepoint_site_posture",
                "sharepoint_access.sitePermissionsBySite",
                site_id,
                site_name=site_name,
                web_url=web_url,
                site_kind=site_kind,
                sharing_capability=sharing_capability,
                permission_count=item.get("permissionCount"),
                principal_count=item.get("principalCount"),
                user_principal_count=item.get("userPrincipalCount"),
                group_principal_count=item.get("groupPrincipalCount"),
                application_principal_count=item.get("applicationPrincipalCount"),
                link_permission_count=item.get("linkPermissionCount"),
                anonymous_link_count=item.get("anonymousLinkCount"),
                organization_link_count=item.get("organizationLinkCount"),
                write_like_permission_count=item.get("writeLikePermissionCount"),
                ownership_state=item.get("ownershipState"),
            )
        )
        if not isinstance(permissions, list):
            continue
        for permission in permissions:
            if not isinstance(permission, dict):
                continue
            permission_id = str(permission.get("id") or f"{site_id}:permission")
            roles = _to_str_list(permission.get("roles"))
            link = permission.get("link") if isinstance(permission.get("link"), dict) else {}
            link_scope = link.get("scope")
            targets = _iter_permission_targets(permission)
            if not targets:
                sharepoint_permission_edges.append(
                    _record(
                        "sharepoint_permission_edge",
                        "sharepoint_access.sitePermissionsBySite",
                        f"{site_id}:{permission_id}",
                        site_id=site_id,
                        site_name=site_name,
                        web_url=web_url,
                        permission_id=permission_id,
                        target_type="link" if link_scope else "unknown",
                        target_id=permission_id,
                        target_name=link.get("type") or link_scope or permission_id,
                        roles=roles,
                        link_scope=link_scope,
                    )
                )
            for target_type, target in targets:
                target_id = str(target.get("id") or target.get("userPrincipalName") or target.get("displayName") or permission_id)
                sharepoint_permission_edges.append(
                    _record(
                        "sharepoint_permission_edge",
                        "sharepoint_access.sitePermissionsBySite",
                        f"{site_id}:{permission_id}:{target_id}",
                        site_id=site_id,
                        site_name=site_name,
                        web_url=web_url,
                        permission_id=permission_id,
                        target_type=target_type,
                        target_id=target_id,
                        target_name=target.get("displayName") or target.get("userPrincipalName") or target_id,
                        roles=roles,
                        link_scope=link_scope,
                    )
                )
            if isinstance(link_scope, str) and link_scope.lower() in {"anonymous", "organization"}:
                sharepoint_sharing_findings.append(
                    _record(
                        "sharepoint_sharing_finding",
                        "sharepoint_access.sitePermissionsBySite",
                        f"{site_id}:{permission_id}:sharing",
                        finding_type="broad_sharing_link",
                        site_id=site_id,
                        site_name=site_name,
                        permission_id=permission_id,
                        link_scope=link_scope,
                        roles=roles,
                        severity="high" if link_scope.lower() == "anonymous" else "medium",
                    )
                )
    app_consent_payload = collector_payloads.get("app_consent", {})
    app_service_principals = _values(app_consent_payload, "servicePrincipals")
    app_service_principal_by_id = _build_index(app_service_principals)
    app_owners_by_sp_id = {
        str(item.get("servicePrincipalId")): item.get("owners", [])
        for item in _values(app_consent_payload, "servicePrincipalOwners")
        if item.get("servicePrincipalId")
    }
    application_consents = [
        _record(
            "application_consent",
            "app_consent.oauth2PermissionGrants",
            str(item.get("id")),
            service_principal_id=item.get("clientId"),
            service_principal_name=(app_service_principal_by_id.get(str(item.get("clientId"))) or {}).get("displayName"),
            resource_id=item.get("resourceId"),
            scope=item.get("scope"),
            consent_type=item.get("consentType"),
            principal_id=item.get("principalId"),
            owner_count=len(app_owners_by_sp_id.get(str(item.get("clientId")), [])),
            source_name="oauth2PermissionGrants",
        )
        for item in _values(app_consent_payload, "oauth2PermissionGrants")
        if item.get("id")
    ]
    for item in _values(app_consent_payload, "servicePrincipalAppRoleAssignments"):
        service_principal_id = str(item.get("servicePrincipalId") or "")
        assignments = item.get("assignments")
        if not service_principal_id or not isinstance(assignments, list):
            continue
        for assignment in assignments:
            if not isinstance(assignment, dict):
                continue
            object_id = str(assignment.get("id") or f"{service_principal_id}:assignment")
            application_consents.append(
                _record(
                    "application_consent",
                    "app_consent.servicePrincipalAppRoleAssignments",
                    object_id,
                    service_principal_id=service_principal_id,
                    service_principal_name=(app_service_principal_by_id.get(service_principal_id) or {}).get("displayName"),
                    principal_display_name=assignment.get("principalDisplayName"),
                    principal_type=assignment.get("principalType"),
                    source_name="servicePrincipalAppRoleAssignments",
                )
            )
    license_inventory = [
        _record(
            "license_sku",
            "licensing.subscribedSkus",
            str(item.get("skuId") or item.get("id")),
            sku_part_number=item.get("skuPartNumber"),
            consumed_units=item.get("consumedUnits"),
            enabled_units=(item.get("prepaidUnits") or {}).get("enabled") if isinstance(item.get("prepaidUnits"), dict) else None,
            warning_units=(item.get("prepaidUnits") or {}).get("warning") if isinstance(item.get("prepaidUnits"), dict) else None,
            suspended_units=(item.get("prepaidUnits") or {}).get("suspended") if isinstance(item.get("prepaidUnits"), dict) else None,
            service_plan_count=len(item.get("servicePlans", [])) if isinstance(item.get("servicePlans"), list) else 0,
        )
        for item in _values(collector_payloads.get("licensing", {}), "subscribedSkus")
        if item.get("skuId") or item.get("id")
    ]
    exchange_policy_objects: list[dict[str, Any]] = []
    for source_name in (
        "transportRules",
        "inboundConnectors",
        "outboundConnectors",
        "acceptedDomains",
        "remoteDomains",
        "mailboxForwarding",
    ):
        for item in _values(collector_payloads.get("exchange_policy", {}), source_name):
            object_id = str(item.get("Identity") or item.get("Name") or item.get("PrimarySmtpAddress") or source_name)
            exchange_policy_objects.append(
                _record(
                    "exchange_policy_object",
                    f"exchange_policy.{source_name}",
                    object_id,
                    source_name=source_name,
                    display_name=item.get("Name") or item.get("Identity") or item.get("DisplayName"),
                    primary_smtp_address=item.get("PrimarySmtpAddress"),
                    forwarding_smtp_address=item.get("ForwardingSmtpAddress"),
                    deliver_to_mailbox_and_forward=item.get("DeliverToMailboxAndForward"),
                    state=item.get("State"),
                    priority=item.get("Priority"),
                )
            )
    governance_objects: list[dict[str, Any]] = []
    for source_name, kind in (
        ("accessReviews", "access_review"),
        ("entitlementCatalogs", "entitlement_catalog"),
        ("accessPackages", "access_package"),
        ("roleAssignmentSchedules", "role_assignment_schedule"),
        ("roleEligibilitySchedules", "role_eligibility_schedule"),
        ("administrativeUnits", "administrative_unit"),
    ):
        for item in _values(collector_payloads.get("identity_governance", {}), source_name):
            object_id = str(item.get("id") or item.get("displayName") or source_name)
            governance_objects.append(
                _record(
                    kind,
                    f"identity_governance.{source_name}",
                    object_id,
                    display_name=item.get("displayName"),
                    description=item.get("description"),
                    status=item.get("status"),
                )
            )
    intune_assignment_objects: list[dict[str, Any]] = []
    for item in _values(collector_payloads.get("intune_depth", {}), "deviceConfigurationAssignments"):
        policy_id = str(item.get("policyId") or "")
        assignments = item.get("assignments")
        if not policy_id or not isinstance(assignments, list):
            continue
        for assignment in assignments:
            if not isinstance(assignment, dict):
                continue
            target = assignment.get("target") if isinstance(assignment.get("target"), dict) else {}
            assignment_id = str(assignment.get("id") or f"{policy_id}:assignment")
            intune_assignment_objects.append(
                _record(
                    "intune_assignment_object",
                    "intune_depth.deviceConfigurationAssignments",
                    assignment_id,
                    policy_id=policy_id,
                    policy_name=item.get("displayName"),
                    target_group_id=target.get("groupId"),
                )
            )
    teams_policy_objects: list[dict[str, Any]] = []
    for source_name in (
        "tenantFederationConfiguration",
        "messagingPolicies",
        "meetingPolicies",
        "appPermissionPolicies",
        "appSetupPolicies",
    ):
        for item in _values(collector_payloads.get("teams_policy", {}), source_name):
            object_id = str(item.get("Identity") or item.get("id") or source_name)
            teams_policy_objects.append(
                _record(
                    "teams_policy_object",
                    f"teams_policy.{source_name}",
                    object_id,
                    source_name=source_name,
                    policy_name=item.get("Identity") or item.get("displayName"),
                    allow_public_users=item.get("AllowPublicUsers"),
                    allow_federated_users=item.get("AllowFederatedUsers"),
                    allow_cloud_recording=item.get("AllowCloudRecording"),
                )
            )
    service_health_objects: list[dict[str, Any]] = []
    for source_name in ("healthOverviews", "serviceIssues", "messages"):
        section = collector_payloads.get("service_health", {})
        rows = _values(section, source_name)
        for item in rows:
            object_id = str(item.get("id") or item.get("service") or item.get("title") or source_name)
            service_health_objects.append(
                _record(
                    "service_health_object",
                    f"service_health.{source_name}",
                    object_id,
                    source_name=source_name,
                    service=item.get("service"),
                    title=item.get("title"),
                    status=item.get("status"),
                )
            )
    usage_report_objects: list[dict[str, Any]] = []
    for source_name in (
        "office365ActiveUserCounts",
        "sharePointSiteUsageDetail",
        "oneDriveUsageAccountDetail",
        "mailboxUsageDetail",
    ):
        for idx, item in enumerate(_values(collector_payloads.get("reports_usage", {}), source_name), start=1):
            object_id = str(item.get("Site Id") or item.get("Owner Principal Name") or item.get("User Principal Name") or f"{source_name}:{idx}")
            usage_report_objects.append(
                _record(
                    "usage_report_object",
                    f"reports_usage.{source_name}",
                    object_id,
                    source_name=source_name,
                    report_refresh_date=item.get("Report Refresh Date"),
                )
            )
    external_identity_objects: list[dict[str, Any]] = []
    for source_name in ("crossTenantAccessPolicy", "authorizationPolicy", "authenticationFlowsPolicy"):
        section = collector_payloads.get("external_identity", {})
        value = section.get(source_name)
        rows = value.get("value", []) if isinstance(value, dict) and isinstance(value.get("value"), list) else [value] if isinstance(value, dict) else []
        for item in rows:
            object_id = str(item.get("id") or item.get("displayName") or source_name)
            external_identity_objects.append(
                _record(
                    "external_identity_object",
                    f"external_identity.{source_name}",
                    object_id,
                    source_name=source_name,
                    display_name=item.get("displayName"),
                    allow_invites_from=item.get("allowInvitesFrom"),
                )
            )
    consent_policy_objects: list[dict[str, Any]] = []
    for source_name in ("adminConsentRequestPolicy", "permissionGrantPolicies", "authorizationPolicy"):
        section = collector_payloads.get("consent_policy", {})
        value = section.get(source_name)
        rows = value.get("value", []) if isinstance(value, dict) and isinstance(value.get("value"), list) else [value] if isinstance(value, dict) else []
        for item in rows:
            object_id = str(item.get("id") or item.get("displayName") or source_name)
            consent_policy_objects.append(
                _record(
                    "consent_policy_object",
                    f"consent_policy.{source_name}",
                    object_id,
                    source_name=source_name,
                    display_name=item.get("displayName"),
                    is_enabled=item.get("isEnabled"),
                )
            )
    domain_hybrid_objects: list[dict[str, Any]] = []
    for item in _values(collector_payloads.get("domains_hybrid", {}), "domains"):
        object_id = str(item.get("id") or item.get("name"))
        if object_id:
            domain_hybrid_objects.append(
                _record(
                    "domain_hybrid_object",
                    "domains_hybrid.domains",
                    object_id,
                    source_name="domains",
                    authentication_type=item.get("authenticationType"),
                    is_default=item.get("isDefault"),
                    is_verified=item.get("isVerified"),
                )
            )
    sync_users = _values(collector_payloads.get("domains_hybrid", {}), "syncSampleUsers")
    if any(bool(item.get("onPremisesSyncEnabled")) for item in sync_users):
        domain_hybrid_objects.append(
            _record(
                "domain_hybrid_object",
                "domains_hybrid.syncSampleUsers",
                "sync-signal",
                source_name="syncSampleUsers",
                synced_user_count=sum(1 for item in sync_users if bool(item.get("onPremisesSyncEnabled"))),
            )
        )
    onedrive_posture_objects: list[dict[str, Any]] = []
    for source_name in ("oneDriveSites", "teamSites"):
        for item in _values(collector_payloads.get("onedrive_posture", {}), source_name):
            object_id = str(item.get("id") or item.get("webUrl"))
            if object_id:
                onedrive_posture_objects.append(
                    _record(
                        "onedrive_posture_object",
                        f"onedrive_posture.{source_name}",
                        object_id,
                        site_name=item.get("displayName") or item.get("name"),
                        web_url=item.get("webUrl"),
                        site_kind=item.get("siteKind") or _site_kind_from_web_url(item.get("webUrl")),
                        sharing_capability=item.get("sharingCapability"),
                    )
                )
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
        "sharepoint_site_posture_objects": sharepoint_site_posture_objects,
        "sharepoint_permission_edges": sharepoint_permission_edges,
        "sharepoint_sharing_findings": sharepoint_sharing_findings,
        "application_consents": application_consents,
        "license_inventory": license_inventory,
        "exchange_policy_objects": exchange_policy_objects,
        "governance_objects": governance_objects,
        "intune_assignment_objects": intune_assignment_objects,
        "teams_policy_objects": teams_policy_objects,
        "service_health_objects": service_health_objects,
        "usage_report_objects": usage_report_objects,
        "external_identity_objects": external_identity_objects,
        "consent_policy_objects": consent_policy_objects,
        "domain_hybrid_objects": domain_hybrid_objects,
        "onedrive_posture_objects": onedrive_posture_objects,
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

    translation_catalog, translation_warning_count = build_friendly_name_catalog(records_by_section)
    if translation_catalog:
        records_by_section["translation_catalog"] = translation_catalog

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
            "friendly_name_warning_count": translation_warning_count,
        }
    }
    for section, records in records_by_section.items():
        if records:
            normalized[section] = {"kind": section, "records": _ordered_value(records)}
    return _ordered_value(normalized)


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
        "translation_catalog_count": len((normalized_snapshot.get("translation_catalog") or {}).get("records", [])),
        "friendly_name_warning_count": snapshot.get("friendly_name_warning_count", 0),
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
