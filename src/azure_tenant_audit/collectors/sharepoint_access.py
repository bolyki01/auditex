from __future__ import annotations

import time
from typing import Any

from ..graph import GraphClient
from ..normalize import _iter_permission_targets
from .base import Collector, CollectorResult, _classify_graph_error, run_graph_endpoints


def _site_kind_from_web_url(web_url: Any) -> str:
    url = str(web_url or "").lower()
    if "-my.sharepoint.com" in url:
        return "personal"
    if "/sites/" in url or "/teams/" in url:
        return "team"
    return "other"


def _summarize_permissions(permissions: list[dict[str, Any]]) -> dict[str, Any]:
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

        roles = [str(role).lower() for role in permission.get("roles", []) if role is not None]
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

    principal_count = len(user_targets | group_targets | application_targets)
    if permissions:
        if principal_count == 0:
            ownership_state = "orphaned"
        elif principal_count <= 1:
            ownership_state = "weak"
        else:
            ownership_state = "sampled"
    else:
        ownership_state = "unknown"

    return {
        "permissionCount": len(permissions),
        "principalCount": principal_count,
        "userPrincipalCount": len(user_targets),
        "groupPrincipalCount": len(group_targets),
        "applicationPrincipalCount": len(application_targets),
        "linkPermissionCount": link_permission_count,
        "anonymousLinkCount": anonymous_link_count,
        "organizationLinkCount": organization_link_count,
        "writeLikePermissionCount": write_like_permission_count,
        "ownershipState": ownership_state,
    }


class SharePointAccessCollector(Collector):
    name = "sharepoint_access"
    description = "SharePoint and OneDrive sharing posture plus sampled site permission inventory."
    required_permissions = [
        "Sites.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 150)
        page_size = context.get("page_size")
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "sharePointSettings": {
                    "endpoint": "/admin/sharepoint/settings",
                    "page": False,
                    "params": {},
                },
                "sites": {
                    "endpoint": "/sites",
                    "params": {
                        "$select": "id,name,displayName,webUrl,createdDateTime",
                    },
                },
            },
            top=top,
            page_size=page_size,
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )

        site_rows = payload.get("sites", {}).get("value", [])
        if not isinstance(site_rows, list):
            site_rows = []
        sharepoint_settings = payload.get("sharePointSettings", {}) if isinstance(payload.get("sharePointSettings"), dict) else {}
        sharing_capability = sharepoint_settings.get("sharingCapability")

        sampled_permissions: list[dict[str, Any]] = []
        for site in site_rows[:10]:
            site_id = site.get("id")
            if not isinstance(site_id, str) or not site_id:
                continue
            endpoint = f"/sites/{site_id}/permissions"
            start = time.perf_counter()
            try:
                permissions = client.get_all(endpoint, params={"$top": "50"})
                if not isinstance(permissions, list):
                    permissions = []
                summary = _summarize_permissions(permissions)
                sampled_permissions.append(
                    {
                        "siteId": site_id,
                        "siteName": site.get("displayName") or site.get("name"),
                        "webUrl": site.get("webUrl"),
                        "siteKind": _site_kind_from_web_url(site.get("webUrl")),
                        "sharingCapability": sharing_capability,
                        "permissions": permissions,
                        **summary,
                    }
                )
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": "sitePermissions",
                        "endpoint": endpoint,
                        "site_id": site_id,
                        "status": "ok",
                        "item_count": len(permissions),
                        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                        "error_class": None,
                        "error": None,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                error_class, error = _classify_graph_error(exc)
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": "sitePermissions",
                        "endpoint": endpoint,
                        "site_id": site_id,
                        "status": "failed",
                        "item_count": 0,
                        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                        "error_class": error_class,
                        "error": error,
                    }
                )

        payload["sitePermissionsBySite"] = {"value": sampled_permissions}
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="SharePoint access collector partially completed" if partial else "",
            coverage=coverage,
        )
