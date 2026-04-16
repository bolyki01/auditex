from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class IdentityCollector(Collector):
    name = "identity"
    description = "Directory and identity objects."
    required_permissions = [
        "Directory.Read.All",
        "User.Read.All",
        "Group.Read.All",
        "Application.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 500)
        selectors = {
            "organization": {
                "endpoint": "/organization",
                "page": False,
                "params": {"$select": "id,displayName,tenantType,city,country"},
            },
            "domains": {"endpoint": "/domains", "page": False, "params": {"$select": "id,authenticationType,isDefault,isVerified,isRoot"}},
            "users": {
                "endpoint": "/users",
                "params": {
                    "$select": "id,displayName,userPrincipalName,mail,jobTitle,department,userType,accountEnabled,lastPasswordChangeDateTime",
                },
            },
            "groups": {
                "endpoint": "/groups",
                "params": {
                    "$select": "id,displayName,mail,groupTypes,createdDateTime",
                    "$filter": "securityEnabled eq true",
                },
            },
            "applications": {
                "endpoint": "/applications",
                "params": {"$select": "id,displayName,createdDateTime,signInAudience"},
            },
            "servicePrincipals": {
                "endpoint": "/servicePrincipals",
                "params": {"$select": "id,displayName,appId,servicePrincipalType"},
            },
            "roleDefinitions": {
                "endpoint": "/roleManagement/directory/roleDefinitions",
                "params": {"$select": "id,displayName,description"},
                "apply_top": False,
            },
            "roleAssignments": {
                "endpoint": "/roleManagement/directory/roleAssignments",
                "params": {"$select": "id,principalId,roleDefinitionId"},
            },
        }
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            selectors,
            top=top,
            log_event=context.get("audit_logger"),
        )
        total_items = sum(entry.get("item_count", 0) for entry in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total_items,
            message="Identity collection partially completed" if partial else "",
            coverage=coverage,
        )
