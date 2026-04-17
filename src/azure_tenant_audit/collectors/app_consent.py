from __future__ import annotations

import time
from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, _classify_graph_error, run_graph_endpoints


class AppConsentCollector(Collector):
    name = "app_consent"
    description = "Enterprise application consent, service principal ownership, and app role assignments."
    required_permissions = [
        "Directory.Read.All",
        "DelegatedPermissionGrant.Read.All",
        "AppRoleAssignment.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 250)
        page_size = context.get("page_size")
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "servicePrincipals": {
                    "endpoint": "/servicePrincipals",
                    "params": {
                        "$select": "id,displayName,appId,servicePrincipalType,appOwnerOrganizationId,verifiedPublisher",
                    },
                },
                "oauth2PermissionGrants": {
                    "endpoint": "/oauth2PermissionGrants",
                    "params": {
                        "$select": "id,clientId,resourceId,scope,consentType,principalId",
                    },
                },
            },
            top=top,
            page_size=page_size,
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )

        service_principals = payload.get("servicePrincipals", {}).get("value", [])
        if not isinstance(service_principals, list):
            service_principals = []

        owner_rows: list[dict[str, Any]] = []
        assignment_rows: list[dict[str, Any]] = []

        for service_principal in service_principals[:10]:
            sp_id = service_principal.get("id")
            if not isinstance(sp_id, str) or not sp_id:
                continue
            owner_endpoint = f"/servicePrincipals/{sp_id}/owners"
            assignment_endpoint = f"/servicePrincipals/{sp_id}/appRoleAssignedTo"

            for endpoint_name, endpoint, target_list, property_name in (
                ("servicePrincipalOwners", owner_endpoint, owner_rows, "owners"),
                ("servicePrincipalAppRoleAssignments", assignment_endpoint, assignment_rows, "assignments"),
            ):
                start = time.perf_counter()
                try:
                    rows = client.get_all(endpoint, params={"$top": "50"})
                    if not isinstance(rows, list):
                        rows = []
                    target_list.append(
                        {
                            "servicePrincipalId": sp_id,
                            "displayName": service_principal.get("displayName"),
                            property_name: rows,
                        }
                    )
                    coverage.append(
                        {
                            "collector": self.name,
                            "type": "graph",
                            "name": endpoint_name,
                            "endpoint": endpoint,
                            "service_principal_id": sp_id,
                            "status": "ok",
                            "item_count": len(rows),
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
                            "name": endpoint_name,
                            "endpoint": endpoint,
                            "service_principal_id": sp_id,
                            "status": "failed",
                            "item_count": 0,
                            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                            "error_class": error_class,
                            "error": error,
                        }
                    )

        payload["servicePrincipalOwners"] = {"value": owner_rows}
        payload["servicePrincipalAppRoleAssignments"] = {"value": assignment_rows}
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="App consent collector partially completed" if partial else "",
            coverage=coverage,
        )
