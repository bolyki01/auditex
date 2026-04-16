from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class IntuneCollector(Collector):
    name = "intune"
    description = "Endpoint management, policies, compliance and devices."
    required_permissions = [
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementApps.Read.All",
        "DeviceManagementServiceConfiguration.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 500)
        endpoints = {
            "managedDevices": {
                "endpoint": "/deviceManagement/managedDevices",
                "params": {
                    "$select": "id,deviceName,manufacturer,model,osVersion,operatingSystem,complianceState,azureADDeviceId",
                },
            },
            "deviceCompliancePolicies": {
                "endpoint": "/deviceManagement/deviceCompliancePolicies",
                "params": {},
            },
            "deviceConfigurationProfiles": {
                "endpoint": "/deviceManagement/deviceConfigurations",
                "params": {},
            },
            "deviceCategories": {
                "endpoint": "/deviceManagement/deviceCategories",
                "params": {},
            },
            "iosManagedAppProtections": {
                "endpoint": "/deviceAppManagement/iosManagedAppProtections",
                "params": {},
            },
            "androidManagedAppProtections": {
                "endpoint": "/deviceAppManagement/androidManagedAppProtections",
                "params": {},
            },
            "deviceEnrollmentConfigurations": {
                "endpoint": "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations",
                "params": {},
            },
            "windowsAutopilotDeploymentProfiles": {
                "endpoint": "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles",
                "params": {},
            },
            "cloudPCs": {
                "endpoint": "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs",
                "params": {
                    "$select": "id,displayName,userPrincipalName,provisioningPolicyId,managedDeviceId,status",
                },
            },
            "provisioningPolicies": {
                "endpoint": "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies",
                "params": {
                    "$select": "id,displayName,provisioningType,imageType,managedBy",
                },
            },
        }
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            endpoints,
            top=top,
            log_event=context.get("audit_logger"),
        )
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Intune collector partially completed" if partial else "",
            coverage=coverage,
        )
