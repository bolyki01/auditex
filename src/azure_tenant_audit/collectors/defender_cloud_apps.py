"""Capability-gated collector for Microsoft Defender for Cloud Apps (CASB)."""
from __future__ import annotations

from typing import Any

from ._capability_gated import build_collector_result, run_capability_gated_endpoints
from .base import Collector


class DefenderCloudAppsCollector(Collector):
    name = "defender_cloud_apps"
    description = (
        "Microsoft Defender for Cloud Apps (CASB) posture via Graph: app security profiles "
        "and OAuth/connected app inventory. Capability-gated; requires Defender for Cloud Apps "
        "(E5/Defender plan) plus tenant onboarding."
    )
    required_permissions = [
        "CloudApp-Discovery.Read.All",
        "Application.Read.All",
        "SecurityEvents.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> Any:
        payload, coverage = run_capability_gated_endpoints(
            self.name,
            context.get("client"),
            [
                ("cloudAppSecurityProfiles", "/security/cloudAppSecurityProfiles"),
                ("appConsentRequests", "/identityGovernance/appConsent/appConsentRequests"),
            ],
            log_event=context.get("audit_logger"),
            skip_reason="no Graph client; Defender for Cloud Apps likely unlicensed",
        )
        return build_collector_result(
            self,
            payload,
            coverage,
            partial_message="Defender for Cloud Apps collection partial; check capability matrix",
        )
