from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuditProfile:
    name: str
    description: str
    default_collectors: tuple[str, ...]
    delegated_role_hints: tuple[str, ...]
    app_escalation_permissions: tuple[str, ...]
    notes: str


PROFILES: dict[str, AuditProfile] = {
    "auto": AuditProfile(
        name="auto",
        description="Run the selected collectors and record gaps without assuming a fixed role.",
        default_collectors=("identity", "security", "intune", "teams"),
        delegated_role_hints=("Global Reader",),
        app_escalation_permissions=(),
        notes="Use for unknown delegated tokens and let diagnostics describe missing visibility.",
    ),
    "global-reader": AuditProfile(
        name="global-reader",
        description="Read-only delegated audit path for Entra, M365, and basic workload posture.",
        default_collectors=("identity", "security", "intune", "teams"),
        delegated_role_hints=("Global Reader",),
        app_escalation_permissions=(
            "Policy.Read.All",
            "Directory.Read.All",
            "AuditLog.Read.All",
            "DeviceManagementManagedDevices.Read.All",
        ),
        notes="Preferred first-pass profile for customer-led browser login without app consent.",
    ),
    "security-reader": AuditProfile(
        name="security-reader",
        description="Focused delegated audit for security posture, risk, and alerts.",
        default_collectors=("identity", "security"),
        delegated_role_hints=("Security Reader", "Global Reader"),
        app_escalation_permissions=("SecurityEvents.Read.All", "AuditLog.Read.All"),
        notes="Use when the customer grants Security Reader but not broader workload access.",
    ),
    "exchange-reader": AuditProfile(
        name="exchange-reader",
        description="Focused delegated audit for Exchange Online configuration and mail flow evidence.",
        default_collectors=("exchange",),
        delegated_role_hints=("Exchange Reader", "Global Reader"),
        app_escalation_permissions=("Exchange.ManageAsApp",),
        notes="Uses command-based Exchange collection where Graph coverage is limited.",
    ),
    "intune-reader": AuditProfile(
        name="intune-reader",
        description="Focused delegated audit for Intune devices, compliance, and configuration.",
        default_collectors=("intune",),
        delegated_role_hints=("Intune Reader", "Global Reader"),
        app_escalation_permissions=(
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementManagedDevices.Read.All",
        ),
        notes="Useful when Global Reader does not expose the device-management surfaces needed.",
    ),
    "app-readonly-full": AuditProfile(
        name="app-readonly-full",
        description="Customer-local app-only read path for deep unattended evidence collection.",
        default_collectors=("identity", "security", "intune", "teams", "exchange"),
        delegated_role_hints=(),
        app_escalation_permissions=(
            "Directory.Read.All",
            "Policy.Read.All",
            "AuditLog.Read.All",
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementManagedDevices.Read.All",
            "SecurityEvents.Read.All",
        ),
        notes="Secondary pass only. Use a customer-local app registration and keep permissions read-only.",
    ),
}


def profile_choices() -> list[str]:
    return list(PROFILES.keys())


def get_profile(name: str) -> AuditProfile:
    return PROFILES.get(name, PROFILES["auto"])
