from .identity import IdentityCollector
from .app_consent import AppConsentCollector
from .conditional_access import ConditionalAccessCollector
from .consent_policy import ConsentPolicyCollector
from .defender import DefenderCollector
from .domains_hybrid import DomainsHybridCollector
from .ediscovery import EDiscoveryCollector
from .exchange_policy import ExchangePolicyCollector
from .external_identity import ExternalIdentityCollector
from .identity_governance import IdentityGovernanceCollector
from .intune_depth import IntuneDepthCollector
from .licensing import LicensingCollector
from .onedrive_posture import OneDrivePostureCollector
from .purview import PurviewCollector
from .reports_usage import ReportsUsageCollector
from .security import SecurityCollector
from .service_health import ServiceHealthCollector
from .auth_methods import AuthMethodsCollector
from .intune import IntuneCollector
from .sharepoint import SharePointCollector
from .sharepoint_access import SharePointAccessCollector
from .teams import TeamsCollector
from .teams_policy import TeamsPolicyCollector
from .exchange import ExchangeCollector

REGISTRY = {
    "identity": IdentityCollector(),
    "app_consent": AppConsentCollector(),
    "security": SecurityCollector(),
    "conditional_access": ConditionalAccessCollector(),
    "consent_policy": ConsentPolicyCollector(),
    "defender": DefenderCollector(),
    "domains_hybrid": DomainsHybridCollector(),
    "auth_methods": AuthMethodsCollector(),
    "external_identity": ExternalIdentityCollector(),
    "intune": IntuneCollector(),
    "intune_depth": IntuneDepthCollector(),
    "licensing": LicensingCollector(),
    "identity_governance": IdentityGovernanceCollector(),
    "onedrive_posture": OneDrivePostureCollector(),
    "sharepoint": SharePointCollector(),
    "sharepoint_access": SharePointAccessCollector(),
    "teams": TeamsCollector(),
    "teams_policy": TeamsPolicyCollector(),
    "reports_usage": ReportsUsageCollector(),
    "service_health": ServiceHealthCollector(),
    "exchange": ExchangeCollector(),
    "exchange_policy": ExchangePolicyCollector(),
    "purview": PurviewCollector(),
    "ediscovery": EDiscoveryCollector(),
}
