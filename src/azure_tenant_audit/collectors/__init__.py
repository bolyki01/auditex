from .identity import IdentityCollector
from .conditional_access import ConditionalAccessCollector
from .defender import DefenderCollector
from .ediscovery import EDiscoveryCollector
from .purview import PurviewCollector
from .security import SecurityCollector
from .auth_methods import AuthMethodsCollector
from .intune import IntuneCollector
from .sharepoint import SharePointCollector
from .teams import TeamsCollector
from .exchange import ExchangeCollector

REGISTRY = {
    "identity": IdentityCollector(),
    "security": SecurityCollector(),
    "conditional_access": ConditionalAccessCollector(),
    "defender": DefenderCollector(),
    "auth_methods": AuthMethodsCollector(),
    "intune": IntuneCollector(),
    "sharepoint": SharePointCollector(),
    "teams": TeamsCollector(),
    "exchange": ExchangeCollector(),
    "purview": PurviewCollector(),
    "ediscovery": EDiscoveryCollector(),
}
