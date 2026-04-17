from .identity import IdentityCollector
from .security import SecurityCollector
from .auth_methods import AuthMethodsCollector
from .intune import IntuneCollector
from .sharepoint import SharePointCollector
from .teams import TeamsCollector
from .exchange import ExchangeCollector

REGISTRY = {
    "identity": IdentityCollector(),
    "security": SecurityCollector(),
    "auth_methods": AuthMethodsCollector(),
    "intune": IntuneCollector(),
    "sharepoint": SharePointCollector(),
    "teams": TeamsCollector(),
    "exchange": ExchangeCollector(),
}
