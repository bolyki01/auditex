from .identity import IdentityCollector
from .security import SecurityCollector
from .intune import IntuneCollector
from .teams import TeamsCollector
from .exchange import ExchangeCollector

REGISTRY = {
    "identity": IdentityCollector(),
    "security": SecurityCollector(),
    "intune": IntuneCollector(),
    "teams": TeamsCollector(),
    "exchange": ExchangeCollector(),
}
