"""Deep AWS service collectors, composed into
:class:`cloudg.inventory.aws_deep.AWSDeepInventoryCollector`.

Each mixin covers one area of the estate and declares the relationships
it observes in ``metadata["relations"]`` (see :func:`._base.rel`); the
relationship linker resolves them into typed edges.
"""

from cloudg.inventory.aws_services.application import ApplicationCollectorsMixin
from cloudg.inventory.aws_services.cloudcontrol import CloudControlCollectorsMixin
from cloudg.inventory.aws_services.containers import ContainerCollectorsMixin
from cloudg.inventory.aws_services.data_ml import DataMLCollectorsMixin
from cloudg.inventory.aws_services.governance import GovernanceCollectorsMixin
from cloudg.inventory.aws_services.identity import IdentityCollectorsMixin
from cloudg.inventory.aws_services.network_ext import NetworkExtCollectorsMixin
from cloudg.inventory.aws_services.platform import PlatformCollectorsMixin
from cloudg.inventory.aws_services.security import SecurityCollectorsMixin
from cloudg.inventory.aws_services.serverless import ServerlessCollectorsMixin

__all__ = [
    "ApplicationCollectorsMixin",
    "CloudControlCollectorsMixin",
    "ContainerCollectorsMixin",
    "DataMLCollectorsMixin",
    "GovernanceCollectorsMixin",
    "NetworkExtCollectorsMixin",
    "IdentityCollectorsMixin",
    "PlatformCollectorsMixin",
    "SecurityCollectorsMixin",
    "ServerlessCollectorsMixin",
]
