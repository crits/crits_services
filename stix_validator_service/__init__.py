import logging

from crits.services.core import Service

logger = logging.getLogger(__name__)

class StixValidatorService(Service):
    name = "stix_validator_service"
    version = '0.0.1'
    supported_types = []
    description = "Validate STIX XML."

    def __init__(self, *args, **kwargs):
        pass

    def _scan(self, obj):
        pass

    def stop(self):
        pass
