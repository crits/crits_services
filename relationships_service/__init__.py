import logging

from crits.services.core import Service

logger = logging.getLogger(__name__)

class RelationshipsService(Service):
    name = "relationships_service"
    version = '0.0.2'
    description = "Generate relationship graphs between objects."

    def __init__(self, *args, **kwargs):
        pass

    def _scan(self, obj):
        pass

    def stop(self):
        pass
