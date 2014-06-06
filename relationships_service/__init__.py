import logging

from crits.services.core import Service

logger = logging.getLogger(__name__)

class RelationshipsService(Service):
    name = "relationships_service"
    version = '0.0.2'
    type_ = Service.TYPE_CUSTOM
    template = None
    supported_types = []
    default_config = []

    def __init__(self, *args, **kwargs):
        pass

    def _scan(self, obj):
        pass

    def stop(self):
        pass
