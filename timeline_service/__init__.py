import logging

from crits.services.core import Service

logger = logging.getLogger(__name__)

class TimelineService(Service):
    name = "timeline_service"
    version = '0.0.1'
    supported_types = []
    description = "Generate a timeline for an object."

    def __init__(self, *args, **kwargs):
        pass

    def _scan(self, obj):
        pass

    def stop(self):
        pass
