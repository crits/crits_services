import logging

from crits.services.core import Service

logger = logging.getLogger(__name__)

class ANBService(Service):
    name = "anb"
    version = '0.0.1'
    template = None
    supported_types = ['Campaign']
    description = "Generate CSV data for Analyst's Notebook."

    def __init__(self, *args, **kwargs):
        pass

    def _scan(self, obj):
        pass

    def stop(self):
        pass
