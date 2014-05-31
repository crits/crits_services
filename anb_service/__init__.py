import logging
import sys

from crits.services.core import Service, ServiceConfigOption

logger = logging.getLogger(__name__)

class ANBService(Service):
    name = "anb"
    version = '0.0.1'
    type_ = Service.TYPE_CUSTOM
    template = None
    supported_types = ['Campaign']
    default_config = []

    def __init__(self, *args, **kwargs):
        pass

    def _scan(self, context):
        pass

    def stop(self):
        pass
