import logging
import sys

from crits.services.core import Service, ServiceConfigOption

logger = logging.getLogger(__name__)

class PyewService(Service):
    """
    Run a binary through the Pyew disassember.
    """

    name = "Pyew"
    version = '0.0.1'
    type_ = Service.TYPE_CUSTOM
    template = None
    supported_types = ['Sample']
    description = "Run a binary through the Pyew disassembler."
    default_config = [
        ServiceConfigOption('pyew',
                            ServiceConfigOption.STRING,
                            description="Full path to pyew py file.",
                            default=None,
                            private=True,
                            required=True),
        ServiceConfigOption('port',
                            ServiceConfigOption.STRING,
                            description="port the pyew websocket is listening on.",
                            default=9876,
                            private=True,
                            required=True),
        ServiceConfigOption('secure',
                            ServiceConfigOption.BOOL,
                            description="Use secure websockets"),
    ]

    def __init__(self, *args, **kwargs):
        pass

    def _scan(self, obj):
        pass

    def stop(self):
        pass
