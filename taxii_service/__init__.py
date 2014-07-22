import logging
import os

from crits.core.handlers import does_source_exist
from crits.services.core import Service, ServiceConfigOption
from crits.services.core import ServiceConfigError

logger = logging.getLogger(__name__)

class TAXIIClient(Service):
    """
    Send TAXII message to TAXII server.
    """

    name = "taxii_service"
    version = "2.0.1"
    type_ = Service.TYPE_CUSTOM
    supported_types = []
    required_fields = ['_id']
    rerunnable = True
    template = "taxii_service_results.html"
    default_config = [
        ServiceConfigOption('hostname',
                            ServiceConfigOption.STRING,
                            description="TAXII Server hostname.",
                            default=None,
                            required=True,
                            private=True),
        ServiceConfigOption('https',
                            ServiceConfigOption.BOOL,
                            description="Connect using HTTPS.",
                            default=True,
                            required=False,
                            private=True),
        ServiceConfigOption('keyfile',
                            ServiceConfigOption.STRING,
                            description="Location of your keyfile on the server.",
                            default=None,
                            required=True,
                            private=True),
        ServiceConfigOption('certfile',
                            ServiceConfigOption.STRING,
                            description="Location of your certfile on the server.",
                            default=None,
                            required=True,
                            private=True),
        ServiceConfigOption('data_feed',
                            ServiceConfigOption.STRING,
                            description="Your TAXII Data Feed Name.",
                            default=None,
                            required=True,
                            private=True),
        ServiceConfigOption('create_events',
                            ServiceConfigOption.BOOL,
                            description="Create events for all STIX documents.",
                            default=False,
                            required=False,
                            private=True),
        ServiceConfigOption('certfiles',
                            ServiceConfigOption.LIST,
                            description=("Comma-delimited list of CRITs Source"
                                         " name, TAXII feed name, and"
                                         " corresponding certificate"
                                         " file on disk for that source."),
                            default=None,
                            required=True,
                            private=True),
    ]

    @classmethod
    def _validate(cls, config):
        hostname = config.get("hostname", "").strip()
        keyfile = config.get("keyfile", "").strip()
        certfile = config.get("certfile", "").strip()
        data_feed = config.get("data_feed", "").strip()
        certfiles = config.get("certfiles", "")
        if not hostname:
            raise ServiceConfigError("You must specify a TAXII Server.")
        if not keyfile:
            raise ServiceConfigError("You must specify a keyfile location.")
        if  not os.path.isfile(keyfile):
            raise ServiceConfigError("keyfile does not exist.")
        if not certfile:
            raise ServiceConfigError("You must specify a certfile location.")
        if  not os.path.isfile(certfile):
            raise ServiceConfigError("certfile does not exist.")
        if not data_feed:
            raise ServiceConfigError("You must specify a TAXII Data Feed.")
        if not certfiles:
            raise ServiceConfigError("You must specify at least one certfile.")
        for crtfile in certfiles:
            try:
                (source, feed, filepath) = crtfile.split(',')
            except ValueError:
                raise ServiceConfigError("You must specify a source, feed name"
                                         ", and certificate path for each source.")
            source.strip()
            feed.strip()
            filepath.strip()
            if not does_source_exist(source):
                raise ServiceConfigError("Invalid source: %s" % source)
            if  not os.path.isfile(filepath):
                raise ServiceConfigError("certfile does not exist: %s" % filepath)

    def __init__(self, *args, **kwargs):
        super(TAXIIClient, self).__init__(*args, **kwargs)
        logger.debug("Initializing TAXII Client.")
        self.hostname = self.config['hostname'].strip()
        self.keyfile = self.config['keyfile'].strip()
        self.certfile = self.config['certfile'].strip()
        self.certfiles = self.config['certfiles']

    def _scan(self, context):
        pass # Not available via old-style services.
