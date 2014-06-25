import logging
import os
import sys
import time
import json

from crits.services.core import Service, ServiceConfigOption
from crits.services.core import ServiceConfigError

logger = logging.getLogger(__name__)

# When running under mod_wsgi we have to make sure sys.stdout is not
# going to the real stdout. This is because multiprocessing (used by
# choplib internally) does sys.stdout.flush(), which mod_wsgi doesn't
# like. Work around by pointing sys.stdout somewhere that mod_wsgi
# doesn't care about.
sys.stdout = sys.stderr

class MetaCapService(Service):
    """
    Run a PCAP through ChopShop's MetaCap module.
    """

    name = "MetaCap"
    version = '0.0.2'
    type_ = Service.TYPE_CUSTOM
    template = "metacap_service_template.html"
    description = "Generate layer 3 and 4 metadata from a PCAP."
    supported_types = ['PCAP']
    default_config = [
        ServiceConfigOption('basedir',
                            ServiceConfigOption.STRING,
                            description="A base directory where all the ChopShop modules and libraries exist.",
                            default=None,
                            private=True,
                            required=True),
        ServiceConfigOption('tcpdump',
                            ServiceConfigOption.STRING,
                            description="Full path to tcpdump binary.",
                            default="/usr/sbin/tcpdump",
                            private=True,
                            required=True),
        ServiceConfigOption('tshark',
                            ServiceConfigOption.STRING,
                            description="Full path to tshark binary.",
                            default="/usr/bin/tshark",
                            private=True,
                            required=True),
    ]

    def __init__(self, *args, **kwargs):
        super(MetaCapService, self).__init__(*args, **kwargs)
        return
        logger.debug("Initializing MetaCap service.")
        self.base_dir = self.config['basedir']
        self.modules = "metacap -b"

    def _scan(self, obj):
        logger.debug("Setting up shop...")
        shop_path = "%s/shop" % self.base_dir
        if not os.path.exists(self.base_dir):
            raise ServiceConfigError("ChopShop path does not exist")
        elif not os.path.exists(shop_path):
            raise ServiceConfigError("ChopShop shop path does not exist")
        else:
            sys.path.append(shop_path)
            from ChopLib import ChopLib
            from ChopUi import ChopUi

            logger.debug("Scanning...")

            choplib = ChopLib()
            chopui = ChopUi()

            choplib.base_dir = self.base_dir

            # XXX: Convert from unicode to str...
            choplib.modules = str(self.modules)

            chopui.jsonout = jsonhandler
            choplib.jsonout = True

            # ChopShop (because of pynids) needs to read a file off disk.
            # The services framework forces you to use 'with' here. It's not
            # possible to just get a path to a file on disk.
            with self._write_to_file() as pcap_file:
                choplib.filename = pcap_file
                chopui.bind(choplib)
                chopui.start()
                chopui.jsonclass.set_service(self)
                choplib.start()

                while chopui.is_alive():
                    time.sleep(.1)

                chopui.join()
                choplib.finish()
                choplib.join()

class jsonhandler:
    def __init__(self, ui_stop_fn=None, lib_stop_fn=None, format_string=None):
        self.service = None

    def set_service(self, service):
        self.service = service

    def handle_message(self, message):
        #logger.info(message)
        # The first 'data' is ChopShop stuffing the module output into a key.
        # The second 'data' is from the module stuffing it's output into a key.
        # It's ugly but that's what we get for not being clever in our names.
        data = message['data']['data']
        # ChopShop stuffs the output of the module into a string... :(
        data = json.loads(data)

        # parse the summary first
        pcap_summary = data.pop()
        summary = pcap_summary['data']
        flow_name = "PCAP Statistics"
        tdict = {"Type": "PCAP Summary"}
        self.service._add_result(flow_name, summary, tdict)

        # parse the flows
        dcount = 1
        for flow in data:
            # each flow has a 'data' and 'type' key
            summary = flow['data']
            flow_name = "Flow %s" % dcount
            tdict = {"Type": "Flow Summary"}
            self.service._add_result(flow_name, summary, tdict)
            dcount += 1

    def handle_ctrl(self, message):
        logger.info(message)
        data = message['data']
        if data['msg'] == 'addmod':
            result = "Add module: %s" % data['name']
        elif data['msg'] == 'finished':
            result = "Finished: %s" % data['status']
        else:
            result = data
        self.service._info(result)

    def stop(self):
        pass
