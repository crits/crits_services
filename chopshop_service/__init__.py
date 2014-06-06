from distutils.version import StrictVersion
import cStringIO
import logging
import os
import sys
import time
import json

from crits.services.core import Service, ServiceConfigOption
from crits.services.core import ServiceConfigError

DEFAULT_MODULES=["HTTP", "DNS"]

logger = logging.getLogger(__name__)

class ChopShopService(Service):
    """
    Run a PCAP through ChopShop.
    """

    name = "ChopShop"
    version = '0.0.5'
    type_ = Service.TYPE_CUSTOM
    template = None
    supported_types = ['PCAP']
    default_config = [
        ServiceConfigOption('basedir',
                            ServiceConfigOption.STRING,
                            description="A base directory where all the modules and libraries exist.",
                            default=None,
                            required=True,
                            private=True),
        ServiceConfigOption('modules',
                            ServiceConfigOption.MULTI_SELECT,
                            description="Supported modules.",
                            choices=DEFAULT_MODULES,
                            default=DEFAULT_MODULES)
    ]

    def __init__(self, *args, **kwargs):
        super(ChopShopService, self).__init__(*args, **kwargs)
        # When running under mod_wsgi we have to make sure sys.stdout is not
        # going to the real stdout. This is because multiprocessing (used by
        # choplib internally) does sys.stdout.flush(), which mod_wsgi doesn't
        # like. Work around by pointing sys.stdout somewhere that mod_wsgi
        # doesn't care about.
        sys.stdout = sys.stderr
        sys.stdin = open(os.devnull)

        logger.debug("Initializing ChopShop service.")
        self.base_dir = self.config['basedir']
        self.modules = ""
        if 'HTTP' in self.config['modules']:
            self.modules += ";http | http_extractor -m"
        if 'DNS' in self.config['modules']:
            self.modules += ";dns | dns_extractor"
        self.template = "chopshop_analysis.html"

    def _scan(self, obj):
        logger.debug("Setting up shop...")
        shop_path = "%s/shop" % self.base_dir
        if not os.path.exists(self.base_dir):
            self._error("ChopShop path does not exist")
        elif not os.path.exists(shop_path):
            self._error("ChopShop shop path does not exist")
        else:
            sys.path.append(shop_path)
            import ChopLib as CL

            # I wanted to do this check in validate, but if it fails and
            # then you fix the path to point to the appropriate chopshop
            # it requires a webserver restart to take effect. So just do
            # the check at each scan.
            if StrictVersion(str(CL.VERSION)) < StrictVersion('4.0'):
                self._error("Need ChopShop 4.0 or newer")

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
        logger.info(message)
        # The first 'data' is ChopShop stuffing the module output into a key.
        # The second 'data' is from the module stuffing it's output into a key.
        # It's ugly but that's what we get for not being clever in our names.
        addr = message['addr']
        data = message['data']['data']
        # ChopShop stuffs the output of the module into a string... :(
        data = json.loads(data)

        self.service._add_result("Metadata", addr['src'], {"Type": 'Src IP'})
        self.service._add_result("Metadata", addr['dst'], {"Type": 'Dst IP'})
        self.service._add_result("Metadata", addr['sport'], {"Type": 'Src port'})
        self.service._add_result("Metadata", addr['dport'], {"Type": 'Dst port'})
        self.service._add_result("Metadata", message['time'], {"Type": 'Timestamp'})

        if message['module'] == 'http_extractor':
            request = data['request']
            response = data['response']

            self.service._add_result("Metadata", request['method'], {"Type": "Method"})
            self.service._add_result("Metadata", response['status'], {"Type": "Status"})

            for (header, value) in request['uri'].iteritems():
                self.service._add_result("URI", value, {'Key': header})

            for (header, value) in request['headers'].iteritems():
                self.service._add_result("Request Headers", value, {'Header': header})
            if 'body_md5' in request:
                self.service._add_result("Request Body MD5", request['body_md5'], {'Type': "Body MD5"})

            for (header, value) in response['headers'].iteritems():
                self.service._add_result("Response Headers", value, {'Header': header})
            if 'body_md5' in response:
                self.service._add_result("Response Body MD5", response['body_md5'], {'Type': "Body MD5"})
        elif message['module'] == 'dns_extractor':
            header = data['header']
            self.service._add_result("Metadata", header['id'], {"Type": "ID"})
            self.service._add_result("Metadata", header['type'], {"Type": "Type"})
            for list_ in [data['questions'], data['rr']]:
                for item in list_:
                    for (header, value) in item.iteritems():
                        self.service._add_result("Resource Record", value, {"Type": header})

    def handle_ctrl(self, message):
        logger.info(message)
        data = message['data']
        if data['msg'] == 'addmod':
            result = "Add module: %s" % data['name']
        elif data['msg'] == 'finished':
            if data['status'] == 'error':
                result = "Error: %s" % data['errors']
            else:
                result = "Finished: %s" % data['status']
        else:
            result = data
        self.service._info(result)

    def stop(self):
        pass
