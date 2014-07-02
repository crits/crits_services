import logging
import os
import sys
import time
import json

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

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
    template = "metacap_service_template.html"
    description = "Generate layer 3 and 4 metadata from a PCAP."
    supported_types = ['PCAP']

    @staticmethod
    def parse_config(config):
        # Make sure basedir exists.
        basedir = config.get('basedir', '')
        if basedir:
            shop_path = "%s/shop" % basedir
            if not os.path.exists(basedir):
                raise ServiceConfigError("Base directory does not exist.")
            elif not os.path.exists(shop_path):
                raise ServiceConfigError("'shop' does not exist in base.")
        else:
            raise ServiceConfigError("Base directory must be defined.")

    @staticmethod
    def get_config(existing_config):
        if existing_config:
            return existing_config

        config = {}
        fields = forms.MetaCapConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial
        return config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.MetaCapConfigForm(initial=config),
                                 'config_error': None})
        form = forms.MetaCapConfigForm
        return form, html

    def scan(self, obj, config):
        logger.debug("Setting up shop...")
        base_dir = config['basedir']
        shop_path = "%s/shop" % base_dir
        if not os.path.exists(base_dir):
            self._error("ChopShop path does not exist")
            return
        elif not os.path.exists(shop_path):
            self._error("ChopShop shop path does not exist")
            return

        sys.path.append(shop_path)
        from ChopLib import ChopLib
        from ChopUi import ChopUi

        logger.debug("Scanning...")

        choplib = ChopLib()
        chopui = ChopUi()

        choplib.base_dir = base_dir

        choplib.modules = "metacap -b"

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
