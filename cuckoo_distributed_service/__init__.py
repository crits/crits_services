import logging
import base64

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from crits.core.user import CRITsUser

from . import forms

logger = logging.getLogger(__name__)


class CuckooDistributedService(Service):
    """
    Leverages RabbitMQ to distribute taskings for Cuckoo

    Requires a RabbitMQ server running the supplied consumers
    """

    name = "Cuckoo_Distributed"
    version = '1.0.0'
    distributed = True
    supported_types = [ 'Sample' ]
    template = 'cd_service_template.html'
    description = 'Submit a sample to Cuckoo in a distributed way'


    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.CuckooDistributedConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nicely.
        fields = forms.CuckooDistributedConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    @staticmethod
    def parse_config(config):
        if not config['rabbit_address']:
            raise ServiceConfigError("URL required.")
        if not config['rabbit_port']:
            raise ServiceConfigError("Port required.")
        if not config['rabbit_user']:
            raise ServiceConfigError("User required.")
        if not config['rabbit_pw']:
            raise ServiceConfigError("Password required.")
        if not config['rabbit_key']:
            raise ServiceConfigError("Key required.")
        if not config['crits_api_key']:
            raise ServiceConfigError("API key required.")

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.CuckooDistributedConfigForm(initial=config),
                                 'config_error': None})
        form = forms.CuckooDistributedConfigForm
        return form, html

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")

    def run(self, obj, config):
        """
        Post a new analysis task for Cuckoo to RabbitMQ.

        """

        self.config = config
        self.obj = obj

        # use payload to pass extra options to cuckoo
        # if you want to.
        payload = {}

        msg = {         
            'payload': payload,
            'file': {
                'name': obj.filename,
                'data': base64.b64encode(obj.filedata.read())
            },
            'crits_data': { # thankfully grabbed from yara_service
                'analysis_id': self.current_task.task_id,
                'object_type': obj._meta['crits_type'],
                'object_id': str(obj.id),
                'username': self.current_task.username,
                'api_key': config['crits_api_key'],
                'md5': str(self.obj.md5),
                'source': self.obj.source[0].name
            }
        }

        rabbit_exch = config.get("rabbit_exch", "")
        routing_key = config['rabbit_key']
        """
        # this is failing for reasons unknown with IndexError: tuple index out of range
        # so I guess 
        rabbit_url = "amqp://{1}:{2}@{3}:{4}/".format(config['rabbit_user'],
            config['rabbit_pw'],
            config['rabbit_address'],
            config['rabbit_port']
        )
        """
        rabbit_url = "amqp://"+config['rabbit_user']+':'+config['rabbit_pw']+'@'+config['rabbit_address']+':'+config['rabbit_port']
        
        try:
            from crits.services.connector import Connector
            conn = Connector(connector="amqp", uri=rabbit_url, ssl=False)
            conn.send_msg(msg, rabbit_exch, routing_key)
            conn.release()
        except Exception as e:
            self._error("Distribution error: {}".format(e))
            return None
