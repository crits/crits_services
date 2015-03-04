import logging
import simplejson
import urllib
import urllib2

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

import shodan

logger = logging.getLogger(__name__)


class ShodanService(Service):
    """
    Check the Shodan database to see if it contains this IP.

    Requires an API key available from shodan.com
    """

    name = "shodan_lookup"
    version = '1.0.0'
    supported_types = ['IP']
    required_fields = []
    template = 'shodan_service_template.html'
    description = "Look up an IP in Shodan"

    @staticmethod
    def save_runtime_config(config):
        del config['shodan_api_key']

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.ShodanConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def parse_config(config):
        if not config['shodan_api_key']:
            raise ServiceConfigError("API key required.")

    @classmethod
    def generate_config_form(self, config):
        # Convert sigfiles to newline separated strings
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.ShodanConfigForm(initial=config),
                                 'config_error': None})
        form = forms.ShodanConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.ShodanConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    def run(self, obj, config):
        key = config.get('shodan_api_key', '')
        
        if not key:
            self._error("No valid Shodan key found")
            return

        api = shodan.Shodan(key)

        if obj._meta['crits_type'] == 'IP':
            try:
                result_dict = api.host(obj.ip)
            except shodan.APIError, e:
                logger.error('Shodan API Error (%s)' % e)
                self._error("Network connection error checking Shodan (%s)" % e)
                return

        if not result_dict:
            return

        # These are the keys we don't care about
        keys = ['data', 'ports', 'hostnames', 'vulns', 'ip_str']
        if obj._meta['crits_type'] == 'IP':
            for key, val in sorted(result_dict.iteritems()):
                if key not in keys:
                    stats = {'data': result_dict.get(key, 'n/a')}
                    if result_dict.get(key, 'n/a'):
                        self._add_result('General', key, stats)
            for item in result_dict.get('data'):
                stats = {'data': item.get('data', 'n/a'), 'type': 'port'}
                self._add_result('Banners', item.get('port', 'n/a'), stats) 

