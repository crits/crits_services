import logging
import json
import requests

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)

class ThreatreconService(Service):
    """
    Check the Threatrecon database to see if it contains this domain or IP

    Requires an API key available from threatrecon.co
    """

    name = "threatrecon_lookup"
    version = '1.0.0'
    supported_types = [ 'Domain', 'IP' ]
    description = 'Look up a Domain or IP in Threatrecon'

    @staticmethod
    def save_runtime_config(config):
        del config['tr_api_key']

    @staticmethod
    def parse_config(config):
        if not config['tr_api_key']:
            raise ServiceConfigError("API key required.")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.ThreatreconConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @classmethod
    def generate_config_form(self, config):
        # Convert sigfiles to newline separated strings
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.ThreatreconConfigForm(initial=config),
                                 'config_error': None})
        form = forms.ThreatreconConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.ThreatreconConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    def run(self, obj, config):
        apikey = config.get('tr_api_key', '')
        queryUrl = config.get('tr_query_url', '')

        if not apikey:
            self._error("Threatrecon API key is invalid or blank")

        if obj._meta['crits_type'] == 'Domain':
            params = { 'indicator': obj.domain, 'api_key': apikey }
        elif obj._meta['crits_type'] == 'IP':
            params = { 'indicator': obj.ip, 'api_key': apikey }
        else:
            logger.error("Threatrecon: Invalid type.")
            self._error("Invalid type.")
            return

        try:
            response = requests.post(queryUrl, params=params)
        except Exception as e:
            logger.error("Threatrecon: network connection error (%s)" % e)
            self._error("Network connection error checking Threatrecon (%s)" % e)
            return

        loaded = json.loads(response.content) # handling a valid response

        if loaded['ResponseCode'] == -1:
            logger.error("Threatrecon: query error (%s)" % loaded['Msg'])
            self._error("Threatrecon: query error (%s)" % loaded['Msg'])
            return

        if loaded['Results'] is None:
            return

        for results in loaded['Results']:
          stats = {
            'indicator': results['Indicator'],
            'attribution': results['Attribution'],
            'reference': results['Reference'],
            'confidence': results['Confidence'],
            'killchain': results['KillChain'],
            'id': results['Id'],
            'comment': results['Comment'],
            'processtype': results['ProcessType'],
            'source': results['Source'],
            'country': results['Country'],
            'rrname': results['Rrname'],
            'rrdata': results['Rdata'],
            'root_node': results['RootNode'],
            'first_seen': results['FirstSeen'],
            'last_seen': results['LastSeen'],
            'tags': results['Tags']
          }
          self._add_result('Enrichment Data', results['Indicator'], stats)
