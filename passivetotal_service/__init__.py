import logging
import json
import requests

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)

class PassiveTotalService(Service):
    """
    Check the PassiveTotal database to see if it contains this domain or IP

    This service reliess on a user's allowed searches within the PassiveTotal
    system which are earned through accurate domain/IP classifications

    Requires an API key available from passivetotal.org
    """

    name = "passivetotal_lookup"
    version = '1.0.0'
    supported_types = [ 'Domain', 'IP' ]
    description = "Lookup a Domain or IP in PassiveTotal."

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.PassiveTotalConfigForm().fields
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

        # Rename keys so they render nice.
        fields = forms.PassiveTotalConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.PassiveTotalConfigForm(initial=config),
                                 'config_error': None})
        form = forms.PassiveTotalConfigForm
        return form, html

    @staticmethod
    def save_runtime_config(config):
        del config['pt_api_key']

    def run(self, obj, config):
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        apiKey = config.get('pt_api_key', '')
        queryUrl = config.get('pt_query_url', '')

        if not apikey:
            self._error("PassiveTotal API key is invalid or blank")

        if obj._meta['crits_type'] == 'Domain':
            params = { 'value': obj.domain, 'apiKey': apiKey }
        elif obj._meta['crits_type'] == 'IP':
            params = { 'value': obj.ip, 'apiKey': apiKey }
        else:
            logger.error("PassiveTotal: Invalid type.")
            self._error("Invalid type.")
            return

        try:
            response = requests.post(queryUrl, params=params)
        except Exception as e:
            logger.error("PassiveTotal: network connection error (%s)" % e)
            self._error("Network connection error checking PassiveTotal (%s)" % e)
            return

        if response.status_code != 200:
            logger.error("Response status code: %s" % response.status_code)
            self._error("Response status code: %s" % response.status_code)
            return

        loaded = json.loads(response.content) # handling a valid response

        if not loaded['success']:
            logger.error("PassiveTotal: query error (%s)" % loaded['error'])
            self._error("PassiveTotal: query error (%s)" % loaded['error'])
            return

        if loaded['result_count'] == 0:
            return

        results = loaded['results']
        if obj._meta['crits_type'] == 'Domain':
            for resolve in results['resolutions']:
                stats = {
                    'value': results['focus'],
                    'first_seen': resolve['firstSeen'],
                    'last_seen': resolve['lastSeen'],
                    'source': ','.join(resolve['source']),
                    'as_name': resolve['as_name'],
                    'asn': resolve['asn'],
                    'country': resolve['country'],
                    'network': resolve['network']
                }
                self._add_result('Passive DNS Data', resolve['value'], stats)
        elif obj._meta['crits_type'] == 'IP':
            stats = {
                'as_name': results['as_name'],
                'asn': results['asn'],
                'country': results['country'],
                'firstSeen': results['firstSeen'],
                'lastSeen': results['lastSeen'],
                'network': results['network']
            }
            self._add_result('Metadata', results['focus'], stats)
            for resolve in results['resolutions']:
                stats = {
                    'firstSeen': resolve['firstSeen'],
                    'lastSeen': resolve['lastSeen'],
                    'source': ','.join(resolve['source']),
                    'whois': resolve.get('whois', {})
                }
                self._add_result('Passive DNS Data', resolve['value'], stats)
