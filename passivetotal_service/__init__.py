import logging
import requests

from django.conf import settings
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
    def parse_config(config):
        if not config['pt_api_key']:
            raise ServiceConfigError("API key required.")

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

    def make_request(self, url, params):
        if settings.HTTP_PROXY:
            proxies = { 'http': settings.HTTP_PROXY,
                        'https': settings.HTTP_PROXY }
        else:
            proxies = {}

        try:
            response = requests.get(url, params=params, proxies=proxies)
        except Exception as e:
            logger.error("PassiveTotal: network connection error (%s)" % e)
            self._error("Network connection error checking PassiveTotal (%s)" % e)
            return

        if response.status_code != 200:
            logger.error("Response status code: %s" % response.status_code)
            self._error("Response status code: %s" % response.status_code)
            return

        loaded = response.json()

        #if not loaded['success']:
        #    logger.error("PassiveTotal: query error (%s)" % loaded['error'])
        #    self._error("PassiveTotal: query error (%s)" % loaded['error'])
        #    return

        if loaded['result_count'] == 0:
            return

        return loaded

    def get_passive_results(self, type_):
        loaded = self.make_request(self.url + 'passive/', params=self.params)
        if not loaded:
            return

        results = loaded['results']
        for record in results['records']:
            stats = { 'First Seen': record['firstSeen'],
                      'Last Seen': record['lastSeen'],
                      'Sources': ','.join(record['source']) }
            self._add_result('Resolutions', record['resolve'], stats)

        if type_ == 'Domain':
            for (ip, count) in results['unique_resolutions'].iteritems():
                # For each resolution grab some stuff from the enrichment map
                enrichment = results['enrichment_map'][ip]
                stats = { 'Count': count,
                          'Sinkhole': enrichment['sinkhole'],
                          'Network': enrichment['network'],
                          'Country': enrichment['country'],
                          'ISP': enrichment['isp'],
                          'AS name': enrichment['as_name'],
                          'ASN': enrichment['asn'] }
                self._add_result('Unique Resolutions', ip, stats)
        elif type_ == 'IP':
            for (ip, count) in results['unique_resolutions'].iteritems():
                stats = { 'Count': count }
                self._add_result('Unique Resolutions', ip, stats)

    def get_subdomain_results(self):
        loaded = self.make_request(self.url + 'subdomains/', params=self.params)
        if not loaded:
            return

        results = loaded['results']
        for subdomain in results['subdomains'].keys():
            self._add_result('Subdomains', subdomain + '.' + self.params['query'])

    def run(self, obj, config):
        apikey = config.get('pt_api_key', '')
        self.url = config.get('pt_query_url', '')

        # Check for trailing slash, because passivetotal.org/api/v1//passive/ is bad.
        if self.url[-1] != '/':
            base += '/'

        if not apikey:
            self._error("PassiveTotal API key is invalid or blank")

        if obj._meta['crits_type'] == 'Domain':
            self.params = { 'query': obj.domain, 'api_key': apikey }
        elif obj._meta['crits_type'] == 'IP':
            self.params = { 'query': obj.ip, 'api_key': apikey }
        else:
            logger.error("PassiveTotal: Invalid type.")
            self._error("Invalid type.")
            return

        self.get_passive_results(obj._meta['crits_type'])

        # Get subdomains if object is Domain
        if obj._meta['crits_type'] == 'Domain':
            self.get_subdomain_results()
