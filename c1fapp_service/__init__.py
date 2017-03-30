import logging
import json
import requests

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)


class C1fappService(Service):
    """
    Check the C1fapp database to see if it contains this domain or IP

    Requires an API key available from www.c1fapp.com
    """

    name = "c1fapp_lookup"
    version = '1.0.1'
    supported_types = ['Domain', 'IP']
    description = 'Look up a Domain or IP in C1fApp'

    @staticmethod
    def save_runtime_config(config):
        del config['cif_api_key']

    @staticmethod
    def parse_config(config):
        if not config['cif_api_key']:
            raise ServiceConfigError("API key required.")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.C1fappConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.C1fappConfigForm(initial=config),
                                 'config_error': None})
        form = forms.C1fappConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        display_config = {}

        fields = forms.C1fappConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    def run(self, obj, config):
        apikey = config.get('cif_api_key', '')
        queryUrl = config.get('cif_query_url', '')

        sources = []
        results = []

        if not apikey:
            self._error("C1fapp API key is invalid or blank")

        if obj._meta['crits_type'] == 'Domain':
            sources.append(obj.domain)
            params = {'backend': 'es', 'format': 'json',
                        'key': apikey, 'request': obj.domain}
            self._info("Looking address: %s" % obj.domain)

        elif obj._meta['crits_type'] == 'IP':
            sources.append(obj.ip)
            params = {'backend': 'es', 'format': 'json',
                        'key': apikey, 'request': obj.ip}
            self._info("Looking address: %s" % obj.ip)
        else:
            logger.error("C1fapp: Invalid type.")
            self._error("Invalid type.")
            return

        s = requests.Session()

        payload = json.dumps(params)

        cif_response = s.post(queryUrl, timeout=20, data=payload)
        try:
            assert cif_response.status_code == 200
            self._info("API Response status code: %s"
                       % cif_response.status_code)
        except AssertionError, e:
            cif_response.close()
            if cif_response.status_code == 403:
                self._error("API Response status code: %s"
                            % cif_response.status_code)
                self._error("C1fApp error: [%s]"
                            % cif_response.text)
            else:
                self._error("C1fApp error: [%s]" % e)
                self._error("API Response status code: %s"
                            % cif_response.status_code)

        cif_response.close()

        try:
            results = json.loads(cif_response.text)
        except Exception, e:
            self._info("No results could be decoded")

        if not results:
            self._info("No results returned")
            return

        try:
            for entry in results:
                _assessment = ""
                _source = ""
                _ip_entry = ""


                _assessment = []
                _source = []

                try:
                    for assessment_entry in entry['assessment']:
                        _assessment = " "+assessment_entry
                    for source_entry in entry['source']:
                        _source = " "+source_entry
                    for _ip_entry in entry['ip_address']:
                        _ip_address = " "+_ip_entry



                    stats = \
                        {

                            'domain': entry['domain'][0],
                            'description': entry['description'][0],
                            'source': _source,
                            'label': entry['feed_label'][0],
                            'assessment': _assessment,
                            'type': entry['derived'],
                            'ip_address': _ip_entry,
                            'country': entry['country'][0],
                            'ASN': entry['asn'][0],
                            'ASN_Desc': entry['asn_desc'][0],

                            'confidence': entry['confidence'][0],
                            'last_seen': entry['reportime'][0]

                        }
                    self._add_result('Enrichment Data', entry['address'][0], stats)
                except Exception,e:
                    pass


        except Exception, e:
            print e
