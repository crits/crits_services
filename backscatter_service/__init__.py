import logging

from backscatter import Backscatter

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from crits.vocabulary.indicators import IndicatorTypes

from . import forms

logger = logging.getLogger(__name__)


class BackscatterService(Service):
    """
    Check the Backscatter.io database to see if it contains this IP.

    Requires an API key available from backscatter.io
    """

    name = "backscatter"
    version = '1.0.0'
    supported_types = ['Indicator']
    required_fields = []
    description = "Look up an IP in Backscatter.io"

    # Saving for future use if the service needs runtime configuration
    #@staticmethod
    #def bind_runtime_form(analyst, config):
    #    return forms.BackscatterRunForm(config)
    #
    #@classmethod
    #def generate_runtime_form(self, analyst, config, crits_type, identifier):
    #    return render_to_string('services_run_form.html',
    #                            {'name': self.name,
    #                            'form': forms.BackscatterRunForm(),
    #                            'crits_type': crits_type,
    #                            'identifier': identifier})
    #
    #@staticmethod
    #def save_runtime_config(config):
    #    del config['api_key']
    #
    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.BackscatterConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def parse_config(config):
        if not config['api_key']:
            raise ServiceConfigError("API key required.")

    @classmethod
    def generate_config_form(self, config):
        # Convert sigfiles to newline separated strings
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.BackscatterConfigForm(initial=config),
                                 'config_error': None})
        form = forms.BackscatterConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.BackscatterConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    def run(self, obj, config):
        self.config = config
        self.obj = obj
        status = {'success': False, 'message': []}

        # Pull configuration and check to see if a key is presented
        key = config.get('api_key', '')
        if not key:
            self._error("No valid API key found")
            return

        # Use a proxy if necessary
        if settings.HTTP_PROXY:
            bs = Backscatter(api_key=key,
                             proxies={'http': settings.HTTP_PROXY,
                                      'https': settings.HTTP_PROXY})
        else:
            bs = Backscatter(api_key=key)

        # Validate the Indicator Type and query for IP information
        if obj._meta['crits_type'] == 'Indicator':
            if self.obj.ind_type in [IndicatorTypes.IPV4_ADDRESS]:
                # Get query data
                try:
                    query_data = bs.get_observations(query=self.obj.value, query_type='ip')
                    q = query_data.get('query', {})
                    r = query_data.get('results', {})
                    o = r.get('observations', [])
                    u = r.get('unique', {})
                    s = r.get('summary', {})

                    for k,v in q.iteritems():
                        self._add_result('Query Parameters', k, {'Value': v})

                    for k,v in s.iteritems():
                        self._add_result('Summary', k, {'Value': v})

                    for k,v in u.iteritems():
                        self._add_result('Unique', k, {'Value': ', '.join(v)})

                    # There can be many observations, assign a number to them to group by
                    c = 1
                    for ob in o:
                        for k,v in ob.iteritems():
                            self._add_result('Observation %s' % c, k, {'Value': v})
                        c += 1
                except Exception, e:
                    self._error("Unable to parse query results: %s" % e)

                # Get enrichment data
                try:
                    enrichment_data = bs.enrich(query=self.obj.value)
                    r = enrichment_data.get('results', {})
                    for k,v in r.iteritems():
                        self._add_result('Enrichment Results', k, {'Value': v})
                except Exception, e:
                    self._error("Unable to parse enrichment results: %s" % e)

        # Updating status information and returning
        if not status['message']:
            status['success'] =  True
            status['message'] = "Processed IP information."
        else:
            status['message'] = "\n".join(status['message'])

        return status
