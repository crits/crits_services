import time
import logging
import simplejson
import urllib2

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)


class FarsightService(Service):
    """
    Check the Farsight DNSDB.

    Requires an API key available from Farsight
    """

    name = "farsight_lookup"
    version = '1.0.0'
    supported_types = ['Domain', 'IP']
    required_fields = []
    description = "Look up a Domain or IP in Farsight"

    @staticmethod
    def save_runtime_config(config):
        del config['farsight_api_key']
        del config['farsight_api_url']

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.FarsightConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def parse_config(config):
        if not config['farsight_api_key']:
            raise ServiceConfigError("API key required.")
        if not config['farsight_api_url']:
            raise ServiceConfigError('API url required.')

    @classmethod
    def generate_config_form(self, config):
        # Convert sigfiles to newline separated strings
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.FarsightConfigForm(initial=config),
                                 'config_error': None})
        form = forms.FarsightConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.FarsightConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    def run(self, obj, config):
        key = config.get('farsight_api_key', '')
        url = config.get('farsight_api_url', '')
 
        if not key:
            self._error("No valid Farsight key found")
            return

        if obj._meta['crits_type'] == 'IP':
            url = '%s/lookup/rdata/ip/%s' % (url,obj.ip)
        elif obj._meta['crits_type'] == 'Domain':
            url = '%s/lookup/rrset/name/%s' % (url, obj.domain)

        req = urllib2.Request(url, headers={'X-API-Key' : '%s' % key, 'Accept': 'application/json'})
        
        if settings.HTTP_PROXY:
            proxy = urllib2.ProxyHandler({'https': settings.HTTP_PROXY})
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)
        try:
            response = urllib2.urlopen(req)
            res = []
            while True:
                line = response.readline()
                if not line:
                    break
                res.append(simplejson.loads(line))
        
        except Exception as e:
            logger.error("Farsight: network connection error (%s)" % e)
            self._error("Network connection error checking Farsight (%s)" % e)
            return

        if not res:
            return

        for itm in res:
            if obj._meta['crits_type'] == 'IP':
                stats = {
                      'Count': itm.get('count', 'n/a'),
                      'Record Type': itm.get('rrtype', 'n/a'),
                      'First Time': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(itm.get('time_first', 'n/a'))),
                      'Last Time': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(itm.get('time_last', 'n/a')))
                    }
                self._add_result('General', itm.get('rrname', 'n/a.')[:-1],  stats)
            if obj._meta['crits_type'] == 'Domain':
                if itm.get('rrtype', 'n/a') == 'NS':
                    stats = {
                        'Count': itm.get('count', 'n/a'),
                        'Record Type': itm.get('rrtype', 'n/a'),
                        'First Time': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(itm.get('zone_time_first', itm.get('time_first')))),
                        'Last Time': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(itm.get('zone_time_last', itm.get('time_last')))),
                      }
                    data = []
                    for d in itm.get('rdata'):
                        data.append(d[:-1])
                    stats['Data'] = ','.join(data)
                    self._add_result('General', itm.get('rrname', 'n/a')[:-1], stats)
                if itm.get('rrtype', 'n/a') == 'A':
                    stats = {
                        'Count': itm.get('count', 'n/a'),
                        'Record Type': itm.get('rrtype', 'n/a'),
                        'First Time': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(itm.get('time_first', 'n/a'))),
                        'Last Time': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(itm.get('time_last', 'n/a'))),
                      }
                    data = []
                    for d in itm.get('rdata'):
                        data.append(d[:-1])
                    stats['Data'] = ','.join(data)
                    self._add_result('General', itm.get('rrname', 'n/a.')[:-1],  stats)
