#!/usr/bin/env python
"""PassiveTotal CRITS Service."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__email__ = "admin@passivetotal.org"
__version__ = '2.0.1'

import logging
import sys

from . import forms
from crits.config.config import CRITsConfig
from crits.services.core import Service, ServiceConfigError
from django.template.loader import render_to_string
from future.utils import iteritems
from passivetotal.libs.dns import DnsResponse

logger = logging.getLogger(__name__)


def call_supported_types(supported=[]):
    """Decorator to check if the incoming query is supported by the func.

    The PassiveTotal service is designed to be extremely flexible and lets a
    user run the service across a number of different types. Defining the type
    checks inside of a decorator makes processing logic simple.

    :param supported: List of supported CRITS types.
    :return: Function call or a blank, logged response.
    """
    def _supported_types(f):
        def wrapper(self, *args):
            request_type = self.obj._meta['crits_type']
            if request_type not in supported:
                logger.warn("PassiveTotal: Invalid type.")
                self._warning("%s: Invalid type specified." % f.func_name)
                return
            return f(self, *args)
        return wrapper
    return _supported_types


class PassiveTotalService(Service):
    """Check PassiveTotal to see if there's any additional enrichment data.

    This service uses PassiveTotal to query for a number of different facets
    eminating from CRITs. At the time of creation, this service will support
    getting passive DNS, WHOIS, SSL certificates and other enrichment data.

    Requires an API key available from https://www.passivetotal.org
    """

    name = "passivetotal_lookup"
    version = '2.0.1'
    supported_types = ['Domain', 'IP', 'Indicator', 'SSL Certificate', 'Email']
    description = "Perform various services on a query value for the user."

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.PassiveTotalConfigForm().fields
        for name, field in iteritems(fields):
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def parse_config(config):
        if not config['pt_username']:
            raise ServiceConfigError("Username required.")
        if not config['pt_api_key']:
            raise ServiceConfigError("API key required.")

    @staticmethod
    def get_config_details(config):
        display_config = {}
        fields = forms.PassiveTotalConfigForm().fields
        for name, field in iteritems(fields):
            display_config[field.label] = config[name]
        return display_config

    @classmethod
    def generate_config_form(self, config):
        details = {
            'name': self.name,
            'form': forms.PassiveTotalConfigForm(initial=config),
            'config_error': None
        }
        html = render_to_string('services_config_form.html', details)
        form = forms.PassiveTotalConfigForm
        return form, html

    @staticmethod
    def save_runtime_config(config):
        config.pop('pt_username')
        config.pop('pt_api_key')
        config.pop('prompt_user')

    @staticmethod
    def bind_runtime_form(analyst, config):
        query_types = ['dns', 'whois', 'ssl', 'enrichment', 'malware', 'osint',
                       'tracker', 'component', 'subdomain', 'ssl_history',
                       'whois_email_search']
        for item in query_types:
            if item not in config:
                config[item] = True
        form = forms.PassiveTotalRuntimeForm(data=config)
        return form

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        if not config['prompt_user']:
            return None

        details = {
            'name': self.name,
            'form': forms.PassiveTotalRuntimeForm(),
            'crits_type': crits_type,
            'identifier': identifier
        }
        html = render_to_string("services_run_form.html", details)
        return html

    def _gen_label(self, item):
        """Generate a friendly looking label based on a string.

        :param item: Str value to clean up
        :return: Cleaned up label based on a key
        """
        output = list()
        for idx, chr in enumerate(item):
            if chr.isupper():
                output.append(' ')
            if idx == 0:
                chr = chr.upper()
            output.append(chr)
        return ''.join(output)

    def _get_query_type(self, obj):
        """Abstract the query type from the call."""
        if obj._meta['crits_type'] == 'Domain':
            query = obj.domain
        elif obj._meta['crits_type'] == 'IP':
            query = obj.ip
        elif obj._meta['crits_type'] == 'Indicator':
            query = obj.value
        elif obj._meta['crits_type'] == 'Email':
            query = list()
            for field in ['sender', 'to', 'from_address']:
                tmp = getattr(obj, field)
                if not tmp or tmp == '':
                    continue
                query.append(tmp)
        self._info("Query value passed along: %s." % str(query))
        return query

    def _generate_request_instance(self, request_type):
        """Automatically generate a request instance to use.

        In the end, this saves us from having to load each request class in a
        explicit way. Loading via a string is helpful to reduce the code per
        call.
        """
        crits_config = CRITsConfig.objects().first()

        http_proxy_value = None

        if crits_config.http_proxy:
            http_proxy_value = crits_config.http_proxy

        class_lookup = {'dns': 'DnsRequest', 'whois': 'WhoisRequest',
                        'ssl': 'SslRequest', 'enrichment': 'EnrichmentRequest',
                        'attributes': 'AttributeRequest'}
        class_name = class_lookup[request_type]
        mod = __import__('passivetotal.libs.%s' % request_type,
                         fromlist=[class_name])
        loaded = getattr(mod, class_name)
        headers = {'PT-INTEGRATION': 'CRITs'}
        authenticated = loaded(self.username, self.api_key, headers=headers,
            http_proxy=http_proxy_value, https_proxy=http_proxy_value)

        return authenticated

    def _check_response(self, response):
        """Make sure there aren't any errors on the response."""
        if 'error' in response:
            error = response.get('error', {})
            message = ("PassiveTotal: [HTTP %d] %s, %s" % (
                error.get('http_code', 500),
                error.get('message', 'Failed to grab message'),
                error.get('developer_message', 'Failed to grab message')
            ))
            logger.error(message)
            self._error(message)
            if error.get('http_code', 500) == 401:
                pt_site = 'https://www.passivetotal.org/enterprise'
                self._add_result('Invalid Authentication', pt_site,
                                 {'Message': message})
            if error.get('http_code', 500) == 403:
                pt_site = 'https://www.passivetotal.org/enterprise'
                self._add_result('Quota Reached', pt_site,
                                 {'Message': message})

    @call_supported_types(['Domain', 'IP', 'Indicator'])
    def do_pdns_query(self, obj):
        """Perform a passive DNS lookup on the query value."""
        client = self._generate_request_instance('dns')
        query = self._get_query_type(obj)
        results = client.get_passive_dns(query=query)
        self._check_response(results)
        results = DnsResponse(results)
        for record in results.get_records():
            stats = {
                'First Seen': record.firstSeen,
                'Last Seen': record.lastSeen,
                'Sources': ','.join(record.source)
            }
            self._add_result('Passive DNS', record.resolve, stats)

    @call_supported_types(['Domain', 'Indicator'])
    def do_whois_query(self, obj):
        """Perform a WHOIS lookup on the query value."""
        client = self._generate_request_instance('whois')
        query = self._get_query_type(obj)
        results = client.get_whois_details(query=query)
        self._check_response(results)
        top_level = ['registered', 'registryUpdatedAt', 'expiresAt',
                     'whoisServer', 'registrar', 'contactEmail']
        for field in top_level:
            self._add_result('WHOIS', results.get(field),
                             {'Key': self._gen_label(field)})
        for ns in results.get('nameServers', []):
            self._add_result('WHOIS', ns, {'Key': 'Nameserver'})
        for section in ['admin', 'tech', 'registrant']:
            for key, value in iteritems(results.get(section, {})):
                self._add_result('WHOIS Section %s' % section, value,
                                 {'Key': self._gen_label(key)})

    @call_supported_types(['Email', 'Indicator'])
    def do_whois_email_search(self, obj):
        """Perform a WHOIS email lookup on the query value."""
        client = self._generate_request_instance('whois')
        query = self._get_query_type(obj)
        field = 'email'
        if type(query) == list:
            for item in query:
                results = client.search_whois_by_field(query=item, field=field)
                self._check_response(results)
                for record in results.get('results', []):
                    stats = {'Registered': record.get('registered'),
                             'Updated': record.get('registryUpdatedAt'),
                             'Expires': record.get('expiresAt'),
                             'WHOIS Server': record.get('whoisServer'),
                             'Registrar': record.get('registrar')}
                    self._add_result('WHOIS Email %s' % item,
                                     record.get('domain'), stats)
        else:
            results = client.search_whois_by_field(query=query, field=field)
            self._check_response(results)
            for record in results.get('results', []):
                stats = {'Registered': record.get('registered'),
                         'Updated': record.get('registryUpdatedAt'),
                         'Expires': record.get('expiresAt'),
                         'WHOIS Server': record.get('whoisServer'),
                         'Registrar': record.get('registrar')}
                self._add_result('WHOIS Email %s' % query,
                                 record.get('domain'), stats)

    @call_supported_types(['IP', 'Indicator'])
    def do_ssl_query(self, obj):
        """Perform an SSL lookup on the query value."""
        client = self._generate_request_instance('ssl')
        query = self._get_query_type(obj)
        results = client.get_ssl_certificate_details(query=query)
        self._check_response(results)
        for key, value in iteritems(results):
            if not value or value == '':
                continue
            self._add_result("SSL Certificate", value,
                             {'Key': self._gen_label(key)})

    @call_supported_types(['IP', 'Indicator'])
    def do_ssl_history(self, obj):
        """Perform an SSL history lookup on the query value."""
        client = self._generate_request_instance('ssl')
        query = self._get_query_type(obj)
        results = client.get_ssl_certificate_history(query=query)
        self._check_response(results)
        for record in results.get('results', []):
            for ip in record.get('ipAddresses', []):
                stats = {'SHA-1': record.get('sha1'),
                         'First Seen': record.get('firstSeen'),
                         'Last Seen': record.get('lastSeen')}
            self._add_result("SSL Certificate History", ip, stats)

    @call_supported_types(['Domain', 'Indicator'])
    def do_subdomain_query(self, obj):
        """Perform a subdomain lookup on the query value."""
        client = self._generate_request_instance('enrichment')
        query = self._get_query_type(obj)
        results = client.get_subdomains(query=query)
        self._check_response(results)
        for sub in results.get('subdomains', []):
            full_domain = sub + "." + results.get('queryValue')
            self._add_result('Subdomains', full_domain)

    @call_supported_types(['Domain', 'Indicator', 'IP'])
    def do_enrichment_query(self, obj):
        """Perform enrichment on the query value."""
        client = self._generate_request_instance('enrichment')
        query = self._get_query_type(obj)
        results = client.get_enrichment(query=query)
        self._check_response(results)
        for key, value in iteritems(results):
            if not value or value == '':
                continue
            self._add_result("Enrichment", value,
                             {'Key': self._gen_label(key)})

    @call_supported_types(['Domain', 'Indicator', 'IP'])
    def do_tracker_query(self, obj):
        """Perform a tracker lookup on the query value."""
        client = self._generate_request_instance('attributes')
        query = self._get_query_type(obj)
        results = client.get_host_attribute_trackers(query=query)
        self._check_response(results)
        for record in results.get('results', []):
            stats = {
                'First Seen': record.get('firstSeen'),
                'Last Seen': record.get('lastSeen'),
                'Type': record.get('attributeType'),
                'Hostname': record.get('hostname')
            }
            self._add_result('Trackers', record.get('attributeValue'), stats)

    @call_supported_types(['Domain', 'Indicator', 'IP'])
    def do_component_query(self, obj):
        """Perform a component lookup on the query value."""
        client = self._generate_request_instance('attributes')
        query = self._get_query_type(obj)
        results = client.get_host_attribute_components(query=query)
        self._check_response(results)
        for record in results.get('results', []):
            stats = {
                'First Seen': record.get('firstSeen'),
                'Last Seen': record.get('lastSeen'),
                'Type': record.get('category'),
                'Hostname': record.get('hostname')
            }
            self._add_result('Components', record.get('label'), stats)

    @call_supported_types(['Domain', 'Indicator', 'IP'])
    def do_osint_query(self, obj):
        """Perform an OSINT lookup on the query value."""
        client = self._generate_request_instance('enrichment')
        query = self._get_query_type(obj)
        results = client.get_osint(query=query)
        self._check_response(results)
        for record in results.get('results', []):
            stats = {'URL': record.get('sourceUrl'),
                     'Tags': ', '.join(record.get('tags'))}
            for indicator in record.get('inReport', []):
                self._add_result('OSINT: %s' % record.get('source'),
                                 indicator, stats)

    @call_supported_types(['Domain', 'Indicator', 'IP'])
    def do_malware_query(self, obj):
        """Perform a malware lookup on the query value."""
        client = self._generate_request_instance('enrichment')
        query = self._get_query_type(obj)
        results = client.get_malware(query=query)
        self._check_response(results)
        for record in results.get('results', []):
            stats = {'Source': record.get('source'),
                     'URL': record.get('sourceUrl'),
                     'Collected': record.get('collectionDate')}
            self._add_result('Malware', record.get('sample'), stats)

    def run(self, obj, config):
        self.username = config.get('pt_username', '')
        self.api_key = config.get('pt_api_key', '')
        self.obj = obj
        self.config = config

        if not self.api_key or not self.username:
            self._error("PassiveTotal username or API key are blank")

        if config['dns'] or not config['prompt_user']:
            self.do_pdns_query(obj)
        if config['whois'] or not config['prompt_user']:
            self.do_whois_query(obj)
        if config['whois_email_search'] or not config['prompt_user']:
            self.do_whois_email_search(obj)
        if config['ssl'] or not config['prompt_user']:
            self.do_ssl_query(obj)
        if config['ssl_history'] or not config['prompt_user']:
            self.do_ssl_history(obj)
        if config['subdomain'] or not config['prompt_user']:
            self.do_subdomain_query(obj)
        if config['enrichment'] or not config['prompt_user']:
            self.do_enrichment_query(obj)
        if config['tracker'] or not config['prompt_user']:
            self.do_tracker_query(obj)
        if config['component'] or not config['prompt_user']:
            self.do_component_query(obj)
        if config['osint'] or not config['prompt_user']:
            self.do_osint_query(obj)
        if config['malware'] or not config['prompt_user']:
            self.do_malware_query(obj)
