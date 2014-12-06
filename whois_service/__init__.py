import logging
import requests
import pythonwhois

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms
from . import dtapi

logger = logging.getLogger(__name__)

class WHOISService(Service):
    """
    Request more information about an artifacts from WHOIS or pyDat.
    """

    name = "whois"
    version = '1.0.0'
    supported_types = [ 'Domain' ]
    template = 'whois_service_template.html'
    description = "Lookup WHOIS records for domains."

    @staticmethod
    def parse_config(config):
        # Must have both DT API key and DT Username or neither.
        if ((config['dt_api_key'] and not config['dt_username']) or
           (config['dt_username'] and not config['dt_api_key'])):
            raise ServiceConfigError("Must specify both DT API and username.")

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.WHOISConfigForm().fields
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
        fields = forms.WHOISConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.WHOISConfigForm(initial=config),
                                 'config_error': None})
        form = forms.WHOISConfigForm
        return form, html

    @staticmethod
    def save_runtime_config(config):
        if config['dt_api_key']:
            del config['dt_api_key']
        if config['dt_username']:
            del config['dt_username']

    @staticmethod
    def bind_runtime_form(analyst, config):
        form = forms.WHOISRunForm(pydat_url=config['pydat_url'],
                                  dt_api_key=config['dt_api_key'],
                                  data=config)
        return form

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        html = render_to_string("services_run_form.html",
                                {'name': self.name,
                                 'form': forms.WHOISRunForm(pydat_url=config['pydat_url'],
                                                            dt_api_key=config['dt_api_key']),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html

    # Live queries work well on the "bigger" TLDs. Using it on a .coop
    # results in hilarity because the parser misses everything.
    # This is a tough nut to crack.
    def do_live_query(self, obj, config):
        try:
            results = pythonwhois.get_whois(obj.domain)
        except pythonwhois.shared.WhoisException as e:
            self._error("Unable to find WHOIS information. %s" % str(e))
            return

        contacts = results.get('contacts', {})
        for contact_type in contacts.keys():
            # If not provided it defaults to None.
            if not contacts[contact_type]:
                continue
            for k, v in contacts[contact_type].iteritems():
                self._add_result("Live: " + contact_type + " Contact", v, {'Key': k})

        for ns in results.get('nameservers', []):
            self._add_result('Live: Nameservers', ns, {})

        for registrar in results.get('registrar', []):
            self._add_result('Live: Registrar', registrar, {})

        for key in ['creation_date', 'expiration_date', 'updated_date']:
            for date in results.get(key, []):
                if date:
                    self._add_result('Live: Dates', date, {'Type': key})

    def do_pydat_query(self, obj, config):
        # Check for trailing slash, because pydat.example.org//ajax is bad.
        base = config['pydat_url']
        if base[-1] != '/':
            base += '/'

        # Figure out how many versions exist
        url = base + 'ajax/domain/' + obj.domain

        r = requests.get(url)
        if r.status_code != 200:
            self._error("Response code not 200.")
            return

        results = r.json()
        if not results['success']:
            self._error(results['error'])
            return

        if results['total'] == 0:
            self._info("Metadata not found in pyDat")
            return

        link = base + 'domains/domainName/' + obj.domain
        self._info('pyDat URL: %s' % link)

        for data in results['data']:
            self._info('Version found: %s' % data['dataVersion'])

        url = base + 'ajax/domain/' + obj.domain + '/latest/'

        r = requests.get(url)
        if r.status_code != 200:
            self._error("Response code not 200.")
            return

        results = r.json()
        if not results['success']:
            self._error(results['error'])
            return

        if results['total'] == 0:
            self._info("No pyDat results found.")
            return

        for data in results['data']:
            for k, v in data.iteritems():
                # Don't add empty strings.
                if v:
                    self._add_result('pyDat Latest', v, {'Key': k})

    def do_dt_query(self, obj, config):
        dt = dtapi.dtapi(config['dt_username'], config['dt_api_key'])
        try:
            resp = dt.whois_parsed(obj.domain)
        except dtapi.DTError as e:
            self._info(str(e))
            return

        results = resp.json()
        results = results['response']['parsed_whois']

        contacts = results.get('contacts', {})
        for contact_type in contacts.keys():
            for k, v in contacts[contact_type].iteritems():
                if v:
                    self._add_result("DomainTools: " + contact_type + " Contact", v, {'Key': k})

        for key in ['created_date', 'expired_date', 'updated_date']:
            if results[key]:
                self._add_result('DomainTools: Dates', results[key], {'Key': key})

        for ns in results.get('nameservers', []):
            self._add_result('DomainTools: Nameservers', ns, {})

        registrar = results.get('registrar', {})
        for k, v in registrar.iteritems():
            if v:
                self._add_result('DomainTools: Registrar', v, {'Key': k})

    def run(self, obj, config):
        if config['live_query']:
            self.do_live_query(obj, config)

        if config['pydat_url'] and config['pydat_query']:
            self.do_pydat_query(obj, config)

        if config['dt_api_key'] and config['dt_username'] and config['dt_query']:
            self.do_dt_query(obj, config)
