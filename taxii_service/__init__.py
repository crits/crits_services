import logging
import os

from django.template.loader import render_to_string

from crits.core.handlers import does_source_exist
from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)

class TAXIIClient(Service):
    """
    Send TAXII message to TAXII server.
    """

    name = "taxii_service"
    version = "2.0.1"
    supported_types = []
    required_fields = ['_id']
    description = "Send TAXII messages to a TAXII server."
    template = "taxii_service_results.html"

    @staticmethod
    def parse_config(config):
        # When editing a config we are given a string.
        # When validating an existing config it will be a list.
        # Convert it to a list of strings.
        certfiles = config.get('certfiles', [])
        if isinstance(certfiles, basestring):
            config['certfiles'] = [cf for cf in certfiles.split('\r\n')]

        hostname = config.get("hostname", "").strip()
        keyfile = config.get("keyfile", "").strip()
        certfile = config.get("certfile", "").strip()
        data_feed = config.get("data_feed", "").strip()
        errors = []
        if not hostname:
            errors.append("You must specify a TAXII Server.")
        if not keyfile:
            errors.append("You must specify a keyfile location.")
        if  not os.path.isfile(keyfile):
            errors.append("keyfile does not exist.")
        if not certfile:
            errors.append("You must specify a certfile location.")
        if  not os.path.isfile(certfile):
            errors.append("certfile does not exist.")
        if not data_feed:
            errors.append("You must specify a TAXII Data Feed.")
        if not certfiles:
            errors.append("You must specify at least one certfile.")
        for crtfile in config['certfiles']:
            try:
                (source, feed, filepath) = crtfile.split(',')
            except ValueError as e:
                errors.append("You must specify a source, feed name, and "
                              "certificate path for each source. (%s)" % str(e))
                break
            source.strip()
            feed.strip()
            filepath.strip()
            if not does_source_exist(source):
                errors.append("Invalid source: %s" % source)
            if  not os.path.isfile(filepath):
                errors.append("certfile does not exist: %s" % filepath)
        if errors:
            raise ServiceConfigError("\n".join(errors))

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.TAXIIServiceConfigForm().fields
        for name, field in fields.iteritems():
            # Convert sigfiles to newline separated strings
            if name == 'certfiles':
                display_config[field.label] = '\r\n'.join(config[name])
            else:
                display_config[field.label] = config[name]

        return display_config

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.TAXIIServiceConfigForm().fields
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
        config['certfiles'] = '\r\n'.join(config['certfiles'])
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.TAXIIServiceConfigForm(initial=config),
                                 'config_error': None})
        form = forms.TAXIIServiceConfigForm
        return form, html

    def run(self, obj, config):
        pass # Not available via old-style services.
