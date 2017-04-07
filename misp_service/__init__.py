import binascii
import logging

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from crits.core.user import CRITsUser

from . import forms

logger = logging.getLogger(__name__)

class MISPService(Service):
    name = "misp_service"
    version = '0.0.1'
    description = "Send indicators to MISP."

    def __init__(self, *args, **kwargs):
        pass

    def _scan(self, obj):
        pass

    def stop(self):
        pass
        
    @staticmethod
    def parse_config(config):
        # When editing a config we are given a string.
        # When validating an existing config it will be a list.
        # Convert it to a list of strings.
        if not config['misp_url']:
            raise ServiceConfigError("MISP URL Required.")
        if not config['misp_key']:
            raise ServiceConfigError("MISP API Key Required.")
        default_tags = config.get('default_tags', [])
        if default_tags:
            if isinstance(default_tags, basestring):
                config['default_tags'] = [default_tag.strip() for default_tag in default_tags.split(',')]
                return config['default_tags']
    
    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.MispConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial
            
        # If there is a config in the database, use values from that
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config
        
    @staticmethod
    def get_config_details(config):
        display_config = {}
        
        # Rename keys so they render nice.
        fields = forms.MispConfigForm().fields
        for name, field in fields.iteritems():
            if name == 'default_tags':
                display_config[field.label] = ', '.join(config[name])
            else:
                display_config[field.label] = config[name]
        
        return display_config

    @classmethod
    def generate_config_form(self, config):
        # Convert default tags to comma-separated strings
        config['default_tags'] = ', '.join(config['default_tags'])
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                'form': forms.MispConfigForm(initial=config),
                                'config_error': None})
        form = forms.MispConfigForm
        return form, html