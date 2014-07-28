import logging
import sys
import os

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)

class PyewService(Service):
    """
    Run a binary through the Pyew disassember.
    """

    name = "Pyew"
    version = '0.0.1'
    supported_types = ['Sample']
    description = "Run a binary through the Pyew disassembler."

    @staticmethod
    def parse_config(config):
        # Make sure basedir exists.
        pyew = config.get('pyew', '')
        if not os.path.exists(pyew):
                raise ServiceConfigError("Pyew does not exist.")

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.pyewConfigForm().fields
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
        fields = forms.pyewConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config


    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.pyewConfigForm(initial=config),
                                 'config_error': None})
        form = forms.pyewConfigForm
        return form, html

    def __init__(self, *args, **kwargs):
        pass

    def _scan(self, obj):
        pass

    def stop(self):
        pass
