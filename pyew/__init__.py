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
        if existing_config:
            return existing_config

        config = {}
        fields = forms.pyewConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial
        return config

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
