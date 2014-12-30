import logging

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)

class DiffieService(Service):
    """
    Display two Analysis Results side by side.
    """

    name = "diffie"
    version = '0.0.1'
    description = "Display two Analysis Results side by side."
    supported_types = []

    def run(self, obj, config):
        return
