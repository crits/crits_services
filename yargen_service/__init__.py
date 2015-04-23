import binascii
import logging
import os.path
import yara

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from crits.core.user import CRITsUser

from . import forms

logger = logging.getLogger(__name__)


class YarGenService(Service):
    """
    Generate Yara Signatures from multiple samples
    """

    name = "yargen_service"
    version = '0.0.1'
    description = "Generate Yara signatures from multiple samples."

    def run(self, obj, config):
        pass
        

