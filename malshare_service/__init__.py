import logging
import os
import hashlib
import urllib
import urllib2
import urlparse

from hashlib import md5

from django.conf import settings
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError as DjangoValidationError

from crits.core.user_tools import get_user_info
from crits.services.core import Service, ServiceConfigError
from django.template.loader import render_to_string
from crits.samples.handlers import handle_file
from crits.vocabulary.acls import SampleACL

from . import forms

logger = logging.getLogger(__name__)


class MalShareService(Service):
    """
    Download samples from MalShare.
    """

    name = "malshare"
    version = '1.1'
    supported_types = ['Sample']
    description = "Download sample from MalShare."

    @staticmethod
    def parse_config(config):
        if not config['malshare_api_key']:
            raise ServiceConfigError("API key required.")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.MalShareConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        return {'malshare_api_key': config['malshare_api_key']}

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.MalShareConfigForm(initial=config),
                                 'config_error': None})
        form = forms.MalShareConfigForm
        return form, html

    def run(self, obj, config):
        key = config.get("malshare_api_key", "")
        self.obj = obj

        if obj.filedata.read():
            logger.info("File already exists, no need to download")
            self._info("File already exists, no need to download")
            return

        if not key:
            logger.error("No valid MalShare API key found")
            self._error("No valid MalShare API key found")
            return

        #Download URL: https://malshare.com/api.php?api_key=[API_KEY]&action=getfile&hash=[HASH]

        parameters = {"api_key": key, "action": "getfile", "hash": obj.md5}
        data = urllib.urlencode(parameters)
        req = urllib2.Request("http://malshare.com/api.php", data)

        logger.info("Connecting MalShare to download sample")
        self._info("Connecting MalShare to download sample")

        # Execute GET request
        if settings.HTTP_PROXY:
            proxy = urllib2.ProxyHandler({'http': settings.HTTP_PROXY})
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)
        try:
            response = urllib2.urlopen(req)
            sample_file = response.read()
        except Exception as e:
            logger.error("MalShare: network connection error (%s)" % e)
            self._error("Network connection error checking MalShare (%s)" % e)
            return

        logger.info("Download completed")
        self._info("Download completed")

        if sample_file.startswith("Sample not found by hash"):
            logger.error("Sample was not found on MalShare")
            self._error("Sample was not found on MalShare")
            return
        else:
            logger.info("Sample was found on MalShare!")
            self._info("Sample was found on MalShare!")

        #Verify file's MD5
        if (hashlib.md5(sample_file).hexdigest() != obj.md5):
            logger.error("Error while downloading sample from MalShare, MD5 missmatch")
            self._error("Error while downloading sample from MalShare, MD5 missmatch")
            return
        if not user.has_access_to(SampleACL.WRITE):
            self._info("User does not have permission to add Samples to CRITs")
            self._add_result("Download Canceled", "User does not have permission to add Samples to CRITs")
            return
        else:
            logger.info("MD5 verification successfull!")
            self._info("MD5 verification successfull!")
            #Write file
            #Filename is just the md5
            filename = obj.md5
            handle_file(filename, sample_file, obj.source,
                        related_id=str(obj.id),
                        related_type=str(obj._meta['crits_type']),
                        campaign=obj.campaign,
                        source_method=self.name,
                        user=self.current_task.user)
            self._add_result("file_downloaded", filename, {'md5': filename})
