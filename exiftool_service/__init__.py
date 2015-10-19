import logging
import os
import subprocess
import hashlib
import json

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file
from crits.vocabulary.relationships import RelationshipTypes

from . import forms

logger = logging.getLogger(__name__)


class ExiftoolService(Service):
    """
    Extract EXIF and other metadata using Phil Harvey's exiftool.
    """

    name = "exiftool"
    version = '1.0'
    supported_types = ['Sample']
    description = "Run exiftool on a binary."

    @staticmethod
    def parse_config(config):
        exiftool_path = config.get("exiftool_path", "")
        if not exiftool_path:
            raise ServiceConfigError("Must specify exiftool path.")

        if not os.path.isfile(exiftool_path):
            raise ServiceConfigError("exiftool path does not exist.")

        if not os.access(exiftool_path, os.X_OK):
            raise ServiceConfigError("exiftool path is not executable.")

        if not 'exiftool' in exiftool_path.lower():
            raise ServiceConfigError("Executable does not appear to be exiftool.")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.ExiftoolConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        return {'exiftool binary': config['exiftool_path']}

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.ExiftoolConfigForm(initial=config),
                                 'config_error': None})
        form = forms.ExiftoolConfigForm
        return form, html

    def run(self, obj, config):
        exiftool_path = config.get("exiftool_path", "")

        #write out the sample stored in the db to a tmp file
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            args = [exiftool_path,'-json', filename]

            #Run exiftool binary
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd=working_dir)

            output = proc.communicate()[0]

            # exiftool will return its results in json, and it will be inside a single element list
            results = json.loads(output.decode('utf-8'))[0]
            for key,value in results.items():
                self._add_result("Metadata", key, {'Value': value})
