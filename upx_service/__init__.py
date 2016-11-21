import logging
import os
import subprocess
import hashlib

from django.template.loader import render_to_string

from crits.core.user_tools import get_user_info
from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file
from crits.vocabulary.relationships import RelationshipTypes
from crits.vocabulary.acls import SampleACL

from . import forms

logger = logging.getLogger(__name__)


class UpxService(Service):
    """
    Attempt to unpack a binary using UPX.
    """

    name = "upx"
    version = '1.0.3'
    supported_types = ['Sample']
    description = "Unpack a binary using UPX."

    @staticmethod
    def parse_config(config):
        upx_path = config.get("upx_path", "")
        if not upx_path:
            raise ServiceConfigError("Must specify UPX path.")

        if not os.path.isfile(upx_path):
            raise ServiceConfigError("UPX path does not exist.")

        if not os.access(upx_path, os.X_OK):
            raise ServiceConfigError("UPX path is not executable.")

        if not 'upx' in upx_path.lower():
            raise ServiceConfigError("Executable does not appear to be UPX.")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.UPXConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        return {'UPX binary': config['upx_path']}

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.UPXConfigForm(initial=config),
                                 'config_error': None})
        form = forms.UPXConfigForm
        return form, html

    def run(self, obj, config):
        upx_path = config.get("upx_path", "")

        user = self.current_task.user
        if not user.has_access_to(SampleACL.WRITE):
            self._info("User does not have permission to add Samples to CRITs")
            self._add_result("Unpacking Canceled", "User does not have permission to add Samples to CRITs")
            return

        # _write_to_file() will delete this file at the end of the "with" block.
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            args = [upx_path, "-q", "-d", filename]

            # UPX does not generate a lot of output, so we should not have to
            # worry about this hanging because the buffer is full
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd=working_dir)

            # Note that we are redirecting STDERR to STDOUT, so we can ignore
            # the second element of the tuple returned by communicate().
            output = proc.communicate()[0]
            self._debug(output)

            if proc.returncode:
                # UPX return code of 1 indicates an error.
                # UPX return code of 2 indicates a warning (usually, the
                # file was not packed by UPX).
                msg = ("UPX could not unpack the file.")
                self._warning(msg)
                return

            with open(tmp_file, "rb") as newfile:
                data = newfile.read()

            #TODO: check to make sure file was modified (new MD5), indicating
            # it was actually unpacked
            md5 = hashlib.md5(data).hexdigest()
            filename = md5 + ".upx"
            handle_file(filename, data, obj.source,
                        related_id=str(obj.id),
                        related_type=str(obj._meta['crits_type']),
                        campaign=obj.campaign,
                        method=self.name,
                        relationship=RelationshipTypes.PACKED_FROM,
                        user=self.current_task.user)
            # Filename is just the md5 of the data...
            self._add_result("file_added", filename, {'md5': filename})
