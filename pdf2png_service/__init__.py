# (c) 2015, Adam Polkosnik <adam.polkosnik@ny.frb.org> <apolkosnik@gmail.com>
#
# All rights reserved.
import logging
import os
import io
from datetime import datetime
import subprocess

# for computing the MD5
from hashlib import md5

# for adding the extracted files
# for adding the actionscript
from crits.screenshots.handlers import add_screenshot

from django.conf import settings
from django.template.loader import render_to_string
from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)


class pdf2pngService(Service):
    """
    Extract text contained in PDF documents using pdftoppm from poppler-utils.
    """

    name = "pdf2png"
    version = '0.0.2'
    supported_types = ['Sample']
    description = "Extract text contained in PDF documents using pdftoppm from poppler-utils."

    @staticmethod
    def parse_config(config):
        pdftoppm_path = config.get("pdftoppm_path", "")
        if not pdftoppm_path:
            raise ServiceConfigError("You must specify a valid path for pdftoppm.")

        if not os.path.isfile(pdftoppm_path):
            raise ServiceConfigError("pdftoppm path does not exist.")

        if not os.access(pdftoppm_path, os.X_OK):
            raise ServiceConfigError("pdftoppm path is not executable.")

        if not 'pdftoppm' in pdftoppm_path.lower():
            raise ServiceConfigError("Executable does not appear to be pdftoppm.")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.pdf2pngConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        return {'pdftoppm_path': config['pdftoppm_path']}

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.pdf2pngConfigForm(initial=config),
                                 'config_error': None})
        form = forms.pdf2pngConfigForm
        return form, html

    @staticmethod
    def valid_for(obj):
        # Only run on PDF files
        if not obj.is_pdf():
            raise ServiceConfigError("Not a valid PDF.")


    def run(self, obj, config):
        self.config = config
        self.obj = obj
        self._debug("pdf2png started\n")
        pdftoppm_path = self.config.get("pdftoppm_path", "/usr/bin/pdftoppm")
        # The _write_to_file() context manager will delete this file at the
        # end of the "with" block.
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            outy = 'page'
            args = [pdftoppm_path, '-png', tmp_file, outy]

            # pdftoppm does not generate a lot of output, so we should not have to
            # worry about this hanging because the buffer is full
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd=working_dir)
            output = proc.communicate()[0]
            for filen in sorted(os.listdir(working_dir)):
                if filen.endswith(".png"):
                    fileh = open(os.path.join(working_dir,filen), "rb")
                    raw_hash = md5(fileh.read()).hexdigest()
                    fileh.seek(0)
                    res = add_screenshot(description='Render of a pdf document', 
                                                         tags=None,
                                                         method=self.name,
                                                         source=obj.source,
                                                         reference=None, 
                                                         analyst=self.current_task.username, 
                                                         screenshot=fileh, 
                                                         screenshot_ids=None,
                                                         oid=obj.id, 
                                                         otype="Sample")
                    if res.get('message') and res.get('success') == True:
                        self._info("message: %s id:%s path: %s" % (res.get('message'), res.get('id'), os.path.join(working_dir,filen)))
            # Note that we are redirecting STDERR to STDOUT, so we can ignore
            # the second element of the tuple returned by communicate().
            self._info("Output:%s" % output)

            if proc.returncode:
                msg = ("pdftoppm could not process the file.")
                self._warning(msg)
                return
        return

