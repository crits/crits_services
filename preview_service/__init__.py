# (c) 2015, Adam Polkosnik <adam.polkosnik@ny.frb.org> <apolkosnik@gmail.com>
#
# All rights reserved.
import logging
import os
import io
import subprocess

# for computing the MD5
from hashlib import md5
# for image conversion
from PIL import Image

# for adding the extracted files
from crits.screenshots.handlers import add_screenshot

from django.conf import settings
from django.template.loader import render_to_string
from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)


class previewService(Service):

    name = "preview"
    version = '0.0.3'
    supported_types = ['Sample']
    description = "Generate screenshots of PDF documents and other image files using Pillow library and pdftoppm from poppler-utils."

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
        fields = forms.previewConfigForm().fields
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
                                 'form': forms.previewConfigForm(initial=config),
                                 'config_error': None})
        form = forms.previewConfigForm
        return form, html

    @staticmethod
    def valid_for(obj):
        # Only run on PIL supported image files or PDF files
        if not obj.filedata:
            return False
        if obj.is_pdf():
            return True
        else:
            try:
                obj.filedata.seek(0)
                im = Image.open(io.BytesIO(obj.filedata.read()))
                obj.filedata.seek(0)
                if not im.format:
                    raise ServiceConfigError("Not supported image format")
                    return False
            except IOError as e:
                raise ServiceConfigError("Not supported image format or a PDF. %s" % str(e))
                return False
        return True

    def run(self, obj, config):
        self.config = config
        self.obj = obj
        if not obj.is_pdf():
            try:
                ofile = io.BytesIO()
                obj.filedata.seek(0)
                im = Image.open(io.BytesIO(obj.filedata.read()))
                # if it's a PNG, then let's convert it to something else and then back to PNG
                if im.format == 'PNG':
                    tfile = io.BytesIO()
                    im.save(tfile, 'TIFF')
                    tfile.seek(0)
                    Image.open(io.BytesIO(tfile.read())).save(ofile, 'PNG', optimize=True)
                else:
                    im.save(ofile,'PNG', optimize=True)
                obj.filedata.seek(0)
                ofile.seek(0)
                res = add_screenshot(description='Render of an image file', 
                                                         tags=None,
                                                         method=self.name,
                                                         source=obj.source,
                                                         reference=None, 
                                                         analyst=self.current_task.username, 
                                                         screenshot=ofile, 
                                                         screenshot_ids=None,
                                                         oid=obj.id, 
                                                         otype="Sample")
                if res.get('message') and res.get('success') == True:
                    self._warning("res-message: %s id:%s" % (res.get('message'), res.get('id') ) ) 
            except IOError as e:
                self._error("Exception while reading: %s" % str(e))
            self._add_result('preview', res.get('id'), {'Message': res.get('message')})
            return
        else:
            self._debug("preview started\n")
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
                            self._warning("res-message: %s id:%s" % (res.get('message'), res.get('id') ) )
                            self._add_result('preview', res.get('id'), {'Message': res.get('message')})
                        self._warning("id:%s, file: %s" % (res.get('id'), os.path.join(working_dir,filen)))
                # Note that we are redirecting STDERR to STDOUT, so we can ignore
                # the second element of the tuple returned by communicate().
                self._warning("Out:%s" % output)

                if proc.returncode:
                    msg = ("pdftoppm could not process the file.")
                    self._warning(msg)
                    return
        return

