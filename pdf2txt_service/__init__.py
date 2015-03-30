# (c) 2015, Adam Polkosnik <adam.polkosnik@ny.frb.org> <apolkosnik@gmail.com>
#
# All rights reserved.
import logging
import os
from datetime import datetime
import subprocess

# for computing the MD5
from hashlib import md5

# for adding the extracted files
from crits.samples.handlers import handle_file
# for adding the actionscript
from crits.raw_data.handlers import handle_raw_data_file

from crits.core.class_mapper import class_from_id

from django.conf import settings
from django.template.loader import render_to_string
from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)


class pdf2txtService(Service):
    """
    Extract text contained in PDF documents using pdftotext from poppler-utils.
    """

    name = "pdf2txt"
    version = '0.0.1'
    supported_types = ['Sample']
    description = "Extract text contained in PDF documents using pdftotext from poppler-utils."

    @staticmethod
    def parse_config(config):
        pdf2txt_path = config.get("pdf2txt_path", "")
        if not pdf2txt_path:
            raise ServiceConfigError("You must specify a valid path for pdftotext.")

        if not os.path.isfile(pdf2txt_path):
            raise ServiceConfigError("pdftotext path does not exist.")

        if not os.access(pdf2txt_path, os.X_OK):
            raise ServiceConfigError("pdftotext path is not executable.")

        if not 'pdftotext' in pdf2txt_path.lower():
            raise ServiceConfigError("Executable does not appear to be pdftotext.")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.pdf2txtConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        return {'pdf2txt_path': config['pdf2txt_path']}

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.pdf2txtConfigForm(initial=config),
                                 'config_error': None})
        form = forms.pdf2txtConfigForm
        return form, html

    @staticmethod
    def valid_for(obj):
        # Only run on PDF files
        if not obj.is_pdf():
            raise ServiceConfigError("Not a valid PDF.")


    def run(self, obj, config):
        self.config = config
        self.obj = obj
        self._debug("pdf2txt started\n")
        pdf2txt_path = self.config.get("pdf2txt_path", "/usr/bin/pdftotext")
        # The _write_to_file() context manager will delete this file at the
        # end of the "with" block.
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            args = [pdf2txt_path, filename, "-"]

            # pdftotext does not generate a lot of output, so we should not have to
            # worry about this hanging because the buffer is full
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd=working_dir)

            # Note that we are redirecting STDERR to STDOUT, so we can ignore
            # the second element of the tuple returned by communicate().
            output = proc.communicate()[0]
            self._debug(output)

            if proc.returncode:
                msg = ("pdftotext could not process the file.")
                self._warning(msg)
                return
            raw_hash = md5(output).hexdigest()
            res = handle_raw_data_file(output, self.obj.source, self.current_task.username,
                        title="pdftotext", data_type='text',
                        tool_name='pdftotext', tool_version='0.1', tool_details='http://poppler.freedesktop.org',
                        method=self.name,
                        copy_rels=True)
            raw_obj = class_from_id("RawData", res["_id"])
            self._warning("obj.id: %s, raw_id:%s, suc: %s" % (str(obj.id), str(raw_obj.id), repr(res['success']) ) )
            # update relationship if a related top-level object is supplied
            rel_type = "Related_To"
            if obj.id != raw_obj.id: #don't form relationship to itself
                resy = obj.add_relationship(rel_item=raw_obj,
                                        rel_type=rel_type,
                                        rel_date=datetime.now(),
                                        analyst=self.current_task.username)
                obj.save(username=self.current_task.username)
                raw_obj.save(username=self.current_task.username)
                self._warning("resy: %s" % (str(resy)) )
                self._add_result("rawdata_added", raw_hash, {'md5': raw_hash})
        return

