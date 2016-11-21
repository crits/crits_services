# (c) 2016, Adam Polkosnik <adam.polkosnik@ny.frb.org> <apolkosnik@gmail.com>
#
# All rights reserved.
import logging
import os
from datetime import datetime
import subprocess

#vocab stuff
from crits.vocabulary.relationships import RelationshipTypes
# for computing the MD5
from hashlib import md5

from crits.core.user_tools import get_user_info
# for adding the extracted files
from crits.samples.handlers import handle_file
# for adding the actionscript
from crits.raw_data.handlers import handle_raw_data_file

from crits.core.class_mapper import class_from_id

from django.conf import settings
from django.template.loader import render_to_string
from crits.services.core import Service, ServiceConfigError
from crits.vocabulary.acls import RawDataACL

from . import forms

logger = logging.getLogger(__name__)


class pdf2txtService(Service):
    """
    Extract text contained in PDF, Word documents using Antiword and pdftotext from poppler-utils.
    """

    name = "pdf2txt"
    version = '0.0.3'
    supported_types = ['Sample']
    description = "Extract text contained in Word and PDF documents using Antiword and pdftotext from poppler-utils."

    @staticmethod
    def parse_config(config):
        pdf2txt_path = config.get("pdf2txt_path", "")
        if not pdf2txt_path:
            raise ServiceConfigError("You must specify a valid path for pdftotext.")

        antiword_path = config.get("antiword_path", "")
        if not antiword_path:
            raise ServiceConfigError("You must specify a valid path for antiword.")

        if not os.path.isfile(pdf2txt_path):
            raise ServiceConfigError("pdftotext path does not exist.")

        if not os.access(pdf2txt_path, os.X_OK):
            raise ServiceConfigError("pdftotext is not executable.")

        if not 'pdftotext' in pdf2txt_path.lower():
            raise ServiceConfigError("Executable does not appear to be pdftotext.")

        if not os.path.isfile(antiword_path):
            raise ServiceConfigError("antiword path does not exist.")

        if not os.access(antiword_path, os.X_OK):
            raise ServiceConfigError("antiword is not executable.")

        if not 'antiword' in antiword_path.lower():
            raise ServiceConfigError("Executable does not appear to be antiword.")

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
        return {'pdf2txt_path': config['pdf2txt_path'],
                'antiword_path': config['antiword_path']}

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
        if not obj.filedata:
            return False
        data = obj.filedata.read(8)
        obj.filedata.seek(0)
        if obj.is_pdf():
            return True
        elif data.startswith("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            # M$ Word document
            return True
        else:
            raise ServiceConfigError("Not a valid PDF or a Word document.")

    def run(self, obj, config):
        obj.filedata.seek(0)
        data8 = obj.filedata.read(8)
        obj.filedata.seek(0)
        user = self.current_task.user
        self.config = config
        self.obj = obj
        self._debug("pdf2txt started")
        pdf2txt_path = self.config.get("pdf2txt_path", "/usr/bin/pdftotext")
        antiword_path = self.config.get("antiword_path", "/usr/bin/antiword")
        # The _write_to_file() context manager will delete this file at the
        # end of the "with" block.
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            new_env = dict(os.environ)  # Copy current environment
            args = []
            obj.filedata.seek(0)
            if obj.is_pdf():
                self._debug("PDF")
                args = [pdf2txt_path, filename, "-"]
            elif data8.startswith("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                self._debug("Word")
                #new_env['LANG'] = 'en_US'
                #env=dict(os.environ, LANG="en_US")
                args = [antiword_path, '-r', '-s', '-t', filename]
            else:
                self._error("Not a valid PDF or Word document")
                return False

            if not user.has_access_to(RawDataACL.WRITE):
                self._info("User does not have permission to add Raw Data to CRITs")
                self._add_result("Parsing Cancelled", "User does not have permission to add Raw Data to CRITs")
                return
            # pdftotext does not generate a lot of output, so we should not have to
            # worry about this hanging because the buffer is full
            proc = subprocess.Popen(args, env=new_env, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, cwd=working_dir)
            # Note that we are redirecting STDERR to STDOUT, so we can ignore
            # the second element of the tuple returned by communicate().
            output, serr = proc.communicate()
            if serr:
                self._warning(serr)

            if proc.returncode:
                msg = ("pdftotext could not process the file.")
                self._warning(msg)
                return
            raw_hash = md5(output).hexdigest()

            res = handle_raw_data_file(output, self.obj.source, self.current_task.user,
                        title="pdftotext", data_type='Text',
                        tool_name='pdftotext', tool_version='0.1', tool_details='http://poppler.freedesktop.org',
                        method=self.name,
                        copy_rels=True)
            raw_obj = class_from_id("RawData", res["_id"])
            self._warning("obj.id: %s, raw_id:%s, suc: %s" % (str(obj.id), str(raw_obj.id), repr(res['success']) ) )
            # update relationship if a related top-level object is supplied
            rel_type = RelationshipTypes.RELATED_TO
            if obj.id != raw_obj.id: #don't form relationship to itself
                resy = obj.add_relationship(rel_item=raw_obj,
                                        rel_type=rel_type,
                                        rel_date=datetime.now(),
                                        analyst=self.current_task.user)
                obj.save(username=self.current_task.user.username)
                raw_obj.save(username=self.current_task.user.username)
                self._warning("resy: %s" % (str(resy)) )
                self._add_result("rawdata_added", raw_hash, {'md5': raw_hash})
        return
