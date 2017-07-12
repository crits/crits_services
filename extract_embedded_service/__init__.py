# (c) 2017, Lionel PRAT <lionel.prat9@gmail.com>
# based on service pdf2txt of Adam Polkosnik && meta_office => Thank!
# All rights reserved.
import logging
import hashlib
import shutil
import os
import tempfile
import re
from datetime import datetime
import subprocess

from django.template.loader import render_to_string

from crits.core.user_tools import get_user_info
from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file
from crits.vocabulary.relationships import RelationshipTypes
from crits.vocabulary.acls import SampleACL
from crits.core.class_mapper import class_from_id
from django.conf import settings
from django.template.loader import render_to_string

from . import forms

logger = logging.getLogger(__name__)


class ExtractEmbeddedService(Service):
    """
    Extract embedded files with clamscan.
    """

    name = "ExtractEmbedded"
    version = '0.0.1'
    supported_types = ['Sample']
    description = "Extract embedded files with clamscan."

    @staticmethod
    def parse_config(config):
        clamscan_path = config.get("clamscan_path", "")
        if not clamscan_path:
            raise ServiceConfigError("You must specify a valid path for clamscan.")
        if not os.path.isfile(clamscan_path):
            raise ServiceConfigError("clamscan path does not exist.")
        if not os.access(clamscan_path, os.X_OK):
            raise ServiceConfigError("clamscan is not executable.")
        if not 'clamscan' in clamscan_path.lower():
            raise ServiceConfigError("Executable does not appear to be clamscan.")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.ExtractEmbeddedConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        return {'clamscan_path': config['clamscan_path']}

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.ExtractEmbeddedConfigForm(initial=config),
                                 'config_error': None})
        form = forms.ExtractEmbeddedConfigForm
        return form, html

    @staticmethod
    def valid_for(obj):
        if not obj.filedata:
            return False
        #work for all types
        return True
        
    def run(self, obj, config):
        obj.filedata.seek(0)
        data8 = obj.filedata.read(8)
        obj.filedata.seek(0)
        user = self.current_task.user
        self.config = config
        self.obj = obj
        self._debug("ExtractEmbedded started")
        clamscan_path = self.config.get("clamscan_path", "/usr/bin/clamscan")
        #write out the sample stored in the db to a tmp file
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            new_env = dict(os.environ)  # Copy current environment
            args = []
            obj.filedata.seek(0)
            #make temp dir for extract embedded file
            dtmp = tempfile.mkdtemp()
            if os.path.isdir(dtmp):
                #create empty file for no check sig on file
                emptyrule_path = tempfile.gettempdir() + '/emptyrule.yar'
                if not os.path.isfile(emptyrule_path):
                    open(emptyrule_path, 'a').close()
                if os.path.isfile(emptyrule_path):
                    #TODO add filename filter for avoid escape shell
                    args = [clamscan_path, '--quiet', '--leave-temps', '--tempdir=' + dtmp, '-d', emptyrule_path, filename]
                    #verify user can write sample
                    acl_write = user.has_access_to(SampleACL.WRITE)
                    if not acl_write:
                        self._info("User does not have permission to add Sample Data to CRITs")
                    # pdftotext does not generate a lot of output, so we should not have to
                    # worry about this hanging because the buffer is full
                    proc = subprocess.Popen(args, env=new_env, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, cwd=working_dir)
                    # Note that we are redirecting STDERR to STDOUT, so we can ignore
                    # the second element of the tuple returned by communicate().
                    output, serr = proc.communicate()
                    #print stderr without message 'empty database file'
                    if serr:
                        if 'empty database file' not in serr:
                            self._warning(serr)
                    #run command problem
                    if proc.returncode:
                        msg = ("clamscan could not process the file.")
                        self._warning(msg)
                    #run command OK
                    else:
                        #get file in dtmp
                        regexp = re.compile(r'^clamav-[a-z0-9]{32}.tmp$')
                        for root, directories, filenames in os.walk(dtmp):
                            for filename in filenames:
                                #not clamav tmp
                                if not regexp.search(filename):
                                    #open and add
                                    with open(os.path.join(root,filename), 'r') as content_file_tmp:
                                        content_tmp = content_file_tmp.read()
                                        name = filename.decode('ascii', errors='ignore')
                                        stream_md5 = hashlib.md5(content_tmp).hexdigest()
                                        if acl_write:
                                            handle_file(name, content_tmp, obj.source,
                                                        related_id=str(obj.id),
                                                        related_type=str(obj._meta['crits_type']),
                                                        campaign=obj.campaign,
                                                        source_method=self.name,
                                                        relationship=RelationshipTypes.CONTAINED_WITHIN,
                                                        user=self.current_task.user)
                                            self._add_result('file_added', name, {'md5': stream_md5})
                                        else:
                                            #TODO print content for user cannot acces to write?
                                            self._add_result('file_embedded', name, {'md5': stream_md5})                   
                else:
                    msg = ("ExtractEmbedded cannot create emptyrule.yar.")
                    self._warning(msg)
                #remove temp dir
                shutil.rmtree(dtmp)
            else:
                msg = ("ExtractEmbedded cannot create temp dir.")
                self._warning(msg)
