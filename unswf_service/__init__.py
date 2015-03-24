# (c) 2015, Adam Polkosnik <adam.polkosnik@ny.frb.org> <apolkosnik@gmail.com>
#
import logging
import os
import io
import tempfile
import shutil
import zlib
import pylzma


import subprocess

# for computing the MD5
from hashlib import md5

# for adding the extracted files
from crits.samples.handlers import handle_file
# for adding the actionscript
from crits.raw_data.handlers import handle_raw_data_file

from django.conf import settings
from django.template.loader import render_to_string
from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)
class unswfService(Service):
     
    """
    Uncompress flash files.
    """
     
    name = "unswf"
    version = '0.0.5'
    supported_types = ['Sample']
    description = "Uncompress flash files."



    @staticmethod
    def parse_config(config):
        flare_path = config.get("flare_path", "")
        if not flare_path:
            raise ServiceConfigError("Must specify Flare path.")

        if not os.path.isfile(flare_path):
            raise ServiceConfigError("Flare path does not exist.")

        if not os.access(flare_path, os.X_OK):
            raise ServiceConfigError("Flare path is not executable.")

        if not 'flare' in flare_path.lower():
            raise ServiceConfigError("Executable does not appear to be Flare.")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.UnswfConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        return {'flare_path': config['flare_path']}

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.UnswfConfigForm(initial=config),
                                 'config_error': None})
        form = forms.UnswfConfigForm
        return form, html




    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")
        data = obj.filedata.read(4)
        if len(data) < 4:
            raise ServiceConfigError("Need at least 4 bytes.")
        # Reset the read pointer.
        obj.filedata.seek(0)
        'We only care about the flash files'
        if not data[:3] in ['FWS','CWS','ZWS']:
            raise ServiceConfigError("Not a valid Flash file.")


    def run(self, obj, config):
        self.config = config
        self.obj = obj
        data = io.BytesIO(obj.filedata.read())
        swf = bytearray()
        try:
            comp = data.read(3)
            header = data.read(5)
            if comp == 'CWS':
                swf = 'FWS' + header + zlib.decompress(data.read())
            if comp == 'ZWS':
                data.seek(12) # seek to LZMA props
                swf = 'FWS' + header + pylzma.decompress(data.read())
            if comp == 'FWS':
                data.seek(0)
                flare_path = config.get("flare_path", "")
                # Needed some special temp file, since Flare only
                #     accepts files with swf file extension
                tempdir = tempfile.mkdtemp()
                self.directory = tempdir
                tfile = os.path.join(tempdir, str(obj.id)+'.swf')
                rfile = os.path.join(tempdir, str(obj.id)+'.flr')
                (working_dir, filename) = os.path.split(tfile)
                with open(tfile, "wb") as f:
                    f.write(data.read())

                if os.path.isfile(tfile):
                    data.seek(0)
                    self._warning("data md5: %s "% md5(data.read()).hexdigest())
                    args = [flare_path, filename]
                    # Flare does not generate a lot of output, so we should not have to
                    # worry about this hanging because the buffer is full
                    proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd=working_dir)
                    # Note that we are redirecting STDERR to STDOUT, so we can ignore
                    # the second element of the tuple returned by communicate().
                    output = proc.communicate()[0]
                    self._warning("Flare output: %s" % output)
                    if proc.returncode:
                        msg = ("Flare could not process the file.")
                        self._warning(msg)
                        return
                    with open(rfile, "rb") as newfile:
                       ac3 = newfile.read()
                    h3 = md5(ac3).hexdigest()
                    # clean up the temp files and folders  
                    if os.path.isdir(self.directory):
                        shutil.rmtree(self.directory)
                    res = handle_raw_data_file(ac3, self.obj.source, self.current_task.username,
                        title="Flare", data_type='text',
                        tool_name='Flare', tool_version='0.6', tool_details='http://www.nowrap.de/flare.html',
                        method=self.name, 
                        copy_rels=True) 
                    self._add_result("file_added", rfile, {'md5': h3})
                    self._warning(res)
        except Exception as exc:
                self._error("unswf: (%s)." % exc)
                return
        if swf:
            h = md5(str(swf)).hexdigest()
            name = h
            self._info("New file: %s (%d bytes, %s)" % (name, len(swf), h))
            handle_file(name, swf, self.obj.source,
                related_id=str(self.obj.id),
                campaign=self.obj.campaign,
                method=self.name,
                relationship='Related_To',
                user=self.current_task.username)
            self._add_result("file_added", name, {'md5': h})


