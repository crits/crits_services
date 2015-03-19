# (c) 2015, Adam Polkosnik <adam.polkosnik@ny.frb.org>
#
import logging
import os
import zlib
import lzma

from django.conf import settings
from django.template.loader import render_to_string
from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)
class clamdService(Service):
     
    """
    Uncompress flash files.
    """
     
    name = "unswf"
    version = '0.0.1'
    supported_types = ['Sample']
    description = "Uncompress flash files."

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")
        data = obj.filedata.read(4)
        if len(data) < 4:
            raise ServiceConfigError("Need at least 4 bytes.")
        # Reset the read pointer.
        obj.filedata.seek(0)
        'We only care about the compressed flash files'
        if not data[:3] in ['CWS','ZWS']:
            raise ServiceConfigError("Not a valid compressed Flash file.")

# Format of SWF when LZMA is used:
#
# | 4 bytes | 4 bytes | 4 bytes | 5 bytes | n bytes | 6 bytes |
# | 'ZWS'+version | scriptLen | compressedLen | LZMA props | LZMA data | LZMA end marker |
#
# scriptLen is the uncompressed length of the SWF data. Includes 4 bytes SWF header and
# 4 bytes for scriptLen it
#
# compressedLen does not include header (4+4+4 bytes) or lzma props (5 bytes)
# compressedLen does include LZMA end marker (6 bytes)

    def run(self, obj, config):
        data = obj.filedata.read()
        try:
        comp = data.read(3)
        header = data.read(5)
        if comp == 'CWS':
            swf = 'FWS' + header + zlib.decompress(data.read())
        if comp == 'ZWS':
            data.seek(8+4) # seek to LZMA props
            swf = 'FWS' + header + lzma.decompress(data.read())
        except Exception:
                self._error("unswf: failed.")
                return

        if swf:
            h = md5(swf).hexdigest()
            name = h
            self._info("New file: %s (%d bytes, %s)" % (name, len(swf), h))
            handle_file(name, data, self.obj.source,
                related_id=str(self.obj.id),
                campaign=self.obj.campaign,
                method=self.name,
                relationship='Related_To',
                user=self.current_task.username)
            self._add_result("file_added", name, {'md5': h})


