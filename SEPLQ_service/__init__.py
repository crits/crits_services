# (c) 2015, Adam Polkosnik, <adam.polkosnik@ny.frb.org> || <apolkosnik@gmail.com>

import logging

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

# for logging, right ;-)
logger = logging.getLogger(__name__)

# for adding the extracted files
from crits.samples.handlers import handle_file

# For decoding and extracting the payloads 
from SEPLQ import ExtractPayloads
# for getting the filename
import ntpath
# to feed the file into CRITs
import io
# for computing the MD5
from hashlib import md5

class SEPLQService(Service):
    """
    Extractor for Symantec Central Quarantine files
    """

    name = "SEPLQ"
    version = '1.0.0'
    supported_types = ['Sample']
    description = "Extractor for Symantec Local Quarantine files"

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")
        data = obj.filedata.read()
        if len(data) < 4:
            raise ServiceConfigError("Need at least 4 bytes.")
        # Reset the read pointer.
        obj.filedata.seek(0)
        if not data[0:4] == b'\x90\x12\x00\x00':
            raise ServiceConfigError("Not a SEP Local Quarantine file")
        
    def run(self, obj, config):
        self.config = config
        self.obj = obj
        #self._doit(obj.filedata.read()[start_offset:end_offset], filters, analyze )
        #self._add_result('SEPLQ', "" % output, {'Value': output})
        datacq = bytearray(obj.filedata.read())
        (metaoutcsv, data) = ExtractPayloads(datacq)
        h = md5(data).hexdigest()
        name = h
	metaout = metaoutcsv.split(",")
        name = ntpath.basename(str(metaout[0]))
        fields = (
        "Filename",
	"Num Failed Remediations",
	"Num Legacy Infections",
	"Num Remediations",
	"Num Snapshots",
	"Record Type",
	"Remediations Type",
	"Restore To Orig Locn Unavailable",
	"Session Item Count",
	"Session Item Index",
	"Structure Version",
	"Extra Info (QF Time)",
	"Extra Info (SND Time)",
	"Extra Info (Unique ID",
	"Extra Info (VBin Time)",
	"Flags",
	"Full Path and LFN",
	"Log Line",
	"Record ID",
	"Size",
	"Storage Instance ID",
	"Storage Key",
	"Storage Name",
	"WDescription",
	"Timestamp (in local time)"
	)


	
        self._info("name: %s" % name )
        n = 0
        for i in metaout:
	    if i and i != 0 and i != "0" and i != "":
                self._info("meta: %s" % str(i))
                self._add_result('SEPLQ', str(i)) 
            n+=1
        self._info("New file: %s (%d bytes, %s)" % (name, len(data), h))
        handle_file(name, io.BytesIO(data).read(), self.obj.source,
                related_id=str(obj.id),
                campaign=obj.campaign,
                method=self.name,
                relationship='Related_To',
                user=self.current_task.username)
        self._add_result("file_added", name, {'md5': h})
