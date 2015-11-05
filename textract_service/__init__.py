# (c) 2015, Adam Polkosnik <adam.polkosnik@ny.frb.org> <apolkosnik@gmail.com>
#
# All rights reserved.
import logging
import os
from datetime import datetime
import textract

#vocab stuff
from crits.vocabulary.relationships import RelationshipTypes
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


class textractService(Service):
    """
    EExtract text contained in documents and files.
    """

    name = "textract"
    version = '0.0.1'
    supported_types = ['Sample']
    description = "Extract text contained in documents and files."

    @staticmethod
    def valid_for(obj):
        if not obj.filedata:
            return False
        with self._write_to_file() as tmp_file:
            output = textract.process(tmp_file)
            if not output:
                return False

    def run(self, obj, config):
        obj.filedata.seek(0)
        data8 = obj.filedata.read(8)
        obj.filedata.seek(0)
        self.config = config
        self.obj = obj
        self._debug("textract started")
        # The _write_to_file() context manager will delete this file at the
        # end of the "with" block.
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            obj.filedata.seek(0)
            output = textract.process(tmp_file)            
            if output:
                raw_hash = md5(output).hexdigest()
                res = handle_raw_data_file(output, self.obj.source, self.current_task.username,
                            title="textract", data_type='text',
                            tool_name='textract', tool_version='0.1', tool_details='https://github.com/deanmalmgren/textract',
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
                                            analyst=self.current_task.username)
                    obj.save(username=self.current_task.username)
                    raw_obj.save(username=self.current_task.username)
                    self._warning("resy: %s" % (str(resy)) )
                    self._add_result("rawdata_added", raw_hash, {'md5': raw_hash})
            else:
                self._error("textract couldn't process the file.")
                return False
        return True

