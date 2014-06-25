import hashlib
import logging

from crits.services.core import Service

import pdfparser
import math
import re
logger = logging.getLogger(__name__)


class PDFInfoService(Service):
    """
    Extract information about PDF files.

    Uses the PDFScanner tools from http://blog.didierstevens.com/programs/pdf-tools/
    to scan PDF files, extract metadata and create hashes of each object.
    """

    name = "pdfinfo"
    version = '1.1.2'
    type_ = Service.TYPE_CUSTOM
    description = "Extract information from PDF files."
    supported_types = ['Sample']

    @staticmethod
    def valid_for(obj):
        # Only run on PDF files
        return obj.is_pdf()

    def H(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x)))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy

    def _get_pdf_version(self, data):
        header_ver = re.compile('%PDF-([A-Za-z0-9\.]{1,3})[\r\n]', re.M)
        matches = header_ver.match(data)
        if matches:
            return matches.group(1)
        else:
            return "0.0"

    def _scan(self, obj):
        data = obj.filedata.read()
        self.object_summary = {
            'XRef':             0,
            'Catalog':          0,
            'ObjStm':           0,
            'Page':             0,
            'Metadata':         0,
            'XObject':          0,
            'Sig':              0,
            'Pages':            0,
            'FontDescriptor':   0,
            'Font':             0,
            'EmbeddedFile':     0,
            'StructTreeRoot':   0,
            'Mask':             0,
            'Group':            0,
            'Outlines':         0,
            'Action':           0,
            'Annot':            0,
            'Other_objects':    0,
            'Encoding':         0,
            'ExtGState':        0,
            'Pattern':          0,
            '3D':               0,
            'Total':            0,
            'Version':      '',
        }
        self.object_summary["Version"] = self._get_pdf_version(data[:1024])

        oPDFParser = pdfparser.cPDFParser(data)
        done = True
        self._debug("Parsing document")
        while done == True:
            try:
                pdf_object = oPDFParser.GetObject()
            except Exception as e:
                pdf_object = None
            if pdf_object != None:
                if pdf_object.type in [pdfparser.PDF_ELEMENT_INDIRECT_OBJECT]:
                    rawContent = pdfparser.FormatOutput(pdf_object.content, True)
                    section_md5_digest = hashlib.md5(rawContent).hexdigest()
                    section_entropy = self.H(rawContent)
                    object_type = pdf_object.GetType()
                    result = {
                            "obj_id":           pdf_object.id,
                            "obj_version":      pdf_object.version,
                            "size":             len(rawContent),
                            "md5":              section_md5_digest,
                            "type":             object_type,
                            "entropy":          section_entropy,
                    }
                    if object_type[1:] in self.object_summary:
                        self.object_summary[object_type[1:]] += 1
                    else:
                        self.object_summary["Other_objects"] += 1
                    self.object_summary["Total"] += 1
                    self._add_result('pdf_object', pdf_object.id, result)
            else:
                done = False
        for item in self.object_summary.items():
            item_str = "{0}: {1}".format(item[0], item[1])
            self._add_result('stats', item_str, {'type': item[0], 'count': item[1]})
    def _parse_error(self, item, e):
        self._error("Error parsing %s (%s): %s" % (item, e.__class__.__name__, e))
