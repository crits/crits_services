import hashlib
import logging

from crits.services.core import Service, ServiceConfigError

import pdfparser
import pdfid
import math
import re
import json

logger = logging.getLogger(__name__)


class PDFInfoService(Service):
    """
    Extract information about PDF files.

    Uses the PDFScanner tools from http://blog.didierstevens.com/programs/pdf-tools/
    to scan PDF files, extract metadata and create hashes of each object.
    """

    name = "pdfinfo"
    version = '1.1.2'
    description = "Extract information from PDF files."
    supported_types = ['Sample']

    @staticmethod
    def valid_for(obj):
        # Only run on PDF files
        if not obj.is_pdf():
            raise ServiceConfigError("Not a valid PDF.")

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

    def run_pdfid(self, data):
        """
        Uses PDFid to generate stats for the PDF
        - Display keyword matches
        """
        xml_json_success = True

        xml_data = pdfid.PDFiD(data)
        try:
            json_data = pdfid.PDFiD2JSON(xml_data,'')
            pdfid_dict = json.loads(json_data)[0]
        except UnicodeDecodeError:
            xml_json_success = False
        
        if xml_json_success:
            try:
                for item in pdfid_dict['pdfid']['keywords']['keyword']:
                    self._add_result('pdfid', item['name'], {'count':item['count']})
            except KeyError:
                pass
        else:
            for count, item in re.findall(r'<Keyword\sCount="([^\"]+)"[^>]+Name=\"([^\"]+)\"',xml_data.toxml()):
                self._add_result('pdfid', item, {'count':count})

    def js_ref_search(self, data):
        """
        Locate PDF objects that reference JavaScript
        @return list of object id's that contain JS
        - This could be achieved using PeePDF.
        """
        oPDFParser = pdfparser.cPDFParser(data)
        done = False 
        js_items = []

        while done == False:
            try:
                pdf_object = oPDFParser.GetObject()
            except Exception as e:
                pdf_object = None

            if pdf_object != None:
                if pdf_object.type in [pdfparser.PDF_ELEMENT_INDIRECT_OBJECT]:
                    rawContent = pdfparser.FormatOutput(pdf_object.content, True)
                    pdf_references = pdf_object.GetReferences()
                    if pdf_references:
                        #Search for JavaScript references and match with GetReferences()
                        tags = re.findall(r'\/JavaScript\s(\d+)\s\d+\sR',rawContent[:100])
                        tags += re.findall(r'\/JS\s(\d+)\s\d+\sR',rawContent[:100])
                        for tag in tags:
                            for ref in pdf_references:
                                if tag == ref[0]:
                                    js_items.append(tag)
                    else:
                        if (pdf_object.Contains('/JavaScript') | pdf_object.Contains('/JS')):
                            js_items.append(str(pdf_object.id))
            else:
                done = True
        return js_items               

    def run_pdfparser(self, data):
        """
        Uses pdf-parser to get information for each object.
        """        
        oPDFParser = pdfparser.cPDFParser(data)
        self._debug("Parsing document")
        done = False
        js_items = []

        #Walk objects and look for JavaScript
        js_items = self.js_ref_search(data)

        while done == False:
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

                    if pdf_object.ContainsStream():
                        object_stream = True
                        try:
                            #decompress stream using codec
                            streamContent = pdf_object.Stream() 
                        except Exception as e:
                            streamContent = "decompress failed."

                        if "decompress failed." in streamContent[:50]:
                            #Provide raw stream data
                            streamContent = pdf_object.Stream('')
                        stream_md5_digest = hashlib.md5(streamContent).hexdigest()
                        stream_entropy = self.H(streamContent)
                    else:
                        object_stream = False
                        streamContent = ''
                        stream_md5_digest = ''
                        stream_entropy = ''

                    object_references = []
                    for reference in pdf_object.GetReferences():
                        object_references.append(reference[0])
                    object_references = ','.join(object_references)

                    js_found = False
                    if str(pdf_object.id) in js_items:
                        js_found = True

                    result = {
                            "obj_id":           pdf_object.id,
                            "obj_version":      pdf_object.version,
                            "size":             len(rawContent),
                            "obj_md5":          section_md5_digest,
                            "type":             object_type,
                            "entropy":          section_entropy,
                            "javascript":       str(js_found),
                            "obj_references":   object_references,
                            "obj_stream":       object_stream,
                            "stream_md5":       stream_md5_digest,
                            "stream_entropy":   stream_entropy,
                    }
                    self._add_result('pdf_parser', pdf_object.id, result)
            else:
                done = True

    def run(self, obj, config):
        """
        Run PDF service
        """
        data = obj.filedata.read()
        self.object_summary = {}
        self.object_summary["PDF Version"] = self._get_pdf_version(data[:1024])

        try:
            self.object_summary["PDF Parser Version"] = pdfparser.__version__
            self.object_summary["PDFid Version"] = pdfid.__version__
        except AttributeError:
            pass

        for key, value in self.object_summary.items():
            self._add_result('pdf_overview', (key + ": " + value),{})

        self.run_pdfid(data)
        self.run_pdfparser(data)

    def _parse_error(self, item, e):
        self._error("Error parsing %s (%s): %s" % (item, e.__class__.__name__, e))
