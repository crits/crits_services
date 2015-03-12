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

    def object_search(self, data, search_size=100):
        """
        Locate defined objects and references via defined tags
        @return dict of object types and object id's
        - Define regex or strings to locate PDF tags of interest

        Note: It is important that objects_str does not detect
            objects_regex items.

        TODO: Remove references that point to /Names entries.
        """
        oPDFParser = pdfparser.cPDFParser(data)
        done = False 
        objects = {}
        objects_regex = [('js', r'\/JavaScript\s(\d+)\s\d+\sR'),
                        ('js', r'\/JS\s(\d+)\s\d+\sR'),
                        ('file', r'\/F\s(\d+)\s\d+\sR')]

        objects_str = [('js', '/JavaScript\n'),
                        ('js', '/JavaScript\r\n'),
                        ('js', '/JS\n'),
                        ('js', '/JS\r\n'),
                        ('file', '/F\n'),
                        ('file', '/F\r\n')]

        while done == False:
            try:
                pdf_object = oPDFParser.GetObject()
            except Exception as e:
                pdf_object = None

            if pdf_object != None:
                if pdf_object.type in [pdfparser.PDF_ELEMENT_INDIRECT_OBJECT]:
                    #See if this PDF object has references to items of interest
                    rawContent = pdfparser.FormatOutput(pdf_object.content, True)
                    pdf_references = pdf_object.GetReferences()
                    if pdf_references:
                        #Match getReferences() with objects_regex results
                        for item in objects_regex:
                            matches = re.findall(item[1],rawContent[:search_size])
                            for match in matches:
                                for ref in list(pdf_references):
                                    #Record found items
                                    if match == ref[0]:
                                        pdf_references.remove(ref)
                                        if objects.get(item[0]):
                                            objects[item[0]].append(match)
                                        else:
                                            objects[item[0]] = [match]
                    #Find items within the current object.
                    for item in objects_str:
                        if pdf_object.Contains(item[1]):
                            if objects.get(item[0]):
                                objects[item[0]].append(str(pdf_object.id))
                            else:
                                objects[item[0]] = [str(pdf_object.id)]
            else:
                done = True
        return objects

    def run_pdfparser(self, data):
        """
        Uses pdf-parser to get information for each object.
        """        
        oPDFParser = pdfparser.cPDFParser(data)
        self._debug("Parsing document")
        done = False
        found_objects = {}

        found_objects = self.object_search(data)

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
                    else:
                        object_stream = False
                        stream_md5_digest = ''

                    object_references = []
                    for reference in pdf_object.GetReferences():
                        object_references.append(reference[0])
                    object_references = ','.join(object_references)

                    object_content = []
                    if found_objects.get('js'):
                        if str(pdf_object.id) in found_objects.get('js'):
                            object_content.append('JavaScript')
                    if found_objects.get('file'):
                        if str(pdf_object.id) in found_objects.get('file'):
                            object_content.append('EmbeddedFile')

                    result = {
                            "obj_id":           pdf_object.id,
                            "obj_version":      pdf_object.version,
                            "size":             len(rawContent),
                            "obj_md5":          section_md5_digest,
                            "type":             object_type,
                            "entropy":          section_entropy,
                            "content":          ','.join(object_content),
                            "x_refs":           object_references,
                            "stream":           object_stream,
                            "stream_md5":       stream_md5_digest,
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
