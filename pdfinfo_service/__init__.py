import hashlib
import logging
import math
import re
import json
import pdfparser
import pdfid

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file

from . import forms

logger = logging.getLogger(__name__)


class PDFInfoService(Service):
    """
    Extract information about PDF files.

    Uses the PDFScanner tools from http://blog.didierstevens.com/programs/pdf-tools/
    to scan PDF files, extract metadata and create hashes of each object.
    """

    name = "pdfinfo"
    version = '1.2.0'
    description = "Extract information from PDF files."
    supported_types = ['Sample']
    added_files = []

    @staticmethod
    def valid_for(obj):
        # Only run on PDF files
        if not obj.is_pdf():
            raise ServiceConfigError("Not a valid PDF.")

    @staticmethod
    def bind_runtime_form(analyst, config):
        if 'pdf_objects' not in config:
            config['pdf_objects'] = False
        return forms.PDFInfoRunForm(config)

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.PDFInfoRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    @staticmethod
    def get_config(existing_config):
        # There are no config options for this service, blow away any existing
        # configs.
        return {}

    def H(self, data):
        """
        Calculate entropy for provided data
        """
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x)))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy

    def _get_pdf_version(self, data):
        """
        Inspect PDF header and return version
        """
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
                pdf_summary = pdfid_dict['pdfid']['keywords']['keyword']
                for item in sorted(pdf_summary, key=lambda x: int(x['count']), reverse=True):
                    self._add_result('pdfid', item['name'], {'count':item['count']})
            except KeyError:
                pass
        else:
            pdf_summary = re.findall(r'<Keyword\sCount="([^\"]+)"[^>]+Name=\"([^\"]+)\"',xml_data.toxml())
            for count, item in sorted(pdf_summary, key=lambda x: int(x[0]), reverse=True):
                self._add_result('pdfid', item, {'count':count})

    def object_search(self, data, search_size=100):
        """
        Locate objects and references of interest
        @return dictionary containing object types and object id's
        - Use regex and strings to locate PDF tags of interest

        Note: It is important that objects_str definitions do 
            not detect objects found with objects_regex defs.
        """
        oPDFParser = pdfparser.cPDFParser(data)
        done = False 
        objects = {}
        objects_regex = [(r'js', r'\/JavaScript\s(\d+)\s\d+\sR'),
                        (r'js', r'\/JS\s(\d+)\s\d+\sR'),
                        (r'file', r'\/F\s(\d+)\s\d+\sR')]

        objects_str = [(r'js', '/JavaScript\n'),
                        (r'js', '/JavaScript\r\n'),
                        (r'js', '/JS\n'),
                        (r'js', '/JS\r\n'),
                        (r'file', '/F\n'),
                        (r'file', '/F\r\n'),]

        #Walk the PDF objects
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
                                for ref in pdf_references:
                                    #Record found items
                                    if match == ref[0]:
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
                    #Check object type
                    if pdf_object.GetType() == '/EmbeddedFile':
                        if objects.get('file'):
                            objects['file'].append(str(pdf_object.id))
                        else:
                            objects['file'] = [str(pdf_object.id)]
                    
            else:
                done = True
        return objects

    def add_objects(self, obj_id, reason, data):
        """
        Manage the insertion of child objects
        - Use signatures to filter/inspect embedded files
            - Fields: title, header, search window size
        """
        file_sigs = [('Flash', 'CWS', 50),
                    ('Flash', 'FWS', 50)]
        file_sigs_found = False

        #Filter/extract embedded files that are being submitted
        if reason == 'EmbeddedFile':
            for sig in file_sigs:
                search_header = sig[1]
                search_window = sig[2]
                offset = data[:search_window].find(search_header)
                if offset >= 0:
                    file_sigs_found = True
                    reason = '{} ({})'.format(reason, sig[0])
                    data = data[offset:]
                    break
            if file_sigs_found == False:
                return

        #Add object to addded_files list
        md5_digest = hashlib.md5(data).hexdigest()
        self.added_files.append([md5_digest,
                                obj_id,
                                len(data),
                                reason,
                                data])

    def run_pdfparser(self, data):
        """
        Uses pdf-parser to get information for each object.
        """        
        oPDFParser = pdfparser.cPDFParser(data)
        done = False
        found_objects = {}

        #Walk the PDF and inspect PDF objects
        found_objects = self.object_search(data)

        while done == False:
            try:
                pdf_object = oPDFParser.GetObject()
            except Exception as e:
                pdf_object = None

            if pdf_object != None:
                if pdf_object.type in [pdfparser.PDF_ELEMENT_INDIRECT_OBJECT]:
                    #Get general information for this PDF object
                    rawContent = pdfparser.FormatOutput(pdf_object.content, True)
                    section_md5_digest = hashlib.md5(rawContent).hexdigest()
                    section_entropy = self.H(rawContent)
                    object_type = pdf_object.GetType()

                    #Access data associated with this PDF object
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

                        #Stream returns list of object tags (not actual stream data)
                        if type(streamContent) == list:
                            streamContent = pdfparser.FormatOutput(pdf_object.content, True)
                            #Inspect pdf_object.content and extract raw stream
                            stream_start = streamContent.find('stream') + len('stream')
                            stream_end = streamContent.rfind('endstream')
                            if stream_start >= 0 and stream_end > 0:
                                streamContent = streamContent[stream_start:stream_end]

                        stream_md5_digest = hashlib.md5(streamContent).hexdigest()
                    else:
                        object_stream = False
                        stream_md5_digest = ''

                    #Collect references between this object and others
                    object_references = []
                    for reference in pdf_object.GetReferences():
                        object_references.append(reference[0])
                    object_references = ','.join(object_references)

                    #Get results from the object searching
                    object_content = []
                    if found_objects.get('js'):
                        if str(pdf_object.id) in found_objects.get('js'):
                            object_content.append('JavaScript')
                            #Submit JavaScript objects to CRITS
                            if object_stream:
                                self.add_objects('{} (stream)'.format(pdf_object.id),
                                                   'JavaScript',
                                                   streamContent)
                            else:
                                self.add_objects('{}'.format(pdf_object.id),
                                                   'JavaScript',
                                                   rawContent)
                    if found_objects.get('file'):
                        if str(pdf_object.id) in found_objects.get('file'):
                            object_content.append('EmbeddedFile')
                            #Submit (some) embedded files to CRITS
                            if object_stream:
                                self.add_objects('{} (stream)'.format(pdf_object.id),
                                                   'EmbeddedFile',
                                                   streamContent)
                            else:
                                self.add_objects('{}'.format(pdf_object.id),
                                                   'EmbeddedFile',
                                                   rawContent)

                    result = {
                            "obj_id":           pdf_object.id,
                            "obj_version":      pdf_object.version,
                            "size":             len(rawContent),
                            "type":             object_type,
                            "entropy":          section_entropy,
                            "content":          ','.join(object_content),
                            "x_refs":           object_references,
                            "stream":           object_stream,
                            "stream_md5":       stream_md5_digest,
                    }
                    self._add_result('pdf_parser', section_md5_digest, result)
            else:
                done = True

    def run(self, obj, config):
        """
        Run PDF service
        """
        data = obj.filedata.read()

        self._info('Sample PDF Version: {}'.format(self._get_pdf_version(data[:1024])))
        try:
            self._info('PDF Parser Version: {}'.format(pdfparser.__version__))
            self._info('PDFid Version: {}'.format(pdfid.__version__))
        except AttributeError:
            pass

        self.run_pdfid(data)
        self._notify()
        self.run_pdfparser(data)
        self._notify()

        #Add child objects
        if config['pdf_objects']:
            for f in self.added_files:
                self._info('{} {} {} {}'.format(f[0], f[1], f[2], f[3]))
                """
                handle_file(f[0], f[4], obj.source,
                            related_id=str(obj.id),
                            campaign=obj.campaign,
                            method=self.name,
                            relationship='Extracted_From',
                            user=self.current_task.username)
                self._add_result("pdf_objects_added", f[0], {'obj_id':f[1],'size': f[1],'reason': f[3]})
                """

    def _parse_error(self, item, e):
        self._error("Error parsing %s (%s): %s" % (item, e.__class__.__name__, e))
