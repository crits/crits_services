import os
import re
import hashlib
import tempfile
import HTMLParser
import logging
from chm import chm

from django.template.loader import render_to_string

from crits.core.user_tools import get_user_info
from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file
from crits.vocabulary.relationships import RelationshipTypes
from crits.vocabulary.acls import SampleACL

from . import forms

logger = logging.getLogger(__name__)

class CHMInfoService(Service):
    """
    Microsoft Compiled HTML Help file information service
    - Extract information from CHM
    - Provde details about suspicious behaviour within a CHM
    """
    name = "chminfo"
    version = '1.0.0'
    supported_types = ['Sample']
    description = "Generate information about Windows CHM files."
    added_files = []

    chmparse = chm.CHMFile()
    item_string = {r'x-oleobject':'CHM contains reference to OLE Object.',
                    r'<script':'CHM contains JavaScript.',
                    r'.savetofile':'CHM contains a function to save data to file.',
                    r'document.write(':'CHM contains a function to save data to file.',
                    r'adodb.stream':'CHM creates ADO steam object for file access.',
                    r'msxml2.xmlhttp':'CHM uses an XHLHTTP object to create a network connection.',
                    r'system.net.webclient':'CHM uses the PowerShell WebClient class to create a network connection.',
                    r'cmd.exe':'CHM references Windows Command Prompt (cmd).',
                    r'cscript':'CHM references Console Based Script Host (cscript).',
                    r'wscript':'CHM references Windows Based Script Host (wscript).',
                    r'rundll32':'CHM references Windows host process (rundll32).',
                    r'powershell':'CHM references Windows PowerShell.',
                    r'end if':'CHM contains \'if\' statement.',
                    }
    item_regex = {r'<iframe\s.*src="([^\"]*)".*>':'CHM file creates an IFRAME',
                    r'<object\s[^>]+codebase=\"([^\"]*)\"':'CHM contains object that references external code',
                    r'<object\s[^>]+codebase=\'([^\"]*)\'':'CHM contains object that references external code',
                    r'<object\s[^>]+data=\"([^\"]*)\"':'CHM contains object that references external code',
                    r'<object\s[^>]+data=\'([^\"]*)\'':'CHM contains object that references external code',
                    r'createobject\(([^\)]*)':'CHM attempts to create an object',
                    r'.downloadfile\(([^\)^,]*)': 'CHM attempts to download a file',
                    r'.exec\(([^\)]*)':'CHM attempts to execute a file',
                    r'.shellexecute\(([^\)]*)': 'CHM attempts to execute a file',
                }

    @staticmethod
    def valid_for(obj):
        chm_magic = '\x49\x54\x53\x46\x03\x00\x00\x00\x60\x00\x00\x00'
        if obj.filedata != None:
            data = obj.filedata.read()
            # Need to reset the read pointer.
            obj.filedata.seek(0)
            if data.startswith(chm_magic):
                return
        raise ServiceConfigError("Not a valid ITSF (CHM) file.")

    @staticmethod
    def bind_runtime_form(analyst, config):
        if 'chm_items' not in config:
            config['chm_items'] = False
        return forms.CHMInfoRunForm(config)

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.CHMInfoRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    @staticmethod
    def get_config(existing_config):
        # There are no config options for this service, blow away any existing
        # configs.
        return {}

    @classmethod
    def find_items(self, data):
        """
        Find interesting CHM items using regex and strings
        - Inspects the pages within the CHM
        """
        results = []
        data = self.unescape(data).lower()
        #Regex matching
        for match, desc in self.item_regex.items():
            found = re.findall(match.lower(), data)
            for res in found:
                temp = desc + ' (' + res + ').'
                results.append(temp)

        #String matching
        for match, desc in self.item_string.items():
            if match.lower() in data:
                results.append(desc)
        return results

    @classmethod
    def find_urls(self, data):
        """
        Extract URLs/IPs from document items
        - Inspects the pages within the CHM
        """
        results = []
        url = re.compile(ur'''(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s
            ()<>\'\"]+|\(([^\s()<>]+|(\([^\s()<>\'\"]+\)))*\))+(?:\(([^\s()<>\'\"]+|(\([^\s\(\)<>
            \'\"]+\)))*\)|[^\s`!()\[\]{};:\'\"\.,<>?\xab\xbb\u201c\u201d\u2018\u2019]))''')
        ip = re.compile(ur'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

        #Regex matches
        data = self.unescape(data)
        matches = re.findall(url,data)
        for match in matches:
            if not match in results:
                results.append(match[0])

        #String matches
        matches = re.findall(ip,data)
        for match in matches:
            if not match in results:
                results.append(match)
        return results

    @classmethod
    def unescape(self, data):
        """
        Unescape HTML code
        - Used to assist with inspection of document items
        """
        html_parser = HTMLParser.HTMLParser()
        try:
            data = data.decode('ascii','ignore')
            data = html_parser.unescape(data)
        except UnicodeDecodeError:
            self._error('HTMLParser library encountered an error when decoding Unicode characters.')
        return data

    @classmethod
    def analyze(self):
        """
        Extract metadata and analyze the CHM file
        @return analysis results dictionary
        """
        obj_items = set()
        obj_items_details = {}
        obj_items_summary = []
        locale_desc = ''

        locale_desc = self.chmparse.GetLCID()
        if locale_desc:
            locale_desc = ', '.join(locale_desc)

        #Create a list of items within the CHM
        obj_items.add(self.chmparse.home)
        obj_items.add(self.chmparse.index)
        obj_items.add(self.chmparse.topics)
        obj_items = [x for x in obj_items if x is not None]

        #Analyse objects/pages in CHM
        for item in obj_items:
            fetch = self.chmparse.ResolveObject(item)
            if fetch[0] == 0:
                #Read data for object
                try:
                    item_details = self.chmparse.RetrieveObject(fetch[1])
                    if len(item_details) == 2:
                        data = item_details[1]
                        size = item_details[0]
                        md5_digest = hashlib.md5(data).hexdigest()
                        obj_items_details = {
                            'name':         item,
                            'size':         size,
                            'md5':          md5_digest,
                            'urls':         self.find_urls(data),
                            'detection':    self.find_items(data),
                        }
                        obj_items_summary.append(obj_items_details)
                        self.added_files.append([item, size, md5_digest, data])
                    else:
                        self._error('RetrieveObject() did not return data for "{}".'.format(item))
                except Exception as e:
                    self._error('Analysis of item "{}" failed.'.format(item))
                    continue

        result = {
            'title':                self.chmparse.title,
            'index':                self.chmparse.index,
            'binary_index':         self.chmparse.binaryindex,
            'topics':               self.chmparse.topics,
            'home':                 self.chmparse.home,
            'encoding':             self.chmparse.encoding,
            'locale_id':            self.chmparse.lcid,
            'locale_description':   locale_desc,
            'searchable':           str(self.chmparse.searchable),
            'chm_items':            ', '.join(obj_items),
            'obj_items_summary':    obj_items_summary,
        }
        return result

    def run(self, obj, config):
        """
        Being plugin processing
        """
        #Load data from file as libchm will only accept a filename
        with self._write_to_file() as chm_file:
            try:
                self.chmparse.LoadCHM(chm_file)
            except Exception as e:
                raise e

        #Conduct analysis
        result = self.analyze()

        #Handle output of results
        if 'obj_items_summary' in result.keys():
            obj_items_summary = result.pop('obj_items_summary')

        #General CHM info
        for key, value in result.items():
            self._add_result('chm_overview', key, {'value': value})

        if config['chm_items']:
            #Data and details of each object/page in the CHM
            user = self.current_task.user
            if user.has_access_to(SampleACL.WRITE):
                for f in self.added_files:
                    handle_file(f[0], f[3], obj.source,
                                related_id=str(obj.id),
                                related_type=str(obj._meta['crits_type']),
                                campaign=obj.campaign,
                                source_method=self.name,
                                relationship=RelationshipTypes.CONTAINED_WITHIN,
                                user=self.current_task.user)
                    self._add_result("chm_items_added", f[0], {'size': f[1],'md5': f[2]})
            else:
                self._info("User does not have permission to add samples to CRITs.")
                self._add_result("chm_items_added","Items found but user does not have permission to add Samples to CRITs.")
        else:
            #Details of each object/page in the CHM
            for object_item in obj_items_summary:
                self._add_result('chm_items', object_item.get('name'),
                            {'size': object_item.get('size'),
                            'md5': object_item.get('md5')})

        #Detection results from CHM analysis
        for object_item in obj_items_summary:
            if object_item.get('detection'):
                for detection in object_item.get('detection'):
                    self._add_result('chm_detection', detection, {'chm_item': object_item.get('name')})

        #URLs and IPs found in CHM
        for object_item in obj_items_summary:
            if object_item.get('urls'):
                for url in object_item.get('urls'):
                    self._add_result('chm_urls', url, {'chm_item': object_item.get('name')})

        #Close file in memory
        self.chmparse.CloseCHM()
