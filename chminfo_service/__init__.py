import os
import re
import hashlib
import tempfile
import HTMLParser
from chm import chm
from contextlib import contextmanager

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file

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

    item_string = {r'x-oleobject':'CHM contains reference to OLE Object.',
                    r'<script':'CHM contains JavaScript',
                    r'.savetofile':'CHM contains a function to save data to file',
                    r'document.write(':'CHM contains a function to save data to file.',
                    r'adodb.stream':'CHM creates ADO steam object for file access.',
                    r'msxml2.xmlhttp':'CHM uses an XHLHTTP object to create a network connection.',
                    r'System.Net.WebClient':'CHM uses the PowerShell WebClient class to create a network connection.',
                    r'cmd.exe':'CHM references Windows command prompt.',
                    r'cscript':'CHM references console scripting host.',
                    r'wscript':'CHM references Windows scripting host.',
                    r'rundll32':'CHM contains suspicious reference to Windows file.',
                    r'powershell':'CHM references PowerShell.',
                    r'end if':'CHM contains if statement.',
                    }
    item_regex = {r'<iframe\s.*src="([^\"]*)".*>':'CHM file creates an IFRAME',
                    r'<object\s[^>]+codebase=\"([^\"]*)\"':'CHM contains object that references external code',
                    r'<object\s[^>]+codebase=\'([^\"]*)\'':'CHM contains object that references external code',
                    r'<object\s[^>]+data=\"([^\"]*)\"':'CHM contains object that references external code',
                    r'<object\s[^>]+data=\'([^\"]*)\'':'CHM contains object that references external code',
                    r'createobject\(([^\)]*)':'CHM attempts to create an object',
                    r'.DownloadFile(([^\)]*)': 'CHM attempts to download a file',
                    r'.exec\(([^\)]*)':'CHM attempts to execute a file',
                    r'.shellexecute(([^\)]*)': 'CHM attempts to execute a file',
                }

    def __init__(self):
        """
        Initialize the CHMInfo service objects
        """
        self.chmparse = chm.CHMFile()
        self.urls = []
        self.items = []

    @staticmethod
    def valid_for(obj):
        chm_magic = '\x49\x54\x53\x46\x03\x00\x00\x00\x60\x00\x00\x00'
        if chmparse.filedata != None:
            data = obj.filedata.read()
            # Need to reset the read pointer.
            obj.filedata.seek(0)
            if data.startswith(office_magic):
                return
        raise ServiceConfigError("Not a valid ITSF (CHM) file.")

    @classmethod
    def find_items(self, data):
        """
        Find interesting CHM items using regex and strings
        - Inspects the pages within the CHM
        """
        results = []
        data = self.unescape(data).lower()
        for match, desc in self.item_regex.items():
            found = re.findall(match, data)
            if found:
                temp = desc + ' (' + found + ').'
                results.append(temp)

        for match, desc in self.item_string.items():
            if match in data:
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
                results.append(match)

        #String matches
        matches = re.findall(ip,data)
        for match in matches:
            if not match in results:
                results.append(match)
        return results

    @staticmethod
    def unescape(data):
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
        data = data.replace('\',\'','')
        data = data.replace('\",\"','')
        return data

    @classmethod
    def analyse(self):
        """
        Extract metadata and analyze the CHM file
        @return analysis results dictionary
        """
        obj_items = []
        obj_items_details = {}
        obj_items_summary = []
        locale_desc = ''

        locale_desc = chmparse.GetLCID()
        if locale_desc:
            locale_desc = ', '.join(local_desc)

        #Create a list of items within the CHM
        obj_items.append(chmparse.home)
        obj_items.append(chmparse.index)
        obj_items.append(chmparse.topics)
        obj_items = [x for x in obj_items if x is not None]

        #Analyse objects/pages in CHM
        for item in obj_items:
            fetch = chmparse.ResolveObject(item)
            if fetch[0] == 0:
                #Read data for object
                try:
                    item_details = chmparse.RetrieveObject(fetch[1])
                    if len(item_details) == 2:
                        data = item_details[1]
                        size = item_details[0]
                        md5_digest = hashlib.md5(data).hexdigest()
                        obj_items_details = {
                            'name':         item,
                            'size':         size,
                            'md5':          md5_digest,
                            'urls':         find_urls(data),
                            'detection':    find_items(data),
                        }
                        obj_item_summary.append(obj_items_details)
                    else:
                        self._error('RetrieveObject() did not return data for "{}".'.format(item))
                except Exception:
                    self._error('Analysis of item "{}" failed.'.format(item))

        result = {
            'title':                chmparse.title,
            'index':                chmparse.index,
            'binary_index':         chmparse.binaryindex,
            'topics':               chmparse.topics,
            'home':                 chmparse.home,
            'encoding':             chmparse.encoding,
            'locale_id':            chmparse.lcid,
            'locale_desc':          locale_desc,
            'searchable':           str(chmparse.searchable),
            'items':                ', '.join(obj_items),
            'obj_items_summary':    obj_items_summary,
        }
        chmparse.CloseCHM()
        return result

    @contextmanager
    def tempinput(data):
        """
        tempfile management
        """
        temp = tempfile.NamedTemporaryFile(delete=False)
        temp.write(data)
        temp.close()
        yield temp.name
        os.unlink(temp.name)

    def run(self, obj, config):
        """
        Being plugin processing
        """
        data = obj.filedata.read()

        with tempinput(data) as tempfilename:
            self.chmparse.LoadCHM(tempfilename)

        #Conduct analysis
        result = self.analyze()

        #Handle output of results
        if result.get('obj_items_summary'):
            obj_items_summary = result.pop('obj_items_summary')
        
        #General CHM info
        for key, value in result.items():
            self._add_result('chm_overview', (key + ": " + value), {})

        #URLs and IPs found in CHM
        for object_item in obj_items_summary:
            if object_item.get('urls'):
                for url in object_item.get('urls'):
                    self._add_result('chm_urls', url, {'item': object_item.get('name')})
                object_item.pop('urls')

        #Detection results from CHM analysis
        for object_item in obj_items_sumary:
            if object_item.get('detection'):
                for detection in object_item.get('detection'):
                    self._add_result('chm_detection', detection, {'item': object_item.get('name')})
                object_item.pop('detection')

        #Details of each object/page in the CHM
        for object_item in obj_items_summary:
            name = object_item.pop('name')
            self._add_result('chm_items', name, object_item)

    def _parse_error(self, item, e):
        self._error("Error parsing %s (%s): %s" % (item, e.__class__.__name__, e))
