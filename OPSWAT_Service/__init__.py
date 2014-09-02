import urllib2
import xml.parsers.expat

from datetime import datetime
from crits.core.mongo_tools import get_file
from crits.core.data_tools import create_zip

from crits.services.core import Service, ServiceConfigOption

class OPSWATService(Service):
    """
    Pushes a sample to your local OPSWAT appliance and scans the sample with different custom engines.
    Specify the URL for the REST API. Also include any API option in the URL.

    ie:http://example.org:8008/metascan_rest/scanner?method=scan&archive_pwd=infected'
    """

    name = "OPSWAT"
    version = "1.0.0"
    type_ = Service.TYPE_AV
    supported_types = ['Sample']
    default_config = [
        ServiceConfigOption('OPSWAT_url',
                            ServiceConfigOption.STRING,
                            description="URL for the OPSWAT REST API.",
                            default='http://example.org:8008/metascan_rest/scanner?method=scan&archive_pwd=infected',
                            required=True,
                            private=True),
        ServiceConfigOption('OPSWAT_proxy_on',
                            ServiceConfigOption.BOOL,
                            description="Use proxy for connecting to OPSWAT service",
                            private=True,
                            default=False),
    ]

    def _scan(self, context):
        data = get_file(context.md5)
        zipdata = create_zip([("samples", data)])
        url = self.config.get('OPSWAT_url', '')
        if not self.config.get('OPSWAT_proxy_on'):
            proxy_handler = urllib2.ProxyHandler({})
            opener = urllib2.build_opener(proxy_handler)
            urllib2.install_opener(opener)
        req = urllib2.Request(url)
        req.add_header("Content-Type", "application/zip")
        req.add_data(bytearray(zipdata))
        out = urllib2.urlopen(req)
        text_out = out.read()

        # Parse XML output
        handler = XMLTagHandler()
        parser = xml.parsers.expat.ParserCreate()
        parser.StartElementHandler = handler.StartElement
        parser.EndElementHandler = handler.EndElement
        parser.CharacterDataHandler = handler.CharData
        parser.Parse(text_out)

        for threat in handler.threatList:
            self._add_result('av_result', threat["threat_name"], {"engine":threat["engine_name"], "date":datetime.now().isoformat()})

class XMLTagHandler(object):
    def __init__(self):
        self.ResetFlags()
        self.threatList = []

    def ResetFlags(self):
        self.isEngineNameElement = 0
        self.isScanResultElement = 0
        self.isThreatNameElement = 0

        self.engineName = ""
        self.scanResult = ""
        self.threatName = ""

    def StartElement(self, name, attr):
        if name == "engine_result":
            self.ResetFlags()
        elif name == "engine_name":
            self.isEngineNameElement = 1
        elif name == "scan_result":
            self.isScanResultElement = 1
        elif name == "threat_name":
            self.isThreatNameElement = 1


    def EndElement(self, name):
        if name == "engine_result":
            if self.scanResult >= 1:
                self.threatList.append({"engine_name": self.engineName, "threat_name": self.threatName})
            else:
                self.threatList.append({"engine_name": self.engineName, "threat_name": ""})
        elif name == "engine_name":
            self.isEngineNameElement = 0
        elif name == "scan_result":
            self.isScanResultElement = 0
        elif name == "threat_name":
            self.isThreatNameElement = 0

    def CharData(self, data):
        if self.isEngineNameElement:
            self.engineName = data
        elif self.isScanResultElement:
            self.scanResult = int(data)
        elif self.isThreatNameElement:
            self.threatName = data
