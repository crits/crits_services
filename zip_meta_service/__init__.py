from crits.services.core import Service, ServiceConfigOption
from zip_meta import ZipParser

class ZipMetaService(Service):
    """
    Parses meta data from Zip Files using a custom parser.
    """

    name = "zip_meta"
    version = '1.0.0'
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']

    @staticmethod
    def valid_for(context):
        # Only run on zip files
        if len(context.data) < 4:
            return false
        return context.data[:4] in [ZipParser.zipLDMagic, ZipParser.zipCDMagic]

    def _scan(self, context):
        zparser = ZipParser(context.data)
        parsedZip =  zparser.parseZipFile()
        if not parsedZip:
            self._error("Could not parse document as a zip file")
            return
        for cd in parsedZip:
            for name,value in cd.iteritems():
                if name == 'ZipExtraField':
                    continue
                name = {"Name" : name}
                if type(value) is list or type(value) is tuple:
                    for element in value:
                        self._add_result(cd["ZipFileName"], str(element), name)
                # Add way to handle dictionary.
                #if type(value) is dict: ...
                else:
                    self._add_result(cd["ZipFileName"], str(value), name)
            if cd["ZipExtraField"]:
                for dictionary in cd["ZipExtraField"]:
                    if dictionary["Name"] == "UnknownHeader":
                        for name,value in dictionary.iteritems():
                            name = {"Name" : name}
                            if name == "Data":
                                self._add_result(dictionary["Name"], name, name)
                            else:
                                self._add_result(dictionary["Name"], str(value), name)
                    else:
                        for name,value in dictionary.iteritems():
                            name = {"Name" : name}
                            self._add_result(dictionary["Name"], str(value), name)
            else:
                name = {"Name" : "ExtraField"}
                self._add_result(cd["ZipFileName"], "None", name)
    def _parse_error(self, item, e):
        self._error("Error parsing %s (%s): %s" % (item, e.__class__.__name__, e))
