import binascii

from crits.services.core import Service, ServiceConfigOption

from office_meta import OfficeParser


class OfficeMetaService(Service):
    """
    Parses meta data from Office documents using a custom parser.
    """

    name = "office_meta"
    version = '1.0.2'
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']
    default_config = [
        ServiceConfigOption('overwrite',
                            ServiceConfigOption.BOOL,
                            description="Whether the previous results should be overwritten."),
        ServiceConfigOption('save_streams',
                            ServiceConfigOption.BOOL,
                            description="Whether streams should be added as new samples."),
    ]

    @staticmethod
    def valid_for(obj):
        office_magic = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        if obj.filedata != None:
            data = obj.filedata.read()
            # Need to reset the read pointer.
            obj.filedata.seek(0)
            return office_magic in data
        return False

    def _scan(self, obj):
        oparser = OfficeParser(obj.filedata.read())
        oparser.parse_office_doc()
        if not oparser.office_header.get('maj_ver'):
            self._error("Could not parse file as an office document")
            return
        self._add_result('office_header', '%d.%d' %
            (oparser.office_header.get('maj_ver'), oparser.office_header.get('min_ver')))
        for curr_dir in oparser.directory:
            result = {
                'md5':          curr_dir.get('md5', ''),
                'size':         curr_dir.get('stream_size', 0),
                'mod_time':     oparser.timestamp_string(curr_dir['modify_time'])[1],
                'create_time':  oparser.timestamp_string(curr_dir['create_time'])[1],
            }
            self._add_result('directory', curr_dir['norm_name'], result)
            if self.config.get('save_streams', 0) == 1 and 'data' in curr_dir:
                self._add_file(curr_dir['data'],
                               curr_dir['norm_name'],
                               relationship="Extracted_From")
        for prop_list in oparser.properties:
            for prop in prop_list['property_list']:
                prop_summary = oparser.summary_mapping.get(binascii.unhexlify(prop['clsid']), None)
                prop_name = prop_summary.get('name', 'Unknown')
                for item in prop['properties']['properties']:
                    result = {
                        'name':             item.get('name', 'Unknown'),
                        'value':            item.get('date', item['value']),
                        'result':           item.get('result', ''),
                    }
                    self._add_result('doc_meta', prop_name, result)

    def _parse_error(self, item, e):
        self._error("Error parsing %s (%s): %s" % (item, e.__class__.__name__, e))
