import binascii

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from office_meta import OfficeParser
from . import forms

class OfficeMetaService(Service):
    """
    Parses meta data from Office documents using a custom parser.
    """

    name = "office_meta"
    version = '1.0.2'
    supported_types = ['Sample']
    description = "Parses metadata from Office documents."

    @staticmethod
    def valid_for(obj):
        office_magic = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        if obj.filedata != None:
            data = obj.filedata.read()
            # Need to reset the read pointer.
            obj.filedata.seek(0)
            if data.startswith(office_magic):
                return
        raise ServiceConfigError("Not a valid office document.")

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        html = render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.OfficeMetaRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html

    @staticmethod
    def bind_runtime_form(analyst, config):
        return forms.OfficeMetaRunForm(config)

    def scan(self, obj, config):
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
            name = curr_dir['norm_name'].decode('ascii', errors='ignore')
            self._add_result('directory', name, result)
            if config.get('save_streams', 0) == 1 and 'data' in curr_dir:
                self._add_file(curr_dir['data'],
                               name,
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
