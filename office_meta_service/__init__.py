import binascii
import hashlib

from django.template.loader import render_to_string

from crits.core.user_tools import get_user_info
from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file
from crits.vocabulary.relationships import RelationshipTypes
from crits.vocabulary.acls import SampleACL

from office_meta import OfficeParser
from . import forms

class OfficeMetaService(Service):
    """
    Parses meta data from Office documents using a custom parser.
    """

    name = "office_meta"
    version = '1.0.3'
    supported_types = ['Sample']
    description = "Parses metadata from Office documents."

    @staticmethod
    def get_config(existing_config):
        # This service no longer uses config options, so blow away any existing
        # configs.
        return {}

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

    def run(self, obj, config):
        oparser = OfficeParser(obj.filedata.read())
        oparser.parse_office_doc()
        added_files = []
        user = self.current_task.user
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
            if user.has_access_to(SampleACL.WRITE) and config.get('save_streams', 0) == 1 and 'data' in curr_dir:
                handle_file(name, curr_dir['data'], obj.source,
                            related_id=str(obj.id),
                            related_type=str(obj._meta['crits_type']),
                            campaign=obj.campaign,
                            source_method=self.name,
                            relationship=RelationshipTypes.CONTAINED_WITHIN,
                            user=self.current_task.user)
                stream_md5 = hashlib.md5(curr_dir['data']).hexdigest()
                added_files.append((name, stream_md5))
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
        for f in added_files:
            self._add_result("file_added", f[0], {'md5': f[1]})
