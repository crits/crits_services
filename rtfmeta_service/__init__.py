import binascii
import hashlib

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file
from crits.vocabulary.relationships import RelationshipTypes

from rtf_parser import RtfParser
from . import forms

class RTFMetaService(Service):
    """
    Parses meta data from RTF documents using a custom parser.
    """

    name = "rtf_meta"
    version = '1.0.0'
    supported_types = ['Sample']
    description = "Parses metadata from RTF documents."

    @staticmethod
    def get_config(existing_config):
        # This service no longer uses config options, so blow away any existing
        # configs.
        return {}

    @staticmethod
    def valid_for(obj):
        rtf_magic = "{\\rt"
        if obj.filedata != None:
            data = obj.filedata.read()
            # Need to reset the read pointer.
            obj.filedata.seek(0)
            if data.startswith(rtf_magic):
                return
        raise ServiceConfigError("Not a valid rtf document.")

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        html = render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.RTFMetaRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html

    @staticmethod
    def bind_runtime_form(analyst, config):
        return forms.RTFMetaRunForm(config)

    def run(self, obj, config):
        rparser = RtfParser(obj.filedata.read())
        rparser.parse()
        added_files = []
        if not rparser.features.get('valid_rtf'):
            self._error("Could not parse file as an RTF document")
            return
        props = [
            'rtf_header_version',
            'rtf_generator',
            'ansi_code_page',
            'ansi_code_page_name',
            'deflang',
            'binary_ratio',
        ]
        for prop in props:
            value = rparser.features.get(prop)
            if value == None:
                continue
            result = {
                'name': prop,
                'value': value,
                'result': value,
            }
            self._add_result('rtf_meta', prop, result)
        for (k,v) in rparser.features.get('info', {}).items():
            result = {
                'name': k,
                'value': v,
                'result': v,
            }
            self._add_result('rtf_meta', prop, result)
        hashes = [
            'themedata',
            'blipuid',
            'colorschememapping',
            'rsids',
        ]
        for hash_type in hashes:
            items = rparser.features.get(hash_type, [])
            for item in items:
                result = {
                    'name': hash_type,
                    'value': item,
                    'result': item,
                }
                self._add_result('Item Hashes', hash_type, result)
        obj_num = 1
        for obj_info in rparser.features.get('objects', []):
            name = 'Object %d - %s' % (obj_num, obj_info.get('classname', 'Unknown'))
            for (k,v) in obj_info.items():
                val = hex(v) if type(v) == int else v
                result = {
                    'name': k,
                    'value': val,
                    'result': v,
                }
                self._add_result(name, name, result)
            obj_num += 1
        obj_num = 1
        for dstore in rparser.features.get('datastores', []):
            name = 'Datastore %d - %s' % (obj_num, dstore.get('classname', 'Unknown'))
            for (k,v) in dstore.items():
                val = hex(v) if type(v) == int else v
                result = {
                    'name': k,
                    'value': val,
                    'result': v,
                }
                self._add_result(name, name, result)
            obj_num += 1            
        if config.get('save_streams', 0) == 1:
            for i in range(len(rparser.objects)):
                stream_md5 = hashlib.md5(rparser.objects[i]).hexdigest()
                name = "Unknown object"
                for obj_info in rparser.features.get('objects', []):
                    if stream_md5 == obj_info.get('content_md5'):
                        name = "Object - %s" % obj_info.get('classname', 'Unknown')
                for obj_info in rparser.features.get('datastore', []):
                    if stream_md5 == obj_info.get('content_md5'):
                        name = "Object - %s" % obj_info.get('classname', 'Unknown')
                handle_file(
                    name, 
                    rparser.objects[i],
                    obj.source,
                    related_id=str(obj.id),
                    related_type=str(obj._meta['crits_type']),
                    campaign=obj.campaign,
                    method=self.name,
                    relationship=RelationshipTypes.CONTAINED_WITHIN,
                    user=self.current_task.username,
                )
                added_files.append((stream_md5, stream_md5))
        for f in added_files:
            self._add_result("file_added", f[0], {'md5': f[1]})