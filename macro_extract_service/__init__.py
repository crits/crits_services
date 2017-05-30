from oletools.olevba import (
    VBA_Parser
)

from crits.raw_data.handlers import handle_raw_data_file
from crits.services.core import Service
from crits.vocabulary.relationships import RelationshipTypes


class MacroExtractService(Service):
    """
    Attempts to extract VBA Macros from MS Office files.
    """

    name = "macro_extract"
    version = '0.1.0'
    template = "macro_extract_template.html"
    supported_types = ['Sample']
    description = "Extracs VBA Macros from MS Office documents."
    compatibility_mode = True

    @staticmethod
    def get_config(existing_config):
        # This service no longer uses config options, so blow away any existing
        # configs.
        return {}

    @staticmethod
    def valid_for(obj):
        return

    def run(self, obj, config):
        username = self.current_task.user
        filename = obj.filename
        filedata = obj.filedata.read()
        try:
            vbaparser = VBA_Parser(filename, data=filedata)
        except Exception, e:
            self._error("Cannot parse file: %s" % str(e))
            return
        if vbaparser.detect_vba_macros():
            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                d = {
                    'OLE stream': stream_path,
                    'VBA filename': vba_filename,
                    'Length': len(vba_code)
                }
                result = handle_raw_data_file(
                    vba_code,
                    obj.source,
                    user=username,
                    description="VBA Macro source code for %s" % vba_filename,
                    title=vba_filename,
                    data_type="Text",
                    tool_name=self.name,
                    tool_version=self.version,
                    tool_details=self.description
                )
                if result['success']:
                    obj.add_relationship(
                        result['object'],
                        RelationshipTypes.RELATED_TO,
                        analyst=username,
                        rel_reason="Extracted from related Sample"
                    )
                    obj.save()
                    d['RawData TLO ID'] = result['_id']
                self._add_result('Macros', filename, d)
            results = vbaparser.analyze_macros(show_decoded_strings=True)
            self._add_result('Counts',
                             'Suspicious keywords',
                             {'Count': vbaparser.nb_suspicious})
            self._add_result('Counts',
                             'AutoExec keywords',
                             {'Count': vbaparser.nb_autoexec})
            self._add_result('Counts',
                             'IOCs',
                             {'Count': vbaparser.nb_iocs})
            self._add_result('Counts',
                             'Hex obfuscated strings',
                             {'Count': vbaparser.nb_hexstrings})
            self._add_result('Counts',
                             'Base64 obfuscated strings',
                             {'Count': vbaparser.nb_base64strings})
            self._add_result('Counts',
                             'Dridex obfuscated strings',
                             {'Count': vbaparser.nb_dridexstrings})
            self._add_result('Counts',
                             'VBA obfuscated strings',
                             {'Count': vbaparser.nb_vbastrings})
            for kw_type, keyword, description in results:
                try:
                    d = {
                        'type': kw_type,
                        'description': description.decode('utf-8')
                    }
                    self._add_result('Keywords',
                                    keyword.decode('utf-8'),
                                     d)
                except:
                    pass
        else:
            self._info('No VBA Macros found')
        vbaparser.close()
        return
