from crits.services.core import Service

from . import pylnker

class LnkService(Service):
    name = "LnkService"
    version = "0.0.1"
    supported_types  = ['Sample']
    description = "Extracts the command from an LNK file"

    def run(self, obj, config):
        fname = obj.filename
        fh = obj.filedata
        fh.seek(0)
        try:
            lnk_info = pylnker.parse_lnk(fname, fh)
            
            _add_result(self, "Target Location", lnk_info['target_location'])
            if lnk_info['target_location'] == 'local volume':
                _add_result(self, "Base Path", lnk_info['base_path'])
            elif lnk_info['target_location'] == 'network share':
                _add_result(self, "Network Share Name", lnk_info['net_share_name'])
            
            if 'command_line' in lnk_info:
                _add_result(self, "Command Line", lnk_info['command_line'])
            if 'icon_filename' in lnk_info:
                _add_result(self, "Icon filename", lnk_info['icon_filename'])
            
        except Exception(e):
            self._error("Cannot parse file: %s" % str(e))
            return